use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use policy::{fingerprints_from_tools_list_versioned, server_identity_hash, ServerIdentity};
use proxy_core::{parse_line, Direction};
use storage::{
    ActionTaken, FingerprintOutcome, InjectEvent, Record, SecurityEvent, SecurityEventKind, Store,
};
use tokio::sync::mpsc;

/// Outstanding tools/list request ids awaiting their response. Only a response
/// whose id is still tracked here is fingerprinted, so an ordinary business
/// response that happens to carry a `result.tools[]` shape is never mistaken for a
/// tool advertisement.
///
/// Keyed strictly: a JSON-RPC id is per outstanding request, so a *non*-tools/list
/// request reusing an id retires the stale entry ([`invalidate`](Self::invalidate)),
/// and the map is bounded ([`CAP`](Self::CAP)) so a client that never reuses ids and
/// whose responses are lost cannot grow it without end — the oldest entry is evicted.
struct PendingToolsList {
    /// id -> the request's `ts_ms`, used to evict the oldest entry when at capacity.
    inner: HashMap<String, i64>,
}

impl PendingToolsList {
    /// Cap on outstanding tracked ids. Comfortably above any realistic count of
    /// concurrent tools/list requests, so eviction only ever discards leaked ids.
    const CAP: usize = 1024;

    fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    /// Note a tools/list request. If inserting a new id would exceed [`CAP`](Self::CAP),
    /// the oldest tracked id is evicted first. Re-noting an existing id refreshes it.
    fn note_request(&mut self, id: String, ts_ms: i64) {
        if !self.inner.contains_key(&id) && self.inner.len() >= Self::CAP {
            if let Some(oldest) = self
                .inner
                .iter()
                .min_by_key(|(_, &ts)| ts)
                .map(|(k, _)| k.clone())
            {
                self.inner.remove(&oldest);
            }
        }
        self.inner.insert(id, ts_ms);
    }

    /// Retire the pending entry for an id reused by a non-tools/list request.
    fn invalidate(&mut self, id: &str) {
        self.inner.remove(id);
    }

    /// Consume the pending entry for a response id; returns whether it was tracked
    /// (i.e. this response answers a tools/list request we saw).
    fn take(&mut self, id: &str) -> bool {
        self.inner.remove(id).is_some()
    }
}

/// Outstanding `initialize` request ids awaiting their response, so the negotiated
/// protocol version can be read off the matching response. Modelled exactly on
/// [`PendingToolsList`] (same strict id-reuse invalidation and [`CAP`](Self::CAP)
/// eviction): a non-`initialize` request reusing an id retires the stale entry, and
/// the map is bounded so leaked ids cannot grow it without end. The stored value is
/// the version the client *proposed* (`params.protocolVersion`), carried through to
/// pair with the version the server *selects* in the response.
struct PendingInitialize {
    /// id -> (request `ts_ms` for eviction, the client-proposed version if any).
    inner: HashMap<String, (i64, Option<String>)>,
}

impl PendingInitialize {
    /// Cap on outstanding tracked ids — comfortably above any realistic count of
    /// concurrent `initialize` requests (normally one per session).
    const CAP: usize = 1024;

    fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    /// Note an `initialize` request with the version it proposed. Evicts the oldest
    /// entry if inserting a new id would exceed [`CAP`](Self::CAP); re-noting refreshes.
    fn note_request(&mut self, id: String, ts_ms: i64, proposed: Option<String>) {
        if !self.inner.contains_key(&id) && self.inner.len() >= Self::CAP {
            if let Some(oldest) = self
                .inner
                .iter()
                .min_by_key(|(_, (ts, _))| *ts)
                .map(|(k, _)| k.clone())
            {
                self.inner.remove(&oldest);
            }
        }
        self.inner.insert(id, (ts_ms, proposed));
    }

    /// Retire the pending entry for an id reused by a non-`initialize` request.
    fn invalidate(&mut self, id: &str) {
        self.inner.remove(id);
    }

    /// Consume the pending entry for a response id. Returns `Some(proposed)` when this
    /// response answers an `initialize` request we tracked (the inner value may itself
    /// be `None` if the request omitted a `protocolVersion`), or `None` otherwise.
    fn take(&mut self, id: &str) -> Option<Option<String>> {
        self.inner.remove(id).map(|(_, proposed)| proposed)
    }
}

/// How a session's protocol version has been recorded so far, so the precedence rule
/// can be enforced across the storage loop's lifetime: an `initialize` handshake
/// always wins, and an `MCP-Protocol-Version` header is recorded only once and only
/// when nothing has been recorded yet. Session-local: one per [`storage_loop`].
#[derive(Default, PartialEq, Eq)]
enum ProtocolSource {
    /// No protocol version recorded yet.
    #[default]
    None,
    /// Recorded from an `MCP-Protocol-Version` header (a weaker signal that a later
    /// `initialize` may still override).
    Header,
    /// Recorded from an `initialize` handshake (authoritative; never overridden).
    Initialize,
}

/// How much of each tapped frame to persist. Set once at startup (`--record`), never
/// switched mid-run. `Off` means the pumps never enqueue a `Tap` at all (zero
/// side-channel cost); `Metadata`/`Full` both enqueue, and the difference — whether the
/// raw body is stored — is applied here in [`storage_loop`], *after* every parse that
/// needs the body (fingerprinting, protocol observation) has run on it.
#[derive(Clone, Copy, PartialEq, Eq, Debug, clap::ValueEnum)]
pub(crate) enum RecordMode {
    /// Record everything: the full raw frame plus all metadata (the default).
    Full,
    /// Record metadata only — method, ids, direction, timing, validity, plus the
    /// original body length in `raw_len` — but not the raw body itself.
    Metadata,
    /// Record nothing to `messages`: security and inject events are still persisted
    /// (the security promise is independent of recording), and the session still opens.
    Off,
}

/// One tapped frame handed to the storage thread. Off the hot path by design.
pub(crate) struct TapEvent {
    pub(crate) direction: Direction,
    pub(crate) ts_ms: i64,
    pub(crate) raw: Vec<u8>,
}

/// Work items for the storage thread. All are strictly best-effort and off the
/// forwarding path: a full or closed channel drops them without touching the wire.
pub(crate) enum StorageMsg {
    /// Record a framed message (either direction) into `messages`.
    Tap(TapEvent),
    /// Persist a security decision into `security_events`.
    Security(SecurityEvent),
    /// Persist a fault-injection event into `inject_events`. Best-effort like the
    /// others: a failed write is logged and dropped, never affecting the wire.
    Inject(InjectEvent),
    /// An `MCP-Protocol-Version` header value seen on an inbound HTTP request (the
    /// gateway path). A passive hint used only when the session has no version from
    /// an `initialize` handshake yet — recorded once, `initialize` always wins. Sent
    /// best-effort per request; a full/closed channel just drops it.
    ProtocolHint { version: String },
}

/// Drain the storage channel into SQLite. Runs on a blocking thread; a DB failure
/// is logged and the item dropped — recording stops, forwarding does not.
pub(crate) fn storage_loop(
    mut rx: mpsc::Receiver<StorageMsg>,
    db_path: PathBuf,
    logger: Logger,
    label: String,
    command_line: String,
    identity: ServerIdentity,
    record: RecordMode,
) {
    let store = match Store::open_with_log(&db_path, &|m| logger.info(m)) {
        Ok(s) => s,
        Err(e) => {
            logger.error(format!("db open failed ({e:#}); recording disabled"));
            // Keep draining so pumps' try_send never blocks/errors on a full queue.
            while rx.blocking_recv().is_some() {}
            return;
        }
    };
    // The structured server identity (schema v7) is the fingerprint scope key across
    // sessions. `server_id` is its hash; `legacy_key` reproduces the pre-v7 scope key
    // (stdio: `argv.join(" ")`; http: the url) — which is exactly `command_line` on both
    // transports — so a baseline recorded before the upgrade is found and re-keyed
    // rather than reset. The argv/program/transport are persisted on the session row.
    let server_id = server_identity_hash(&identity);
    let legacy_key = command_line.clone();
    let argv_json = match &identity {
        ServerIdentity::Stdio { argv } => Some(serde_json::to_string(argv).unwrap_or_default()),
        ServerIdentity::Http { .. } => None,
    };
    let session_id = match store.begin_session_with_identity(
        &label,
        &command_line,
        identity.program(),
        argv_json.as_deref(),
        identity.transport(),
        &server_id,
    ) {
        Ok(id) => id,
        Err(e) => {
            logger.error(format!("begin_session failed ({e:#}); recording disabled"));
            while rx.blocking_recv().is_some() {}
            return;
        }
    };
    // Outstanding tools/list requests, so only their responses are fingerprinted.
    // Requests are forwarded before their tap is enqueued and a response cannot
    // precede its request, so the id is present here by the time the matching
    // response is drained.
    let mut pending_tools_list = PendingToolsList::new();
    // Outstanding initialize requests + how the session's protocol version has been
    // recorded so far. Both session-local; the observation is a pure side-channel
    // read off the same tapped frames (plus header hints), never touching the wire.
    let mut pending_initialize = PendingInitialize::new();
    let mut protocol_source = ProtocolSource::None;
    while let Some(msg) = rx.blocking_recv() {
        match msg {
            StorageMsg::Tap(ev) => {
                let direction = ev.direction;
                let parsed = parse_line(&ev.raw, direction);
                // Capture the correlation keys before `parsed` is moved into Record.
                // A c2s request splits by method: a tools/list request is tracked; any
                // *other* request bearing an id retires that id (JSON-RPC ids are per
                // request, so reuse means the old tools/list is done).
                let is_tools_list = parsed.method.as_deref() == Some("tools/list");
                let is_initialize = parsed.method.as_deref() == Some("initialize");
                let tools_list_req_id = if direction == Direction::C2s && is_tools_list {
                    parsed.rpc_id.clone()
                } else {
                    None
                };
                // A c2s initialize request: track its id alongside the version it
                // proposed (params.protocolVersion), so the response's selected version
                // can be paired with it. Parsing the full body here is off the hot path.
                let initialize_req = if direction == Direction::C2s && is_initialize {
                    let proposed = serde_json::from_slice::<serde_json::Value>(&ev.raw)
                        .ok()
                        .and_then(|v| {
                            v.get("params")
                                .and_then(|p| p.get("protocolVersion"))
                                .and_then(|s| s.as_str())
                                .map(str::to_owned)
                        });
                    parsed.rpc_id.clone().map(|id| (id, proposed))
                } else {
                    None
                };
                // Only a genuine *request* reusing the id retires the pending entry —
                // a c2s response (no method) answering something the server asked
                // (e.g. sampling/createMessage) must not invalidate an unrelated
                // tools/list by coincidence of id.
                let reused_req_id = if direction == Direction::C2s
                    && !is_tools_list
                    && parsed.method.is_some()
                {
                    parsed.rpc_id.clone()
                } else {
                    None
                };
                // Likewise for the initialize tracker: any non-initialize request
                // reusing the id retires a stale pending initialize.
                let reused_init_id = if direction == Direction::C2s
                    && !is_initialize
                    && parsed.method.is_some()
                {
                    parsed.rpc_id.clone()
                } else {
                    None
                };
                // For a response, carry its id and whether it is a JSON-RPC error:
                // an error response consumes the pending entry but is not fingerprinted.
                // `method.is_none()` excludes a server-initiated s2c *request* (e.g.
                // sampling/createMessage) that happens to reuse a tracked id — only a
                // JSON-RPC response (no method) can answer a tools/list request.
                let resp = if direction == Direction::S2c && parsed.method.is_none() {
                    parsed.rpc_id.clone().map(|id| (id, parsed.is_error))
                } else {
                    None
                };
                // In metadata mode the raw body is dropped: store an empty `raw` and
                // put the original byte length in `raw_len`. All body-dependent
                // observation (fingerprinting below, protocol negotiation) still runs on
                // the full `ev.raw`, so only the persisted body is affected.
                //
                // `Off` never reaches here — every pump gates the Tap enqueue — but if a
                // future tap path forgets that gate, degrading to the metadata shape
                // keeps "off" from silently persisting full bodies (defense in depth).
                let raw = match record {
                    RecordMode::Metadata | RecordMode::Off => String::new(),
                    RecordMode::Full => String::from_utf8_lossy(&ev.raw).into_owned(),
                };
                let rec = Record {
                    ts_ms: ev.ts_ms,
                    direction,
                    raw,
                    method: parsed.method,
                    rpc_id: parsed.rpc_id,
                    is_valid_json: parsed.is_valid_json,
                    is_error: parsed.is_error,
                };
                let insert_result = match record {
                    RecordMode::Metadata | RecordMode::Off => {
                        store.insert_with_raw_len(session_id, &rec, Some(ev.raw.len() as i64))
                    }
                    RecordMode::Full => store.insert(session_id, &rec),
                };
                if let Err(e) = insert_result {
                    logger.error(format!("insert failed (record dropped): {e:#}"));
                }
                // Track outstanding tools/list requests; retire ids reused by other
                // requests. (These are mutually exclusive per frame.)
                if let Some(id) = tools_list_req_id {
                    pending_tools_list.note_request(id, ev.ts_ms);
                }
                if let Some(id) = reused_req_id {
                    pending_tools_list.invalidate(&id);
                }
                if let Some((id, proposed)) = initialize_req {
                    pending_initialize.note_request(id, ev.ts_ms, proposed);
                }
                if let Some(id) = reused_init_id {
                    pending_initialize.invalidate(&id);
                }
                // Rug-pull detection lives here so the s2c leg stays a pure tap: only
                // a non-error response that answers a tools/list request we saw has
                // its per-tool fingerprints recorded and any change flagged. An error
                // response still consumes the pending entry (the request is answered)
                // but carries no tools to fingerprint. Failures are logged only.
                if let Some((id, is_error)) = resp {
                    if pending_tools_list.take(&id) && !is_error {
                        record_fingerprints(
                            &store,
                            session_id,
                            &server_id,
                            &legacy_key,
                            &ev.raw,
                            ev.ts_ms,
                            &logger,
                        );
                    }
                    // The matching initialize response carries the *selected* protocol
                    // version. An error response consumes the pending entry but records
                    // no version (the handshake failed). An id is per request, so this
                    // and the tools/list take above never both fire for one response.
                    if let Some(proposed) = pending_initialize.take(&id) {
                        if !is_error {
                            record_initialize_negotiation(
                                &store,
                                session_id,
                                &mut protocol_source,
                                proposed,
                                &ev.raw,
                                &logger,
                            );
                        }
                    }
                }
            }
            StorageMsg::ProtocolHint { version } => {
                apply_header_hint(&store, session_id, &mut protocol_source, &version, &logger);
            }
            StorageMsg::Security(ev) => {
                if let Err(e) = store.insert_security_event(session_id, &ev) {
                    logger.error(format!("security event insert failed (dropped): {e:#}"));
                }
            }
            StorageMsg::Inject(ev) => {
                if let Err(e) = store.insert_inject_event(session_id, &ev) {
                    logger.error(format!("inject event insert failed (dropped): {e:#}"));
                }
            }
        }
    }
    // The pumps have hung up: the child has exited. Best-effort end stamp.
    if let Err(e) = store.end_session(session_id) {
        logger.error(format!("end_session failed: {e:#}"));
    }
}

/// From one server->client frame, record each advertised tool's fingerprint (under
/// both algorithm versions, for the dual-hash migration) and flag any that changed
/// definition (a rug-pull signal). A non tools/list frame yields no fingerprints;
/// fingerprint changes are advisory (`flagged`), never blocking — the block
/// decision only lives on the c2s leg.
///
/// Both a `Changed` (a brand-new definition) and a `Reverted` (an oscillation back
/// to a previously seen one, A -> B -> A) raise a `fingerprint_change` event; the
/// `Reverted` detail notes the oscillation. A single event kind is reused for both
/// so no CHECK-constraint migration or dashboard change is needed.
///
/// `server_id` scopes the comparison to this server's structured identity so a change
/// is detected across sessions; `legacy_key` is the pre-v7 scope key (the joined
/// command / url) so a baseline recorded before the identity upgrade is re-keyed onto
/// `server_id` rather than reset (see [`Store::record_fingerprint`]).
pub(crate) fn record_fingerprints(
    store: &Store,
    session_id: i64,
    server_id: &str,
    legacy_key: &str,
    raw: &[u8],
    ts_ms: i64,
    logger: &Logger,
) {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(raw) else {
        return;
    };
    for (tool, fp) in fingerprints_from_tools_list_versioned(&value) {
        match store.record_fingerprint(
            session_id, server_id, legacy_key, &tool, &fp.v1, &fp.v2, &fp.v3, ts_ms,
        ) {
            Ok(outcome @ (FingerprintOutcome::Changed | FingerprintOutcome::Reverted)) => {
                let detail = match outcome {
                    FingerprintOutcome::Reverted => format!(
                        "tool {tool:?} definition reverted to a previously seen fingerprint \
                         (oscillation; possible rug-pull)"
                    ),
                    _ => format!(
                        "tool {tool:?} definition changed since first sighting (possible rug-pull)"
                    ),
                };
                let ev = SecurityEvent {
                    ts_ms,
                    kind: SecurityEventKind::FingerprintChange,
                    rule: tool.clone(),
                    detail,
                    tool_name: Some(tool),
                    rpc_id: None,
                    action_taken: ActionTaken::Flagged,
                };
                if let Err(e) = store.insert_security_event(session_id, &ev) {
                    logger.error(format!("fingerprint-change event insert failed: {e:#}"));
                }
            }
            Ok(_) => {}
            Err(e) => logger.error(format!("record_fingerprint failed: {e:#}")),
        }
    }
}

/// Record the protocol version negotiated by an `initialize` handshake. `proposed`
/// is the version the client offered (from the request); `resp_raw` is the matching
/// server response, from which the *selected* version (`result.protocolVersion`) is
/// read. A response without a parseable selected version is ignored (nothing
/// meaningful to record). `initialize` is authoritative: it always wins over a prior
/// header hint, and is written once. A parse or DB failure is logged only — this is a
/// pure side-channel that must never affect the wire or the existing record path.
fn record_initialize_negotiation(
    store: &Store,
    session_id: i64,
    source: &mut ProtocolSource,
    proposed: Option<String>,
    resp_raw: &[u8],
    logger: &Logger,
) {
    if *source == ProtocolSource::Initialize {
        return; // already recorded authoritatively; don't churn on a re-initialize
    }
    let negotiated = serde_json::from_slice::<serde_json::Value>(resp_raw)
        .ok()
        .and_then(|v| {
            v.get("result")
                .and_then(|r| r.get("protocolVersion"))
                .and_then(|s| s.as_str())
                .map(str::to_owned)
        });
    let Some(negotiated) = negotiated else {
        return;
    };
    match store.set_session_protocol(session_id, proposed.as_deref(), Some(&negotiated), "initialize")
    {
        Ok(()) => *source = ProtocolSource::Initialize,
        Err(e) => logger.error(format!("recording initialize protocol version failed: {e:#}")),
    }
}

/// Apply an `MCP-Protocol-Version` header hint. Recorded only when nothing has been
/// recorded yet (`initialize` always takes precedence, and a header writes once), so
/// a stream of per-request hints collapses to a single write. Best-effort: a DB
/// failure is logged and dropped.
fn apply_header_hint(
    store: &Store,
    session_id: i64,
    source: &mut ProtocolSource,
    version: &str,
    logger: &Logger,
) {
    if *source != ProtocolSource::None {
        return;
    }
    match store.set_session_protocol(session_id, None, Some(version), "header") {
        Ok(()) => *source = ProtocolSource::Header,
        Err(e) => logger.error(format!("recording header protocol hint failed: {e:#}")),
    }
}

pub(crate) fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Append-only diagnostics sink. Silently no-ops if the file can't be opened —
/// logging must never be a reason to fail proxying. Never touches stdout/stderr.
#[derive(Clone)]
pub(crate) struct Logger {
    inner: Arc<Mutex<Option<std::fs::File>>>,
}

impl Logger {
    pub(crate) fn open(path: Option<&Path>) -> Self {
        let file = path.and_then(|p| {
            if let Some(parent) = p.parent() {
                if !parent.as_os_str().is_empty() {
                    let _ = std::fs::create_dir_all(parent);
                }
            }
            // The proxy log can echo request/response detail, so keep it owner-only at
            // rest (0600) on Unix, like the sessions db: set the mode on creation, and
            // reset an existing file best-effort. Windows relies on the default
            // %LOCALAPPDATA% ACL. Best-effort — a permission failure never stops logging.
            let mut opts = std::fs::OpenOptions::new();
            opts.create(true).append(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let file = opts.open(p).ok();
            #[cfg(unix)]
            if file.is_some() {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
            }
            file
        });
        Self {
            inner: Arc::new(Mutex::new(file)),
        }
    }

    fn write(&self, level: &str, msg: &str) {
        if let Ok(mut guard) = self.inner.lock() {
            if let Some(file) = guard.as_mut() {
                use std::io::Write;
                let _ = writeln!(file, "{} [{}] {}", now_ms(), level, msg);
                let _ = file.flush();
            }
        }
    }

    pub(crate) fn info(&self, msg: impl AsRef<str>) {
        self.write("INFO", msg.as_ref());
    }

    pub(crate) fn error(&self, msg: impl AsRef<str>) {
        self.write("ERROR", msg.as_ref());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- PendingToolsList (B3 correlation, unit level) ----------------------

    #[test]
    fn pending_invalidate_and_take_are_strict() {
        let mut p = PendingToolsList::new();
        p.note_request("5".to_owned(), 1);
        p.invalidate("5");
        assert!(!p.take("5"), "an invalidated id must not be tracked");

        p.note_request("6".to_owned(), 2);
        assert!(p.take("6"));
        assert!(!p.take("6"), "take consumes the entry");
    }

    #[test]
    fn pending_evicts_oldest_when_full() {
        let mut p = PendingToolsList::new();
        // Fill to capacity with strictly increasing timestamps (id 0 is oldest).
        for i in 0..PendingToolsList::CAP {
            p.note_request(i.to_string(), i as i64);
        }
        assert_eq!(p.inner.len(), PendingToolsList::CAP);
        // One more insert evicts the oldest rather than growing past the cap.
        p.note_request("new".to_owned(), 1_000_000);
        assert_eq!(p.inner.len(), PendingToolsList::CAP);
        assert!(!p.take("0"), "the oldest id should have been evicted");
        assert!(p.take("new"), "the newest id should be tracked");
    }

    // --- storage_loop correlation + oscillation (B2/B3, integration level) --

    struct TmpDb(PathBuf);
    impl TmpDb {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "mcpglass-tap-test-{}-{}-{:?}",
                tag,
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            TmpDb(dir)
        }
        fn db(&self) -> PathBuf {
            self.0.join("sessions.db")
        }
    }
    impl Drop for TmpDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn tap_ev(direction: Direction, ts_ms: i64, raw: &str) -> StorageMsg {
        StorageMsg::Tap(TapEvent {
            direction,
            ts_ms,
            raw: raw.as_bytes().to_vec(),
        })
    }

    /// Drive `storage_loop` to completion over a prefilled channel.
    fn drive(db: &Path, msgs: Vec<StorageMsg>) {
        let (tx, rx) = mpsc::channel::<StorageMsg>(256);
        for m in msgs {
            tx.try_send(m).expect("prefill channel");
        }
        drop(tx); // closes the channel so storage_loop returns at drain end.
        storage_loop(
            rx,
            db.to_path_buf(),
            Logger::open(None),
            "t".to_owned(),
            "srv".to_owned(),
            ServerIdentity::Stdio {
                argv: vec!["srv".to_owned()],
            },
            RecordMode::Full,
        );
    }

    fn fingerprinted_tool_names(db: &Path) -> Vec<String> {
        let conn = rusqlite::Connection::open(db).unwrap();
        let mut stmt = conn
            .prepare("SELECT tool_name FROM tool_fingerprints ORDER BY id")
            .unwrap();
        let names = stmt
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        names
    }

    fn fingerprint_change_count(db: &Path) -> i64 {
        let conn = rusqlite::Connection::open(db).unwrap();
        conn.query_row(
            "SELECT COUNT(*) FROM security_events WHERE kind = 'fingerprint_change'",
            [],
            |r| r.get(0),
        )
        .unwrap()
    }

    /// Drive `storage_loop` in [`RecordMode::Metadata`] over a prefilled channel.
    fn drive_metadata(db: &Path, msgs: Vec<StorageMsg>) {
        let (tx, rx) = mpsc::channel::<StorageMsg>(256);
        for m in msgs {
            tx.try_send(m).expect("prefill channel");
        }
        drop(tx);
        storage_loop(
            rx,
            db.to_path_buf(),
            Logger::open(None),
            "t".to_owned(),
            "srv".to_owned(),
            ServerIdentity::Stdio {
                argv: vec!["srv".to_owned()],
            },
            RecordMode::Metadata,
        );
    }

    #[test]
    fn metadata_mode_drops_body_keeps_metadata_and_fingerprints() {
        // In metadata mode the raw body is not persisted (raw = '', raw_len set), but the
        // observation that needs the body — tools/list fingerprinting — still runs on the
        // full frame before it is dropped, and method/rpc_id/direction survive.
        let tmp = TmpDb::new("metadata-mode");
        let db = tmp.db();
        let req = r#"{"jsonrpc":"2.0","id":5,"method":"tools/list"}"#;
        let resp = r#"{"jsonrpc":"2.0","id":5,"result":{"tools":[{"name":"search","description":"y"}]}}"#;
        drive_metadata(
            &db,
            vec![
                tap_ev(Direction::C2s, 1, req),
                tap_ev(Direction::S2c, 2, resp),
            ],
        );

        let conn = rusqlite::Connection::open(&db).unwrap();
        // Every recorded body is empty, but each row carries the original byte length and
        // its method/direction metadata.
        let rows: Vec<(String, Option<i64>, Option<String>, String)> = conn
            .prepare("SELECT raw, raw_len, method, direction FROM messages ORDER BY id")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, "", "metadata mode stores no raw body");
        assert_eq!(rows[0].1, Some(req.len() as i64), "raw_len is the original byte length");
        assert_eq!(rows[0].2.as_deref(), Some("tools/list"));
        assert_eq!(rows[0].3, "c2s");
        assert_eq!(rows[1].0, "");
        assert_eq!(rows[1].1, Some(resp.len() as i64));

        // Fingerprinting still ran despite the body being dropped from storage.
        let fps: i64 = conn
            .query_row("SELECT COUNT(*) FROM tool_fingerprints WHERE tool_name = 'search'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(fps, 1, "tools/list fingerprint must be recorded before the body is dropped");
    }

    #[test]
    fn error_response_consumes_pending_and_is_not_fingerprinted() {
        let tmp = TmpDb::new("err-resp");
        let db = tmp.db();
        drive(
            &db,
            vec![
                tap_ev(Direction::C2s, 1, r#"{"jsonrpc":"2.0","id":5,"method":"tools/list"}"#),
                // Error response to id 5: consumes the pending entry, records nothing.
                tap_ev(
                    Direction::S2c,
                    2,
                    r#"{"jsonrpc":"2.0","id":5,"error":{"code":-32601,"message":"no"}}"#,
                ),
                // A later valid tools/list response reusing id 5 finds no pending entry.
                tap_ev(
                    Direction::S2c,
                    3,
                    r#"{"jsonrpc":"2.0","id":5,"result":{"tools":[{"name":"search","description":"y"}]}}"#,
                ),
            ],
        );
        assert!(
            fingerprinted_tool_names(&db).is_empty(),
            "an error response must consume the pending entry; the reused-id response must not fingerprint"
        );
    }

    #[test]
    fn reused_id_by_another_request_invalidates_pending() {
        let tmp = TmpDb::new("reuse-id");
        let db = tmp.db();
        drive(
            &db,
            vec![
                tap_ev(Direction::C2s, 1, r#"{"jsonrpc":"2.0","id":7,"method":"tools/list"}"#),
                // Client reuses id 7 for a different request: the tools/list is retired.
                tap_ev(
                    Direction::C2s,
                    2,
                    r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"x"}}"#,
                ),
                // The (late/spoofed) tools/list response for id 7 must not fingerprint.
                tap_ev(
                    Direction::S2c,
                    3,
                    r#"{"jsonrpc":"2.0","id":7,"result":{"tools":[{"name":"search","description":"y"}]}}"#,
                ),
            ],
        );
        assert!(
            fingerprinted_tool_names(&db).is_empty(),
            "an id reused by another request must invalidate the pending tools/list"
        );

        // Control: without the reuse, the same response IS fingerprinted.
        let tmp2 = TmpDb::new("reuse-id-control");
        let db2 = tmp2.db();
        drive(
            &db2,
            vec![
                tap_ev(Direction::C2s, 1, r#"{"jsonrpc":"2.0","id":7,"method":"tools/list"}"#),
                tap_ev(
                    Direction::S2c,
                    3,
                    r#"{"jsonrpc":"2.0","id":7,"result":{"tools":[{"name":"search","description":"y"}]}}"#,
                ),
            ],
        );
        assert_eq!(fingerprinted_tool_names(&db2), vec!["search".to_owned()]);
    }

    #[test]
    fn oscillation_raises_fingerprint_change_event() {
        let tmp = TmpDb::new("oscillation");
        let db = tmp.db();
        let req = r#"{"jsonrpc":"2.0","id":5,"method":"tools/list"}"#;
        let resp = |desc: &str| {
            format!(
                r#"{{"jsonrpc":"2.0","id":5,"result":{{"tools":[{{"name":"search","description":"{desc}"}}]}}}}"#
            )
        };
        drive(
            &db,
            vec![
                tap_ev(Direction::C2s, 1, req),
                tap_ev(Direction::S2c, 2, &resp("A")), // New: no event
                tap_ev(Direction::C2s, 3, req),
                tap_ev(Direction::S2c, 4, &resp("B")), // Changed: event 1
                tap_ev(Direction::C2s, 5, req),
                tap_ev(Direction::S2c, 6, &resp("A")), // Reverted (A->B->A): event 2
            ],
        );
        assert_eq!(
            fingerprint_change_count(&db),
            2,
            "one Changed and one Reverted must each raise a fingerprint_change event"
        );
        // The revert is labelled as an oscillation in its detail.
        let conn = rusqlite::Connection::open(&db).unwrap();
        let osc: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM security_events
                 WHERE kind = 'fingerprint_change' AND detail LIKE '%oscillation%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(osc, 1, "the revert must be recorded as an oscillation");
    }

    #[test]
    fn output_schema_only_change_raises_fingerprint_change_event() {
        // v3 folds `outputSchema` into the fingerprint: a tool whose result contract
        // is quietly rewritten (same name/description/inputSchema/annotations, only
        // outputSchema differs) is a rug-pull surface and must be flagged.
        let tmp = TmpDb::new("fp-v3-outputschema");
        let db = tmp.db();
        let req = r#"{"jsonrpc":"2.0","id":5,"method":"tools/list"}"#;
        let resp = |schema: &str| {
            format!(
                r#"{{"jsonrpc":"2.0","id":5,"result":{{"tools":[{{"name":"search","description":"d","inputSchema":{{}},"outputSchema":{schema}}}]}}}}"#
            )
        };
        drive(
            &db,
            vec![
                tap_ev(Direction::C2s, 1, req),
                tap_ev(Direction::S2c, 2, &resp(r#"{"type":"object"}"#)), // New: no event
                tap_ev(Direction::C2s, 3, req),
                tap_ev(Direction::S2c, 4, &resp(r#"{"type":"string"}"#)), // Changed: one event
            ],
        );
        assert_eq!(
            fingerprint_change_count(&db),
            1,
            "an outputSchema-only change must raise exactly one fingerprint_change event"
        );
    }

    #[test]
    fn server_initiated_request_does_not_consume_pending_tools_list() {
        let tmp = TmpDb::new("s2c-server-request");
        let db = tmp.db();
        drive(
            &db,
            vec![
                tap_ev(Direction::C2s, 1, r#"{"jsonrpc":"2.0","id":9,"method":"tools/list"}"#),
                // Server-initiated request, s2c, reusing id 9: it has a `method`, so
                // it is not a JSON-RPC response and must not be mistaken for the
                // tools/list reply.
                tap_ev(
                    Direction::S2c,
                    2,
                    r#"{"jsonrpc":"2.0","id":9,"method":"sampling/createMessage","params":{}}"#,
                ),
                // The real tools/list response, still id 9, arrives after.
                tap_ev(
                    Direction::S2c,
                    3,
                    r#"{"jsonrpc":"2.0","id":9,"result":{"tools":[{"name":"search","description":"y"}]}}"#,
                ),
            ],
        );
        assert_eq!(
            fingerprinted_tool_names(&db),
            vec!["search".to_owned()],
            "a server-initiated s2c request must not consume the pending tools/list; \
             the actual response must still be fingerprinted"
        );
    }

    #[test]
    fn c2s_response_to_server_request_does_not_invalidate_pending_tools_list() {
        let tmp = TmpDb::new("c2s-response-to-server-req");
        let db = tmp.db();
        drive(
            &db,
            vec![
                tap_ev(Direction::C2s, 1, r#"{"jsonrpc":"2.0","id":7,"method":"tools/list"}"#),
                // Client's c2s response to a server-initiated request, reusing id 7:
                // no `method`, so it is a response, not a request — it must not
                // retire the tracked tools/list id.
                tap_ev(
                    Direction::C2s,
                    2,
                    r#"{"jsonrpc":"2.0","id":7,"result":{}}"#,
                ),
                // The real tools/list response, still id 7.
                tap_ev(
                    Direction::S2c,
                    3,
                    r#"{"jsonrpc":"2.0","id":7,"result":{"tools":[{"name":"search","description":"y"}]}}"#,
                ),
            ],
        );
        assert_eq!(
            fingerprinted_tool_names(&db),
            vec!["search".to_owned()],
            "a c2s response bearing no method must not invalidate the pending tools/list"
        );
    }

    #[test]
    fn create_task_result_does_not_disturb_tools_list_correlation() {
        // An interleaved 2025-11-25 CreateTaskResult (a response with a `result` but a
        // different id and no `tools`) must neither be fingerprinted nor consume the
        // pending tools/list — the genuine tools/list response still fingerprints.
        let tmp = TmpDb::new("create-task-result");
        let db = tmp.db();
        drive(
            &db,
            vec![
                tap_ev(Direction::C2s, 1, r#"{"jsonrpc":"2.0","id":5,"method":"tools/list"}"#),
                // A CreateTaskResult for an unrelated request (id 99): result, no tools.
                tap_ev(
                    Direction::S2c,
                    2,
                    r#"{"jsonrpc":"2.0","id":99,"result":{"task":{"taskId":"abc","ttl":30000},"_meta":{"io.modelcontextprotocol/related-task":{"taskId":"abc"}}}}"#,
                ),
                // The genuine tools/list answer still arrives for id 5.
                tap_ev(
                    Direction::S2c,
                    3,
                    r#"{"jsonrpc":"2.0","id":5,"result":{"tools":[{"name":"search","description":"y"}]}}"#,
                ),
            ],
        );
        assert_eq!(
            fingerprinted_tool_names(&db),
            vec!["search".to_owned()],
            "a CreateTaskResult must not be fingerprinted nor consume the pending tools/list"
        );
    }

    // --- identity re-key on upgrade (WF5) -----------------------------------

    #[test]
    fn upgrade_baseline_survives_identity_rekey_without_alert() {
        // A fingerprint recorded pre-v7 under the joined-command `server_key` must be
        // found and re-keyed onto the structured `server_id` on the first post-upgrade
        // sighting — Unchanged, no rug-pull alert, no residual legacy-scoped rows. This
        // is the end-to-end guard that the lazy re-key never silently zeroes a baseline.
        let tmp = TmpDb::new("lazy-rekey-e2e");
        let db = tmp.db();
        let resp = r#"{"jsonrpc":"2.0","id":5,"result":{"tools":[{"name":"search","description":"y"}]}}"#;
        // The exact v3 hash the tap will compute for this tool.
        let value: serde_json::Value = serde_json::from_str(resp).unwrap();
        let fp_v3 = fingerprints_from_tools_list_versioned(&value)[0].1.v3.clone();

        // Seed a pre-v7 baseline under the legacy joined-command key.
        {
            let store = Store::open(&db).unwrap();
            let sid = store.begin_session("legacy", "npx some-server").unwrap();
            let conn = rusqlite::Connection::open(&db).unwrap();
            conn.execute(
                "INSERT INTO tool_fingerprints
                    (session_id, server_key, tool_name, fingerprint, first_seen_ts_ms, last_seen_ts_ms, fp_version)
                 VALUES (?1, 'npx some-server', 'search', ?2, 1, 1, 3)",
                rusqlite::params![sid, fp_v3],
            )
            .unwrap();
        }

        // A new session for the SAME server (structured identity) re-advertises `search`
        // with the identical definition.
        let (tx, rx) = mpsc::channel::<StorageMsg>(64);
        tx.try_send(tap_ev(Direction::C2s, 1, r#"{"jsonrpc":"2.0","id":5,"method":"tools/list"}"#))
            .unwrap();
        tx.try_send(tap_ev(Direction::S2c, 2, resp)).unwrap();
        drop(tx);
        storage_loop(
            rx,
            db.clone(),
            Logger::open(None),
            "run".to_owned(),
            "npx some-server".to_owned(),
            ServerIdentity::Stdio {
                argv: vec!["npx".to_owned(), "some-server".to_owned()],
            },
            RecordMode::Full,
        );

        // No rug-pull alert: the baseline was re-keyed, not reset.
        assert_eq!(
            fingerprint_change_count(&db),
            0,
            "an identity upgrade must not raise a fingerprint_change event"
        );
        // The legacy-scoped row is gone (migrated to the structured server_id), and it
        // is the only fingerprint row (no duplicate baseline was inserted).
        let conn = rusqlite::Connection::open(&db).unwrap();
        let legacy: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM tool_fingerprints WHERE server_key = 'npx some-server'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(legacy, 0, "the legacy-keyed baseline must be re-keyed away");
        let total: i64 = conn
            .query_row("SELECT COUNT(*) FROM tool_fingerprints", [], |r| r.get(0))
            .unwrap();
        assert_eq!(total, 1, "exactly one baseline row survives, under the structured id");
    }

    // --- passive protocol-version observation (WF1) -------------------------

    /// Read a session's three protocol columns from the db.
    fn session_protocol(db: &Path) -> (Option<String>, Option<String>, Option<String>) {
        let conn = rusqlite::Connection::open(db).unwrap();
        conn.query_row(
            "SELECT protocol_version, client_protocol_version, protocol_version_source
             FROM sessions ORDER BY id LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap()
    }

    fn hint(version: &str) -> StorageMsg {
        StorageMsg::ProtocolHint {
            version: version.to_owned(),
        }
    }

    #[test]
    fn initialize_round_trip_records_negotiated_version() {
        let tmp = TmpDb::new("proto-init");
        let db = tmp.db();
        drive(
            &db,
            vec![
                tap_ev(
                    Direction::C2s,
                    1,
                    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#,
                ),
                tap_ev(
                    Direction::S2c,
                    2,
                    r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{}}}"#,
                ),
            ],
        );
        let (negotiated, client, source) = session_protocol(&db);
        assert_eq!(negotiated.as_deref(), Some("2025-11-25"));
        assert_eq!(client.as_deref(), Some("2025-06-18"));
        assert_eq!(source.as_deref(), Some("initialize"));
    }

    #[test]
    fn initialize_id_reuse_invalidates_pending_version() {
        let tmp = TmpDb::new("proto-reuse");
        let db = tmp.db();
        drive(
            &db,
            vec![
                tap_ev(
                    Direction::C2s,
                    1,
                    r#"{"jsonrpc":"2.0","id":7,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#,
                ),
                // A different request reuses id 7: the pending initialize is retired.
                tap_ev(
                    Direction::C2s,
                    2,
                    r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"x"}}"#,
                ),
                // A late response for id 7 must not record a version.
                tap_ev(
                    Direction::S2c,
                    3,
                    r#"{"jsonrpc":"2.0","id":7,"result":{"protocolVersion":"2025-11-25"}}"#,
                ),
            ],
        );
        let (negotiated, _, source) = session_protocol(&db);
        assert_eq!(negotiated, None, "a reused id must invalidate the pending initialize");
        assert_eq!(source, None);
    }

    #[test]
    fn initialize_error_response_records_no_version() {
        let tmp = TmpDb::new("proto-err");
        let db = tmp.db();
        drive(
            &db,
            vec![
                tap_ev(
                    Direction::C2s,
                    1,
                    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#,
                ),
                tap_ev(
                    Direction::S2c,
                    2,
                    r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"unsupported version"}}"#,
                ),
            ],
        );
        let (negotiated, _, source) = session_protocol(&db);
        assert_eq!(negotiated, None, "a failed handshake records no version");
        assert_eq!(source, None);
    }

    #[test]
    fn header_hint_records_once_when_no_initialize() {
        let tmp = TmpDb::new("proto-header");
        let db = tmp.db();
        drive(&db, vec![hint("2025-11-25"), hint("2025-06-18")]);
        let (negotiated, client, source) = session_protocol(&db);
        // Only the first hint is recorded (header writes once); no client-proposed
        // version (a header carries only the negotiated one).
        assert_eq!(negotiated.as_deref(), Some("2025-11-25"));
        assert_eq!(client, None);
        assert_eq!(source.as_deref(), Some("header"));
    }

    #[test]
    fn initialize_overrides_a_prior_header_hint() {
        let tmp = TmpDb::new("proto-header-then-init");
        let db = tmp.db();
        drive(
            &db,
            vec![
                // A header hint arrives first (e.g. a resumed request).
                hint("2025-06-18"),
                // Then the real handshake is observed: initialize takes precedence.
                tap_ev(
                    Direction::C2s,
                    2,
                    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#,
                ),
                tap_ev(
                    Direction::S2c,
                    3,
                    r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25"}}"#,
                ),
                // A later header hint must NOT clobber the authoritative initialize value.
                hint("2024-11-05"),
            ],
        );
        let (negotiated, client, source) = session_protocol(&db);
        assert_eq!(negotiated.as_deref(), Some("2025-11-25"));
        assert_eq!(client.as_deref(), Some("2025-06-18"));
        assert_eq!(source.as_deref(), Some("initialize"));
    }
}
