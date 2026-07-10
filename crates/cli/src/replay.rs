//! `mcpglass replay`: re-send a recorded client->server request back to its server,
//! out of band, for debugging and reproduction.
//!
//! Unlike `wrap`/`gateway`, replay is **not** on any live wire — it is a probe run
//! from the CLI or the dashboard, on demand, against a server reconstructed from the
//! recorded session. So the fail-open contract that governs the proxy hot path does
//! not apply here: there is no client<->server traffic to protect. Two consequences
//! are load-bearing and surfaced to the user:
//!
//! * **stdio replay restarts the server process.** A recorded session's `command`
//!   is re-spawned and driven through a fresh `initialize` handshake, so anything the
//!   server does on startup or in response to the replayed request (writes, network
//!   calls, ...) happens for real — replaying can have side effects.
//! * **replay is never recorded.** It opens the session store read-only to look up
//!   the message and its server command, and writes nothing back: a replay must not
//!   pollute the session list, and an stdio `tools/list` during replay must not touch
//!   the same server_key's fingerprint baseline. The result is returned to the caller
//!   only (CLI stdout / dashboard response), never to storage.
//!
//! Gatekeeping: only a client->server *request* (a frame with both a `method` and an
//! `id`) can be replayed — a response, a notification, or an s2c frame has nothing to
//! re-send and is rejected with a clear error.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::Duration;

use proxy_core::{parse_line, Direction, LineSplitter, SseSplitter, MCP_PROTOCOL_VERSION};
use serde::Serialize;
use storage::Store;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_stream::StreamExt;

use crate::tap::Logger;

/// Frame cap for the replay reader/splitter. Generous (a replayed response is a
/// single JSON-RPC message), yet bounded so a runaway server stream can't grow the
/// buffer without end. Independent of the wire path's test override.
const REPLAY_MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;

/// Read buffer size for the stdio reader.
const READ_BUF_BYTES: usize = 64 * 1024;

/// The `id` used for the replay's own `initialize` request. A fixed, recognisable
/// token so it never collides with the replayed request's real id.
const REPLAY_INIT_ID: &str = "mcpglass-replay-init";

/// The `notifications/initialized` frame sent to complete the MCP handshake before
/// the replayed request. A bare notification (no id, no response expected).
const INITIALIZED_NOTIFICATION: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;

/// Upper bound on how many bytes of an SSE replay response we'll read while looking
/// for the event that carries the request id. A replayed request expects a single
/// framed answer, so this only needs to bound a pathological upstream that keeps the
/// stream open (or floods unrelated events) without ever answering; matching the
/// per-frame cap gives one constant's worth of headroom.
const SSE_MAX_BODY_BYTES: usize = REPLAY_MAX_FRAME_BYTES;

/// Time budget for the best-effort teardown `DELETE`, applied *outside* the exchange
/// timeout so a stalled DELETE can never discard an already-obtained response.
const DELETE_TIMEOUT: Duration = Duration::from_secs(2);

/// The outcome of a completed replay. `transport` says which path ran (`"stdio"` or
/// `"http"`); `response_raw` is the server's answer to the replayed request (the raw
/// JSON-RPC frame, or the whole HTTP body when no framed answer could be isolated);
/// `note` records the caveats (fresh handshake, possible side effects, not recorded).
#[derive(Debug, Serialize)]
pub struct ReplayResult {
    pub transport: &'static str,
    pub response_raw: Option<String>,
    pub note: String,
}

/// Why a replay could not be completed. Categorised so the dashboard can map each to
/// an HTTP status (see `dashboard::ReplayError`) and the CLI can report it cleanly.
#[derive(Debug)]
pub enum ReplayError {
    /// The message isn't a replayable client->server request (wrong direction, a
    /// response, a notification, or an unknown id). A caller-input error.
    NotReplayable(String),
    /// The exchange exceeded its time budget.
    Timeout,
    /// The reconstructed server couldn't be reached or driven (spawn failed, HTTP
    /// request failed, stream closed early).
    Upstream(String),
    /// A local failure unrelated to the server (opening the store, building a client).
    Internal(String),
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplayError::NotReplayable(m) => write!(f, "not replayable: {m}"),
            ReplayError::Timeout => write!(f, "timed out waiting for the server to answer"),
            ReplayError::Upstream(m) => write!(f, "server error: {m}"),
            ReplayError::Internal(m) => write!(f, "internal error: {m}"),
        }
    }
}

impl std::error::Error for ReplayError {}

/// CLI entry point for `mcpglass replay <message-id>`. Resolves the default db the
/// same way the other subcommands do, runs the replay directly (no confirmation —
/// the CLI is explicit by construction), prints the outcome as pretty JSON on
/// success (exit 0), or reports the error on stderr (exit 1).
pub async fn run(db: Option<PathBuf>, message_id: i64, timeout_secs: u64) -> i32 {
    let db_path = db
        .or_else(|| crate::default_data_dir().map(|d| d.join("sessions.db")))
        .unwrap_or_else(|| std::env::temp_dir().join("mcpglass").join("sessions.db"));

    match run_replay(db_path, message_id, Duration::from_secs(timeout_secs)).await {
        Ok(result) => {
            // `to_string_pretty` on a plain owned struct cannot fail; fall back to a
            // terse form rather than panicking if it somehow does.
            match serde_json::to_string_pretty(&result) {
                Ok(json) => println!("{json}"),
                Err(_) => println!(
                    "{{\"transport\":{:?},\"note\":{:?}}}",
                    result.transport, result.note
                ),
            }
            0
        }
        Err(e) => {
            eprintln!("mcpglass: replay of message {message_id} failed: {e}");
            1
        }
    }
}

/// Look up message `message_id` and its session, gate it, and replay it against the
/// reconstructed server. The store is opened read-only and dropped before any
/// network/process IO, so nothing is recorded and the (blocking) rusqlite handle is
/// never held across an `.await`.
pub async fn run_replay(
    db_path: PathBuf,
    message_id: i64,
    timeout: Duration,
) -> Result<ReplayResult, ReplayError> {
    // Synchronous lookups first; the Store is dropped at the end of this block.
    let (command, argv_json, transport, raw, rpc_id, protocol_version) = {
        let store = Store::open(&db_path)
            .map_err(|e| ReplayError::Internal(format!("opening session store: {e:#}")))?;
        let msg = store
            .message(message_id)
            .map_err(|e| ReplayError::Internal(format!("reading message {message_id}: {e:#}")))?
            .ok_or_else(|| ReplayError::NotReplayable(format!("message {message_id} not found")))?;

        // Only a client->server *request* can be replayed.
        if msg.direction != Direction::C2s {
            return Err(ReplayError::NotReplayable(format!(
                "message {message_id} is a server->client frame; only client->server requests can be replayed"
            )));
        }
        if msg.method.is_none() {
            return Err(ReplayError::NotReplayable(format!(
                "message {message_id} is a response, not a request (no method); nothing to replay"
            )));
        }
        let Some(rpc_id) = msg.rpc_id.clone() else {
            return Err(ReplayError::NotReplayable(format!(
                "message {message_id} is a notification (no id); only a request expecting a response can be replayed"
            )));
        };
        // A metadata-only recording (`--record metadata`) kept the frame's metadata but
        // not its body, so there is nothing to re-send.
        if msg.raw.is_empty() && msg.raw_len.is_some() {
            return Err(ReplayError::NotReplayable(format!(
                "message {message_id} was recorded metadata-only (body not recorded); nothing to replay"
            )));
        }

        let session = store
            .session(msg.session_id)
            .map_err(|e| ReplayError::Internal(format!("reading session {}: {e:#}", msg.session_id)))?
            .ok_or_else(|| {
                ReplayError::NotReplayable(format!(
                    "session {} for message {message_id} not found",
                    msg.session_id
                ))
            })?;

        (
            session.command,
            session.argv_json,
            session.transport,
            msg.raw,
            rpc_id,
            session.protocol_version,
        )
    };

    // Reconstruct the handshake with the version this session actually negotiated;
    // a legacy session with none recorded falls back to the build's default constant.
    let version = protocol_version.unwrap_or_else(|| MCP_PROTOCOL_VERSION.to_owned());

    if replay_is_http(&command, transport.as_deref()) {
        replay_http(&command, &raw, &rpc_id, &version, timeout).await
    } else {
        // Prefer the structured argv (v7, lossless); fall back to splitting the joined
        // command string for a legacy session that recorded no argv.
        let argv = stdio_argv(&command, argv_json.as_deref());
        replay_stdio(argv, &raw, &rpc_id, &version, timeout).await
    }
}

/// Decide whether to replay over HTTP. The session's recorded `transport` column (v7)
/// is authoritative; a legacy session with none recorded falls back to sniffing the
/// `command` for an `http(s)://` scheme.
fn replay_is_http(command: &str, transport: Option<&str>) -> bool {
    match transport {
        Some("http") => true,
        Some("stdio") => false,
        _ => is_http_command(command),
    }
}

/// Resolve the argv to re-spawn for an stdio replay. A v7 session recorded its argv as
/// a JSON array (`argv_json`), which round-trips losslessly — including whitespace,
/// quotes, and backslashes that [`split_command`] cannot recover. A legacy session (or
/// an unparseable value) falls back to splitting the joined `command`.
fn stdio_argv(command: &str, argv_json: Option<&str>) -> Vec<String> {
    argv_json
        .and_then(|j| serde_json::from_str::<Vec<String>>(j).ok())
        .unwrap_or_else(|| split_command(command))
}

/// A session `command` targets an HTTP(S) upstream (the gateway path) rather than a
/// spawnable stdio program. Scheme match is case-insensitive; leading space tolerant.
fn is_http_command(command: &str) -> bool {
    let lower = command.trim_start().to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

/// The replay's own `initialize` request, carrying `version` (the session's
/// negotiated protocol version, or the build default for a legacy session) so the
/// reconstructed server negotiates the same version the original session used.
fn initialize_request(version: &str) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": REPLAY_INIT_ID,
        "method": "initialize",
        "params": {
            "protocolVersion": version,
            "capabilities": {},
            "clientInfo": { "name": "mcpglass-replay", "version": env!("CARGO_PKG_VERSION") }
        }
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// stdio replay.
// ---------------------------------------------------------------------------

/// Split a recorded `command` string into argv, honouring single- and double-quoted
/// runs so a token that contains whitespace (a quoted `C:\Program Files\...` path, a
/// `"a b"` flag value) survives whole. This is a best-effort inverse of the
/// `argv.join(" ")` the recorder stored before schema v7: quotes group and the quote
/// characters themselves are dropped; an unterminated quote runs to the end of the
/// string. It is deliberately minimal (no backslash escaping, no shell expansion).
///
/// **Only applies to pre-v7 sessions.** A v7 session records its argv as a JSON array
/// (`sessions.argv_json`), which replay uses directly for a lossless reconstruction
/// (see [`stdio_argv`]); this splitter is the fallback for a legacy row that carries no
/// structured argv, where a command with embedded quotes or backslashes still cannot be
/// restored exactly.
fn split_command(command: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut in_token = false;
    let mut quote: Option<char> = None;
    for c in command.chars() {
        match quote {
            // Inside a quoted run: everything is literal until the matching quote.
            Some(q) => {
                if c == q {
                    quote = None;
                } else {
                    cur.push(c);
                }
            }
            None => {
                if c == '"' || c == '\'' {
                    quote = Some(c);
                    in_token = true; // an empty `""` still opens a (possibly empty) token
                } else if c.is_whitespace() {
                    if in_token {
                        parts.push(std::mem::take(&mut cur));
                        in_token = false;
                    }
                } else {
                    cur.push(c);
                    in_token = true;
                }
            }
        }
    }
    if in_token {
        parts.push(cur);
    }
    parts
}

/// Replay over stdio: re-spawn the recorded server command, drive a fresh handshake,
/// re-send the request verbatim, and read frames until the one bearing the request's
/// id comes back. The whole exchange is bounded by `timeout`, and the child is always
/// killed on the way out.
///
/// `argv` is the already-resolved server command line (see [`stdio_argv`]): a v7 session
/// hands over the losslessly recorded argv array, while a legacy session falls back to
/// [`split_command`], which recovers whitespace-quoted arguments but cannot restore
/// embedded quotes or backslashes exactly.
async fn replay_stdio(
    argv: Vec<String>,
    raw: &str,
    rpc_id: &str,
    version: &str,
    timeout: Duration,
) -> Result<ReplayResult, ReplayError> {
    let Some((program, args)) = argv.split_first() else {
        return Err(ReplayError::Internal(
            "recorded session command is empty; cannot reconstruct the server".to_owned(),
        ));
    };

    // A no-op logger: replay must never write to the proxy's diagnostics file.
    let logger = Logger::open(None);
    let mut child = crate::spawn_child(program, args, &logger)
        .await
        .map_err(|e| ReplayError::Upstream(format!("failed to spawn server `{program}`: {e:#}")))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| ReplayError::Internal("child stdin was not piped".to_owned()))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| ReplayError::Internal("child stdout was not piped".to_owned()))?;
    // Drain the child's stderr so a chatty server can't block on a full stderr pipe
    // while we wait for its stdout answer. Detached; ends when the child exits.
    let stderr = child.stderr.take();
    let stderr_drain = tokio::spawn(async move {
        if let Some(mut e) = stderr {
            let mut sink = tokio::io::sink();
            let _ = tokio::io::copy(&mut e, &mut sink).await;
        }
    });

    let outcome = match tokio::time::timeout(
        timeout,
        stdio_exchange(&mut stdin, &mut stdout, raw, rpc_id, version),
    )
    .await
    {
        Ok(inner) => inner,
        Err(_) => Err(ReplayError::Timeout),
    };

    // Always tear the child down (it may otherwise wait forever on stdin). `kill`
    // already reaps, so no separate `wait` is needed.
    let _ = child.kill().await;
    stderr_drain.abort();
    outcome
}

/// The stdio handshake + request/response exchange, minus timeout/teardown (the
/// caller owns those). Sends `initialize`, waits for one response frame, sends
/// `notifications/initialized`, sends the original request verbatim, then reads until
/// a frame whose id matches `rpc_id` (skipping unrelated frames such as the echoed
/// notification or server log notifications).
async fn stdio_exchange<W, R>(
    stdin: &mut W,
    stdout: &mut R,
    raw: &str,
    rpc_id: &str,
    version: &str,
) -> Result<ReplayResult, ReplayError>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    write_line(stdin, &initialize_request(version)).await?;

    let mut reader = FrameReader::new(stdout);
    // One frame is the initialize response; its exact contents don't matter here.
    if reader
        .next_frame()
        .await
        .map_err(|e| ReplayError::Upstream(format!("reading initialize response: {e}")))?
        .is_none()
    {
        return Err(ReplayError::Upstream(
            "server closed the stream before responding to initialize".to_owned(),
        ));
    }

    write_line(stdin, INITIALIZED_NOTIFICATION).await?;
    write_line(stdin, raw).await?;

    loop {
        match reader
            .next_frame()
            .await
            .map_err(|e| ReplayError::Upstream(format!("reading replay response: {e}")))?
        {
            Some(frame) => {
                if parse_line(&frame, Direction::S2c).rpc_id.as_deref() == Some(rpc_id) {
                    return Ok(ReplayResult {
                        transport: "stdio",
                        response_raw: Some(String::from_utf8_lossy(&frame).into_owned()),
                        note: format!(
                            "re-sent request id {rpc_id} to a freshly spawned server after a new \
                             initialize handshake; replaying can have side effects and is not recorded"
                        ),
                    });
                }
                // A non-matching frame (echoed notification, server log, ...): keep reading.
            }
            None => {
                return Err(ReplayError::Upstream(format!(
                    "server closed the stream before answering request id {rpc_id}"
                )));
            }
        }
    }
}

/// Write `line` followed by the framing newline and flush. Maps IO failures to
/// `Upstream` (a failed write means the reconstructed server went away).
async fn write_line<W: AsyncWrite + Unpin>(w: &mut W, line: &str) -> Result<(), ReplayError> {
    async fn inner<W: AsyncWrite + Unpin>(w: &mut W, line: &str) -> std::io::Result<()> {
        w.write_all(line.as_bytes()).await?;
        w.write_all(b"\n").await?;
        w.flush().await
    }
    inner(w, line)
        .await
        .map_err(|e| ReplayError::Upstream(format!("writing to server: {e}")))
}

/// Incremental newline-framed reader over an async source, yielding one JSON-RPC
/// frame per call. Reuses `proxy_core::LineSplitter` (the same framing the tap uses)
/// so id matching is consistent with how the request was originally recorded.
struct FrameReader<'a, R> {
    reader: &'a mut R,
    splitter: LineSplitter,
    pending: VecDeque<Vec<u8>>,
    buf: Vec<u8>,
    eof: bool,
}

impl<'a, R: AsyncRead + Unpin> FrameReader<'a, R> {
    fn new(reader: &'a mut R) -> Self {
        Self {
            reader,
            splitter: LineSplitter::new(REPLAY_MAX_FRAME_BYTES),
            pending: VecDeque::new(),
            buf: vec![0u8; READ_BUF_BYTES],
            eof: false,
        }
    }

    /// Next complete frame, or `None` at end of stream. A trailing partial frame with
    /// no terminating newline is discarded (a well-formed MCP response is newline
    /// terminated), so `None` also means "the stream ended without a full frame".
    async fn next_frame(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        loop {
            if let Some(frame) = self.pending.pop_front() {
                return Ok(Some(frame));
            }
            if self.eof {
                return Ok(None);
            }
            let n = self.reader.read(&mut self.buf).await?;
            if n == 0 {
                self.eof = true;
                return Ok(None);
            }
            for frame in self.splitter.push(&self.buf[..n]) {
                self.pending.push_back(frame);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP replay.
// ---------------------------------------------------------------------------

/// Replay over HTTP (a gateway session whose command is the upstream URL). The
/// original Streamable-HTTP session cannot be resumed, so this re-initializes: POST
/// `initialize` to obtain a fresh `Mcp-Session-Id`, POST `notifications/initialized`,
/// then POST the recorded request and return its response.
///
/// Only the request/response exchange is bounded by `timeout`. The best-effort
/// `DELETE` that tears the fresh session down runs *after* the timed exchange, under
/// its own short budget: a slow or stalled teardown must never cancel an
/// already-obtained response and turn a success into a 504 (bug #2).
async fn replay_http(
    url: &str,
    raw: &str,
    rpc_id: &str,
    version: &str,
    timeout: Duration,
) -> Result<ReplayResult, ReplayError> {
    let client = reqwest::Client::builder()
        .build()
        .map_err(|e| ReplayError::Internal(format!("building HTTP client: {e}")))?;

    let (result, session_id) =
        match tokio::time::timeout(timeout, http_exchange(&client, url, raw, rpc_id, version)).await {
            Ok(Ok(pair)) => pair,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(ReplayError::Timeout),
        };

    // Best-effort teardown of the fresh session, outside the exchange timeout and
    // fire-and-forget: any failure (or a slow/stalled DELETE) is ignored and cannot
    // affect the response we already have. Only reached once the exchange succeeded,
    // so `session_id` is the one we opened here.
    if let Some(sid) = session_id {
        let del = client.delete(url).header("mcp-session-id", &sid).send();
        let _ = tokio::time::timeout(DELETE_TIMEOUT, del).await;
    }

    Ok(result)
}

/// Drive the fresh handshake and the replayed request. On success returns the
/// [`ReplayResult`] together with the `Mcp-Session-Id` opened here (if any) so the
/// caller can tear it down *outside* this future's timeout. On any error the fresh
/// session is simply abandoned (the upstream expires it on its own).
async fn http_exchange(
    client: &reqwest::Client,
    url: &str,
    raw: &str,
    rpc_id: &str,
    version: &str,
) -> Result<(ReplayResult, Option<String>), ReplayError> {
    // 1. Fresh initialize; capture the new session id from the response headers. A
    //    non-2xx here (e.g. 401 from an upstream that needs auth) is a hard failure:
    //    without a handshake there is nothing to replay against (bug #3).
    let init_resp = post_mcp(client, url, None, &initialize_request(version), version).await?;
    let status = init_resp.status();
    if !status.is_success() {
        return Err(ReplayError::Upstream(format!(
            "upstream returned {status} to the replay initialize handshake"
        )));
    }
    let session_id = init_resp
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let _ = init_resp.bytes().await; // drain so the connection is freed

    // 2. Complete the handshake. This is a notification (fire-and-forget: a 202 with
    //    no body is expected), so its status is not gated — if it truly failed the
    //    replayed request in step 3 would surface the problem anyway.
    let notif = post_mcp(client, url, session_id.as_deref(), INITIALIZED_NOTIFICATION, version).await?;
    let _ = notif.bytes().await;

    // 3. Re-send the recorded request and read its answer. A non-2xx response (error
    //    page, auth failure, ...) must not be handed back as a fake success (bug #3).
    let resp = post_mcp(client, url, session_id.as_deref(), raw, version).await?;
    let status = resp.status();
    if !status.is_success() {
        return Err(ReplayError::Upstream(format!(
            "upstream returned {status} to the replayed request"
        )));
    }
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();

    let (response_raw, note_extra) = if content_type.trim_start().starts_with("text/event-stream")
    {
        // SSE: read chunk-by-chunk and stop as soon as the id matches, rather than
        // buffering the whole body — an upstream that keeps the stream open after the
        // answer would otherwise strand the replay until timeout (bug #4).
        read_sse_response(resp, rpc_id).await?
    } else {
        // Non-SSE: a single framed JSON answer, small enough to buffer whole.
        let body = resp
            .text()
            .await
            .map_err(|e| ReplayError::Upstream(format!("reading replay response body: {e}")))?;
        (Some(body), "")
    };

    let result = ReplayResult {
        transport: "http",
        response_raw,
        note: format!(
            "re-sent request id {rpc_id} over a fresh HTTP initialize handshake \
             (a new Mcp-Session-Id; the original session cannot be resumed); not recorded{note_extra}"
        ),
    };
    Ok((result, session_id))
}

/// POST one JSON-RPC body to the upstream with the MCP client headers, optionally
/// carrying the negotiated `Mcp-Session-Id`. `Accept` advertises both response shapes
/// the Streamable HTTP transport may reply with; `MCP-Protocol-Version` carries the
/// session's negotiated version (matching the `initialize` request).
async fn post_mcp(
    client: &reqwest::Client,
    url: &str,
    session_id: Option<&str>,
    body: &str,
    version: &str,
) -> Result<reqwest::Response, ReplayError> {
    let mut rb = client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(reqwest::header::ACCEPT, "application/json, text/event-stream")
        .header("mcp-protocol-version", version)
        .body(body.to_owned());
    if let Some(sid) = session_id {
        rb = rb.header("mcp-session-id", sid);
    }
    rb.send()
        .await
        .map_err(|e| ReplayError::Upstream(format!("HTTP request to {url} failed: {e}")))
}

/// Read an SSE replay response chunk-by-chunk, returning the raw `data` payload of the
/// first event whose JSON-RPC id matches `rpc_id`. Stops (dropping the stream, so the
/// connection is closed) the moment that event arrives, so an upstream that keeps the
/// stream open afterward can't strand the replay. Reading is capped at
/// `SSE_MAX_BODY_BYTES` so a stream that never carries the id can't grow without end.
///
/// Returns the payload plus a note suffix: empty on a clean match, or an explanation
/// when the stream ended (or was capped) without an event bearing the id.
async fn read_sse_response(
    resp: reqwest::Response,
    rpc_id: &str,
) -> Result<(Option<String>, &'static str), ReplayError> {
    let mut stream = resp.bytes_stream();
    // Reuses `proxy_core::SseSplitter` (the gateway's tap splitter) so parsing matches
    // how such responses are recorded.
    let mut splitter = SseSplitter::new(REPLAY_MAX_FRAME_BYTES);
    let mut total: usize = 0;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk
            .map_err(|e| ReplayError::Upstream(format!("reading replay SSE stream: {e}")))?;
        total = total.saturating_add(chunk.len());
        if total > SSE_MAX_BODY_BYTES {
            return Err(ReplayError::Upstream(format!(
                "upstream SSE stream exceeded {SSE_MAX_BODY_BYTES} bytes without an event bearing request id {rpc_id}"
            )));
        }
        if let Some(ev) = first_matching_event(&mut splitter, &chunk, rpc_id) {
            return Ok((Some(ev), ""));
        }
    }
    // EOF: flush a final event that lacks the terminating blank line (a complete
    // response usually has it, but be forgiving).
    if let Some(ev) = first_matching_event(&mut splitter, b"\n\n", rpc_id) {
        return Ok((Some(ev), ""));
    }
    // Unlike the old buffered path we don't retain the whole stream to hand back, so
    // there is nothing to show — say so in the note.
    Ok((
        None,
        " (the SSE stream ended without an event bearing the request id)",
    ))
}

/// Feed `chunk` into `splitter` and return the `data` payload of the first event it
/// completes whose JSON-RPC id matches `rpc_id`, if any. Pure and synchronous so the
/// id-matching logic can be unit-tested without a live stream.
fn first_matching_event(splitter: &mut SseSplitter, chunk: &[u8], rpc_id: &str) -> Option<String> {
    splitter.push(chunk).into_iter().find_map(|ev| {
        (parse_line(&ev, Direction::S2c).rpc_id.as_deref() == Some(rpc_id))
            .then(|| String::from_utf8_lossy(&ev).into_owned())
    })
}

// ---------------------------------------------------------------------------
// Tests (gatekeeping only; the transport paths are exercised end-to-end in
// `tests/replay.rs`).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mcpglass-replay-unit-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Create a v5 db (via the real Store, so the schema is authoritative), a session
    /// with `command`, and one message, then return `(db_path, message_id)`.
    fn seed_message(
        tag: &str,
        command: &str,
        direction: &str,
        method: Option<&str>,
        rpc_id: Option<&str>,
        raw: &str,
    ) -> (PathBuf, i64) {
        let db = temp_dir(tag).join("sessions.db");
        let sid = {
            let store = Store::open(&db).unwrap();
            store.begin_session("replay-unit", command).unwrap()
        };
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute(
            "INSERT INTO messages
                (session_id, ts_ms, direction, raw, method, rpc_id, is_valid_json, is_error)
             VALUES (?1, 1, ?2, ?3, ?4, ?5, 1, 0)",
            rusqlite::params![sid, direction, raw, method, rpc_id],
        )
        .unwrap();
        let id: i64 = conn
            .query_row("SELECT id FROM messages ORDER BY id DESC LIMIT 1", [], |r| r.get(0))
            .unwrap();
        (db, id)
    }

    #[tokio::test]
    async fn unknown_message_is_not_replayable() {
        // A fresh (empty) db: any id is unknown.
        let db = temp_dir("unknown").join("sessions.db");
        let err = run_replay(db, 999, Duration::from_secs(2)).await.unwrap_err();
        assert!(
            matches!(err, ReplayError::NotReplayable(m) if m.contains("not found")),
            "an unknown message id must be NotReplayable"
        );
    }

    #[tokio::test]
    async fn s2c_message_is_not_replayable() {
        let (db, id) = seed_message(
            "s2c",
            "echo",
            "s2c",
            None,
            Some("1"),
            r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
        );
        let err = run_replay(db, id, Duration::from_secs(2)).await.unwrap_err();
        assert!(
            matches!(err, ReplayError::NotReplayable(m) if m.contains("server->client")),
            "an s2c frame must be NotReplayable"
        );
    }

    #[tokio::test]
    async fn notification_without_id_is_not_replayable() {
        let (db, id) = seed_message(
            "notif",
            "echo",
            "c2s",
            Some("notifications/initialized"),
            None,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        );
        let err = run_replay(db, id, Duration::from_secs(2)).await.unwrap_err();
        assert!(
            matches!(err, ReplayError::NotReplayable(m) if m.contains("notification")),
            "a notification (no id) must be NotReplayable"
        );
    }

    #[tokio::test]
    async fn response_without_method_is_not_replayable() {
        // A c2s frame bearing an id but no method is a response to a server request,
        // not a request we can replay.
        let (db, id) = seed_message(
            "response",
            "echo",
            "c2s",
            None,
            Some("7"),
            r#"{"jsonrpc":"2.0","id":7,"result":{}}"#,
        );
        let err = run_replay(db, id, Duration::from_secs(2)).await.unwrap_err();
        assert!(
            matches!(err, ReplayError::NotReplayable(m) if m.contains("response")),
            "a c2s response (no method) must be NotReplayable"
        );
    }

    #[test]
    fn http_command_detection() {
        assert!(is_http_command("http://127.0.0.1:9000/u/x"));
        assert!(is_http_command("https://example.test/mcp"));
        assert!(is_http_command("  HTTP://127.0.0.1/upper"));
        assert!(!is_http_command("npx -y @scope/server"));
        assert!(!is_http_command("/usr/local/bin/server --stdio"));
    }

    #[test]
    fn initialize_request_carries_protocol_version_and_fixed_id() {
        // The version passed in (a session's negotiated version) is echoed verbatim,
        // so replay reconstructs the handshake the original session used.
        let v: serde_json::Value = serde_json::from_str(&initialize_request("2025-11-25")).unwrap();
        assert_eq!(v["id"], serde_json::json!(REPLAY_INIT_ID));
        assert_eq!(v["method"], serde_json::json!("initialize"));
        assert_eq!(v["params"]["protocolVersion"], serde_json::json!("2025-11-25"));
        // The build default constant is still the fallback for a legacy session.
        let legacy: serde_json::Value =
            serde_json::from_str(&initialize_request(MCP_PROTOCOL_VERSION)).unwrap();
        assert_eq!(legacy["params"]["protocolVersion"], serde_json::json!(MCP_PROTOCOL_VERSION));
    }

    #[test]
    fn first_matching_event_picks_the_matching_id() {
        let body = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"n\":0}}\n\n\
                    event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":42,\"result\":{\"ok\":true}}\n\n";
        let mut s = SseSplitter::new(REPLAY_MAX_FRAME_BYTES);
        let got = first_matching_event(&mut s, body.as_bytes(), "42").expect("event 42 present");
        assert!(got.contains("\"ok\":true"), "must return the id-42 event payload: {got}");
        // A fresh splitter: an id absent from the stream yields nothing.
        let mut s2 = SseSplitter::new(REPLAY_MAX_FRAME_BYTES);
        assert!(
            first_matching_event(&mut s2, body.as_bytes(), "999").is_none(),
            "no event matches id 999"
        );
    }

    #[test]
    fn split_command_honours_quotes_and_whitespace() {
        // Plain whitespace splitting still works.
        assert_eq!(
            split_command("npx -y @scope/server"),
            vec!["npx", "-y", "@scope/server"]
        );
        // A double-quoted path containing spaces stays one token; a quoted flag value
        // with a space does too. This is the case a bare `split_whitespace` mangled.
        assert_eq!(
            split_command(r#"C:\Program Files\srv\mcp.exe --flag "a b""#),
            vec![r"C:\Program", r"Files\srv\mcp.exe", "--flag", "a b"],
            "unquoted spaces still split; only the quoted run is held together"
        );
        assert_eq!(
            split_command(r#""C:\Program Files\srv\mcp.exe" --flag "a b""#),
            vec![r"C:\Program Files\srv\mcp.exe", "--flag", "a b"],
            "a fully quoted Windows path with spaces survives as one argv entry"
        );
        // Single quotes group too; leading/trailing/collapsed whitespace is ignored.
        assert_eq!(split_command("  cmd  'one two'   x  "), vec!["cmd", "one two", "x"]);
        // Adjacent quoted and unquoted fragments concatenate into one token.
        assert_eq!(split_command(r#"pre"a b"post"#), vec!["prea bpost"]);
        // An empty command yields no argv (the caller reports "empty command").
        assert!(split_command("   ").is_empty());
    }

    #[test]
    fn stdio_argv_prefers_lossless_argv_json_over_split_command() {
        // A v7 argv with whitespace, a double quote, and a backslash — the exact cases
        // split_command cannot restore — round-trips exactly through argv_json.
        let argv = vec![
            r"C:\Program Files\srv\mcp.exe".to_owned(),
            "--flag".to_owned(),
            r#"a "b" c\d"#.to_owned(),
        ];
        let json = serde_json::to_string(&argv).unwrap();
        assert_eq!(stdio_argv("ignored display command", Some(&json)), argv);

        // split_command applied to the joined form loses the quotes/backslash, proving
        // argv_json is strictly better rather than merely equivalent.
        assert_ne!(
            split_command(r#"C:\Program Files\srv\mcp.exe --flag a "b" c\d"#),
            argv
        );

        // A legacy session (no argv_json) falls back to split_command...
        assert_eq!(
            stdio_argv("npx -y @scope/server", None),
            vec!["npx", "-y", "@scope/server"]
        );
        // ...as does an unparseable argv_json.
        assert_eq!(stdio_argv("npx server", Some("not json")), vec!["npx", "server"]);
    }

    #[test]
    fn replay_is_http_prefers_recorded_transport_then_sniffs() {
        // The recorded transport column is authoritative, even against a sniff.
        assert!(replay_is_http("npx -y server", Some("http")));
        assert!(!replay_is_http("http://127.0.0.1/u/x", Some("stdio")));
        // A legacy row (no transport) falls back to sniffing the command's scheme.
        assert!(replay_is_http("https://example.test/mcp", None));
        assert!(!replay_is_http("npx -y server", None));
    }
}
