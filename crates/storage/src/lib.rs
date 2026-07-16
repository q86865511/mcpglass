//! SQLite sink and query layer for tapped MCP messages.
//!
//! The write side lives entirely on the tap path. Every fallible operation
//! returns a `Result` so the caller can log-and-continue: a storage failure must
//! never propagate into the forwarding path (fail-open).
//!
//! The read side ([`Store::list_sessions`], [`Store::messages`], [`Store::message`],
//! [`Store::stats`]) backs the local dashboard; it is the query contract the
//! dashboard backend builds on.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use proxy_core::Direction;
use rusqlite::types::Value;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension};

/// Current on-disk schema version, stored in `PRAGMA user_version`.
///
/// v1 -> v2 is a purely additive migration: it appends the `security_events` and
/// `tool_fingerprints` tables and never touches existing `sessions`/`messages`
/// rows, so an in-place upgrade of a v1 file preserves all recorded data.
///
/// v2 -> v3 is likewise additive: it adds a `server_key` column to
/// `tool_fingerprints` (via `ALTER TABLE ADD COLUMN`, so existing fingerprint rows
/// are preserved with an empty `server_key`) to scope rug-pull detection by server
/// identity *across sessions*, and never touches `sessions`/`messages` rows.
///
/// v3 -> v4 is again additive: it adds `fp_version` (DEFAULT 1) and a nullable
/// `last_seen_ts_ms` to `tool_fingerprints`. `last_seen_ts_ms` lets comparison key
/// on the most recent observation so an A -> B -> A oscillation is detected, and
/// `fp_version` marks each row's fingerprint algorithm so a legacy v1 row can be
/// recognised and silently re-pinned to v2 during the dual-hash migration.
///
/// v4 -> v5 is purely additive: it appends the `inject_events` table (Phase 3
/// fault injection) via `CREATE TABLE IF NOT EXISTS` in the same batch as every
/// other table, so unlike the v2/v3/v4 bumps there is no `ALTER TABLE` step —
/// a brand-new table needs no separate migration function, the batch's
/// `IF NOT EXISTS` already makes it additive on an upgraded file.
///
/// v5 -> v6 is additive again: it adds three nullable columns to `sessions` —
/// `protocol_version` (the version the server selected), `client_protocol_version`
/// (the version the client proposed), and `protocol_version_source`
/// (`'initialize'` | `'header'`, how the version was observed) — via
/// `ALTER TABLE ADD COLUMN`, so existing session rows are preserved with all three
/// left NULL (a legacy session simply has no recorded protocol version). This lets
/// replay reconstruct a session with the version it actually negotiated instead of
/// the build's default constant.
///
/// v6 -> v7 is additive again: it adds four nullable columns to `sessions` —
/// `program` (stdio: `argv[0]`; http: NULL), `argv_json` (stdio: the full argv as a
/// JSON array; http: NULL), `transport` (`'stdio'` | `'http'`), and `server_id` (the
/// sha256 of the structured [`policy::ServerIdentity`], the cross-session
/// rug-pull-detection scope key) — plus one nullable `raw_len` column to `messages`
/// (byte length of the raw frame; reserved for a later metadata-only recording mode
/// and left unwritten by this version). All five are nullable via `ALTER TABLE ADD
/// COLUMN`, so existing rows are preserved with them NULL (a legacy session has no
/// structured identity and falls back to the `command` display string). Structured
/// identity lets fingerprint history be scoped by a real identity — the same argv
/// under a different project is a distinct server — and lets `replay` reconstruct argv
/// losslessly instead of re-splitting the joined `command`.
pub const SCHEMA_VERSION: i64 = 7;

/// One captured JSON-RPC frame, ready to persist.
pub struct Record {
    pub ts_ms: i64,
    pub direction: Direction,
    /// The raw framed line, verbatim (lossy-UTF-8 if the source was not UTF-8).
    pub raw: String,
    pub method: Option<String>,
    pub rpc_id: Option<String>,
    pub is_valid_json: bool,
    /// A JSON-RPC error response (see `proxy_core::ParsedMessage::is_error`).
    pub is_error: bool,
}

/// One `wrap` invocation: a run of the proxy against a single server process.
pub struct SessionSummary {
    pub id: i64,
    pub label: String,
    pub command: String,
    pub started_at_ms: i64,
    pub ended_at_ms: Option<i64>,
    pub message_count: u64,
    /// The MCP protocol version the server *selected* (from the `initialize`
    /// response, or an `MCP-Protocol-Version` header). `None` for a session with
    /// no observed handshake (e.g. a legacy pre-v6 row, or stdio traffic that never
    /// carried an `initialize`).
    pub protocol_version: Option<String>,
    /// The MCP protocol version the client *proposed* (from the `initialize`
    /// request `params.protocolVersion`). `None` when unobserved.
    pub client_protocol_version: Option<String>,
    /// How the protocol version was observed: `"initialize"` (the handshake) or
    /// `"header"` (an `MCP-Protocol-Version` header on an HTTP request). `None` when
    /// no version was observed.
    pub protocol_version_source: Option<String>,
    /// The server program: `argv[0]` for a stdio session. `None` for an HTTP session
    /// or a legacy pre-v7 row.
    pub program: Option<String>,
    /// The full stdio argv as a JSON array string, for lossless `replay`
    /// reconstruction. `None` for an HTTP session or a legacy pre-v7 row.
    pub argv_json: Option<String>,
    /// The transport this session used: `"stdio"` or `"http"`. `None` for a legacy
    /// pre-v7 row (replay then falls back to sniffing the `command`).
    pub transport: Option<String>,
    /// The structured server identity hash (`policy::server_identity_hash`) that scopes
    /// tool-fingerprint history. `None` for a legacy pre-v7 row.
    pub server_id: Option<String>,
}

/// Filter + page window for [`Store::messages`]. All fields optional except the
/// page size: `limit == 0` yields no rows.
#[derive(Default)]
pub struct MessageFilter {
    pub direction: Option<Direction>,
    pub method: Option<String>,
    /// Case-sensitive substring that must appear in the raw frame.
    pub q: Option<String>,
    pub limit: u32,
    pub offset: u32,
}

/// A row in the message list: metadata plus a bounded preview, never the full raw.
pub struct MessageRow {
    pub id: i64,
    pub ts_ms: i64,
    pub direction: Direction,
    pub method: Option<String>,
    pub rpc_id: Option<String>,
    pub is_valid_json: bool,
    pub is_error: bool,
    /// Byte length of the stored raw frame.
    pub size: u64,
    /// First 200 characters of the raw frame (never splits a UTF-8 sequence).
    pub preview: String,
}

/// A single message with its full raw body, for the detail view.
pub struct MessageDetail {
    pub id: i64,
    pub session_id: i64,
    pub ts_ms: i64,
    pub direction: Direction,
    pub method: Option<String>,
    pub rpc_id: Option<String>,
    pub is_valid_json: bool,
    pub is_error: bool,
    pub size: u64,
    pub preview: String,
    pub raw: String,
    /// Original byte length when the frame was recorded metadata-only (`raw` is then
    /// an empty string); `None` for a full recording. Lets a consumer distinguish "a
    /// genuinely empty body" from "a body that was deliberately not recorded".
    pub raw_len: Option<i64>,
}

/// Per-method aggregate for a session. Latency is derived from request/response
/// `ts_ms` differences (see [`Store::stats`]).
pub struct MethodStat {
    pub method: String,
    pub count: u64,
    pub avg_latency_ms: Option<f64>,
    pub max_latency_ms: Option<i64>,
}

/// Session-wide counters.
pub struct Totals {
    pub messages: u64,
    pub invalid: u64,
    pub errors: u64,
}

/// Aggregate view of one session.
pub struct Stats {
    pub per_method: Vec<MethodStat>,
    pub totals: Totals,
}

/// What a security event flags. Mirrors `policy::PolicyEvent`; the string tokens
/// match the `security_events.kind` CHECK constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityEventKind {
    /// A request denied by a policy rule.
    PolicyDeny,
    /// A (masked) secret detected in a frame.
    SecretLeak,
    /// A tool's fingerprint changed after first sighting (rug-pull suspicion).
    FingerprintChange,
}

impl SecurityEventKind {
    /// Stable on-disk token; matches the `security_events.kind` CHECK values.
    pub fn as_str(self) -> &'static str {
        match self {
            SecurityEventKind::PolicyDeny => "policy_deny",
            SecurityEventKind::SecretLeak => "secret_leak",
            SecurityEventKind::FingerprintChange => "fingerprint_change",
        }
    }
}

impl std::str::FromStr for SecurityEventKind {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "policy_deny" => Ok(SecurityEventKind::PolicyDeny),
            "secret_leak" => Ok(SecurityEventKind::SecretLeak),
            "fingerprint_change" => Ok(SecurityEventKind::FingerprintChange),
            _ => Err(()),
        }
    }
}

/// What the proxy did about a flagged frame. `Flagged` records-only; `Blocked`
/// means the frame was suppressed on the forwarding path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionTaken {
    Flagged,
    Blocked,
}

impl ActionTaken {
    /// Stable on-disk token; matches the `security_events.action_taken` CHECK values.
    pub fn as_str(self) -> &'static str {
        match self {
            ActionTaken::Flagged => "flagged",
            ActionTaken::Blocked => "blocked",
        }
    }
}

impl std::str::FromStr for ActionTaken {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "flagged" => Ok(ActionTaken::Flagged),
            "blocked" => Ok(ActionTaken::Blocked),
            _ => Err(()),
        }
    }
}

/// One security event, ready to persist. Append-only: there is no update/delete
/// API. `detail` is expected to be already masked by the caller.
pub struct SecurityEvent {
    pub ts_ms: i64,
    pub kind: SecurityEventKind,
    /// The rule that fired (tool name / pattern name / tool name, per `kind`).
    pub rule: String,
    /// Human-readable explanation; any secret is already redacted.
    pub detail: String,
    pub tool_name: Option<String>,
    /// The request `rpc_id` this event relates to, if any.
    pub rpc_id: Option<String>,
    pub action_taken: ActionTaken,
}

/// A persisted security event row, for the dashboard list view.
pub struct SecurityEventRow {
    pub id: i64,
    pub session_id: i64,
    pub ts_ms: i64,
    pub kind: SecurityEventKind,
    pub rule: String,
    pub detail: String,
    pub tool_name: Option<String>,
    pub rpc_id: Option<String>,
    pub action_taken: ActionTaken,
}

/// Per-kind security event tallies plus the blocked count, for a session's
/// dashboard alert badge.
pub struct SecurityCounts {
    pub policy_deny: u64,
    pub secret_leak: u64,
    pub fingerprint_change: u64,
    pub blocked: u64,
}

/// The kind of fault simulated by an injected event (Phase 3 error injection).
/// The string tokens match the `inject_events.fault` CHECK constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectFault {
    Delay,
    Error,
    Drop,
    Truncate,
}

impl InjectFault {
    /// Stable on-disk token; matches the `inject_events.fault` CHECK values.
    pub fn as_str(self) -> &'static str {
        match self {
            InjectFault::Delay => "delay",
            InjectFault::Error => "error",
            InjectFault::Drop => "drop",
            InjectFault::Truncate => "truncate",
        }
    }
}

impl std::str::FromStr for InjectFault {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "delay" => Ok(InjectFault::Delay),
            "error" => Ok(InjectFault::Error),
            "drop" => Ok(InjectFault::Drop),
            "truncate" => Ok(InjectFault::Truncate),
            _ => Err(()),
        }
    }
}

/// One fault-injection event, ready to persist. Append-only, like
/// [`SecurityEvent`]: there is no update/delete API.
pub struct InjectEvent {
    pub ts_ms: i64,
    pub direction: Direction,
    /// The rule that triggered the injection.
    pub rule: String,
    pub fault: InjectFault,
    /// Human-readable detail of the fault applied (e.g. delay duration, injected
    /// error payload).
    pub detail: String,
    pub method: Option<String>,
    /// The request `rpc_id` this event relates to, if any.
    pub rpc_id: Option<String>,
}

/// A persisted fault-injection event row, for the dashboard list view.
pub struct InjectEventRow {
    pub id: i64,
    pub session_id: i64,
    pub ts_ms: i64,
    pub direction: Direction,
    pub rule: String,
    pub fault: InjectFault,
    pub detail: String,
    pub method: Option<String>,
    pub rpc_id: Option<String>,
}

/// Per-fault-kind tallies for a session, for the dashboard's inject alert badge.
pub struct InjectCounts {
    pub delay: u64,
    pub error: u64,
    pub drop: u64,
    pub truncate: u64,
}

/// Row counts removed (or, in a dry run, that *would* be removed) by a prune / delete
/// operation. `tool_fingerprints` is deliberately absent: fingerprint baselines are
/// never pruned (they are the cross-session rug-pull trust baseline), so a pruned
/// session's `session_id` on a fingerprint row is simply left dangling.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PruneStats {
    pub sessions: u64,
    pub messages: u64,
    pub security_events: u64,
    pub inject_events: u64,
}

impl std::ops::AddAssign for PruneStats {
    fn add_assign(&mut self, rhs: Self) {
        self.sessions += rhs.sessions;
        self.messages += rhs.messages;
        self.security_events += rhs.security_events;
        self.inject_events += rhs.inject_events;
    }
}

/// One session's id, start time, and an estimate of the raw bytes it occupies (the
/// summed byte length of its recorded frames). Used by `prune --max-size` to pick the
/// oldest sessions to drop and to preview how much space a dry run would reclaim.
pub struct SessionSize {
    pub id: i64,
    pub started_at_ms: i64,
    pub est_bytes: u64,
}

/// One message row with its full body, for `mcpglass export`. Distinct from
/// [`MessageDetail`] (which carries dashboard-only fields like a preview): this is the
/// verbatim record an export bundle masks and serialises.
pub struct MessageExportRow {
    pub id: i64,
    pub ts_ms: i64,
    pub direction: Direction,
    pub method: Option<String>,
    pub rpc_id: Option<String>,
    pub is_valid_json: bool,
    pub is_error: bool,
    /// The stored raw frame (empty string for a metadata-only recording).
    pub raw: String,
    /// Original byte length when recorded metadata-only; `None` for a full recording.
    pub raw_len: Option<i64>,
}

/// Classification returned by [`Store::record_fingerprint`]: whether an observed
/// tool fingerprint is new, already seen, or a change from a prior fingerprint.
///
/// Scope is `(server_key, tool_name)` and spans sessions: the same server wrapped
/// again in a later session compares against the fingerprints it advertised before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintOutcome {
    /// The observation matches the *most recent* fingerprint on record for this
    /// `(server_key, tool)` — the definition is unchanged.
    Unchanged,
    /// First fingerprint seen for this `(server_key, tool)`.
    New,
    /// A fingerprint never seen before for this `(server_key, tool)` (rug-pull
    /// suspicion), superseding the previous most-recent one. Possibly first
    /// observed in an earlier session.
    Changed,
    /// The observation matches a *historical* (non-most-recent) fingerprint: the
    /// definition oscillated back to a previously seen one (A -> B -> A). Also a
    /// rug-pull signal — a server can flip a tool's definition between requests to
    /// evade a membership-only check.
    Reverted,
}

/// Owns a single write connection. Intended to run on one dedicated thread that
/// drains the tap channel; rusqlite `Connection` is not `Sync`.
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open a read-only consumer's view of `db_path` (the dashboard's use
    /// case). Creates parent dirs and schema as needed in WAL mode, but never
    /// renames or deletes anything: a legacy Phase-0 (v0) file is left
    /// untouched on disk and surfaced as an empty store instead. Destructive
    /// migration only happens on the tap (writer) path; see
    /// [`Store::open_with_log`].
    pub fn open(db_path: &Path) -> Result<Self> {
        if is_legacy_v0(db_path) {
            // Don't touch the file: a v0 layout has no `sessions` table (and an
            // incompatible `messages` shape), so an empty in-memory schema
            // gives read handlers "no data yet" instead of a query error.
            let conn = Connection::open_in_memory()
                .context("opening in-memory store for legacy v0 db")?;
            let store = Self { conn };
            store.init_schema()?;
            return Ok(store);
        }
        let conn = open_physical(db_path)?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    /// Like [`Store::open`], but performs the destructive v0 migration (see
    /// [`migrate_legacy_v0`]) and reports one-off migration events through
    /// `log` (the tap path has no stdout/stderr to spare, so this routes to
    /// the proxy log file instead). Use this only on the writer path.
    pub fn open_with_log(db_path: &Path, log: &dyn Fn(&str)) -> Result<Self> {
        // A Phase-0 (v0) file has an incompatible `messages` shape; move it aside
        // and start fresh before we open the live connection.
        migrate_legacy_v0(db_path, log);
        let conn = open_physical(db_path)?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<()> {
        // Fast path: a db already stamped at the current version needs no work. This
        // is a plain autocommit read that holds no lock afterwards, so several
        // connections opening an existing db (the HTTP gateway runs one storage
        // session per upstream) never contend on the schema batch below — that batch
        // reads `sqlite_master` and then writes within one transaction, a read->write
        // promotion that `busy_timeout` cannot resolve when writers overlap. The
        // first opener still creates everything atomically; the rest just skip.
        let version: i64 = self
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap_or(0);
        if version >= SCHEMA_VERSION {
            return Ok(());
        }

        // v2 -> v3 and v3 -> v4 additive upgrades FIRST, so the CREATE batch below
        // always sees a `tool_fingerprints` table that carries every current column.
        // On a pre-v3 file the table exists without `server_key` and is patched in
        // place with ADD COLUMN (existing rows backfill to '' — acceptable: those are
        // early Phase-2 fingerprints that predate server scoping). On a pre-v4 file it
        // is likewise patched with `fp_version` (backfill 1: legacy rows were hashed
        // under v1) and `last_seen_ts_ms` (backfill NULL). On a fresh db the table
        // does not exist yet, so these are no-ops and the CREATE below builds every
        // column from the start. Idempotent: re-opening a v4 file finds the columns
        // and skips the ALTERs.
        self.migrate_v3_add_server_key()?;
        self.migrate_v4_add_fp_columns()?;
        self.migrate_v6_add_session_protocol_columns()?;
        self.migrate_v7_add_identity_columns()?;

        // BEGIN/COMMIT makes table creation and the `user_version = 7` stamp one
        // atomic unit, so a concurrent reader's legacy-v0 probe (see
        // `is_legacy_v0`) can never observe the `messages` table mid-creation
        // with `user_version` still at 0 and misclassify a fresh db as v0.
        //
        // `CREATE TABLE IF NOT EXISTS` makes the v1 -> v2/v3/v4/v5/v6/v7 upgrade
        // additive: on an existing file the sessions/messages tables are left
        // untouched, any missing tables (including `inject_events` on a pre-v5 file)
        // are appended, and `user_version` is bumped to 7. The `sessions` columns
        // added at v6/v7 (and the `messages.raw_len` column added at v7) are patched
        // onto an existing table above; a fresh db builds them from the CREATE here.
        self.conn
            .execute_batch(
                "BEGIN;
                CREATE TABLE IF NOT EXISTS sessions (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    label         TEXT    NOT NULL,
                    command       TEXT    NOT NULL,
                    started_at_ms INTEGER NOT NULL,
                    ended_at_ms   INTEGER,
                    protocol_version        TEXT,
                    client_protocol_version TEXT,
                    protocol_version_source TEXT CHECK (protocol_version_source IN ('initialize','header')),
                    program       TEXT,
                    argv_json     TEXT,
                    transport     TEXT CHECK (transport IN ('stdio','http')),
                    server_id     TEXT
                );
                CREATE TABLE IF NOT EXISTS messages (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id    INTEGER NOT NULL REFERENCES sessions(id),
                    ts_ms         INTEGER NOT NULL,
                    direction     TEXT    NOT NULL CHECK (direction IN ('c2s','s2c')),
                    raw           TEXT    NOT NULL,
                    method        TEXT,
                    rpc_id        TEXT,
                    is_valid_json INTEGER NOT NULL,
                    is_error      INTEGER NOT NULL DEFAULT 0,
                    raw_len       INTEGER
                );
                CREATE INDEX IF NOT EXISTS idx_messages_session_id
                    ON messages(session_id, id);
                CREATE TABLE IF NOT EXISTS security_events (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id   INTEGER NOT NULL REFERENCES sessions(id),
                    ts_ms        INTEGER NOT NULL,
                    kind         TEXT    NOT NULL CHECK (kind IN ('policy_deny','secret_leak','fingerprint_change')),
                    rule         TEXT    NOT NULL,
                    detail       TEXT    NOT NULL,
                    tool_name    TEXT,
                    rpc_id       TEXT,
                    action_taken TEXT    NOT NULL CHECK (action_taken IN ('flagged','blocked'))
                );
                CREATE INDEX IF NOT EXISTS idx_security_events_session_id
                    ON security_events(session_id, id);
                CREATE TABLE IF NOT EXISTS tool_fingerprints (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id       INTEGER NOT NULL REFERENCES sessions(id),
                    tool_name        TEXT    NOT NULL,
                    fingerprint      TEXT    NOT NULL,
                    first_seen_ts_ms INTEGER NOT NULL,
                    server_key       TEXT    NOT NULL DEFAULT '',
                    fp_version       INTEGER NOT NULL DEFAULT 1,
                    last_seen_ts_ms  INTEGER,
                    UNIQUE (server_key, tool_name, fingerprint)
                );
                CREATE INDEX IF NOT EXISTS idx_tool_fingerprints_scope
                    ON tool_fingerprints(server_key, tool_name, id);
                CREATE TABLE IF NOT EXISTS inject_events (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL REFERENCES sessions(id),
                    ts_ms      INTEGER NOT NULL,
                    direction  TEXT    NOT NULL CHECK (direction IN ('c2s','s2c')),
                    rule       TEXT    NOT NULL,
                    fault      TEXT    NOT NULL CHECK (fault IN ('delay','error','drop','truncate')),
                    detail     TEXT    NOT NULL,
                    method     TEXT,
                    rpc_id     TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_inject_events_session_id
                    ON inject_events(session_id, id);
                PRAGMA user_version = 7;
                COMMIT;",
            )
            .context("creating v7 schema")?;
        Ok(())
    }

    /// Add the `server_key` column to a pre-v3 `tool_fingerprints` table so
    /// rug-pull detection can be scoped by server identity across sessions. A
    /// no-op when the table is absent (fresh db, handled by the CREATE in
    /// [`Store::init_schema`]) or the column already exists (a v3 file).
    ///
    /// Kept separate from the CREATE batch because `ALTER TABLE ADD COLUMN` is not
    /// conditional in SQLite: running it when the column already exists is an
    /// error, so we gate it on an explicit column probe.
    fn migrate_v3_add_server_key(&self) -> Result<()> {
        let table_exists = self
            .conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='tool_fingerprints'",
                [],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !table_exists {
            return Ok(());
        }
        let has_server_key: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('tool_fingerprints') WHERE name = 'server_key'",
            [],
            |r| r.get(0),
        )?;
        if has_server_key == 0 {
            self.conn
                .execute_batch(
                    "ALTER TABLE tool_fingerprints
                        ADD COLUMN server_key TEXT NOT NULL DEFAULT ''",
                )
                .context("adding server_key column (v2 -> v3)")?;
        }
        Ok(())
    }

    /// Add the `fp_version` and `last_seen_ts_ms` columns to a pre-v4
    /// `tool_fingerprints` table. Legacy rows backfill to `fp_version = 1` (they
    /// were hashed under the v1 algorithm) and a NULL `last_seen_ts_ms` (which the
    /// recency comparison COALESCEs to `first_seen_ts_ms`). A no-op when the table
    /// is absent (fresh db, handled by the CREATE in [`Store::init_schema`]) or the
    /// columns already exist (a v4 file).
    ///
    /// Kept separate from the CREATE batch, and gated on an explicit column probe,
    /// for the same reason as [`Store::migrate_v3_add_server_key`]: `ALTER TABLE ADD
    /// COLUMN` is not conditional in SQLite, so running it on an existing column is
    /// an error.
    fn migrate_v4_add_fp_columns(&self) -> Result<()> {
        let table_exists = self
            .conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='tool_fingerprints'",
                [],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !table_exists {
            return Ok(());
        }
        for (col, decl) in [
            ("fp_version", "fp_version INTEGER NOT NULL DEFAULT 1"),
            ("last_seen_ts_ms", "last_seen_ts_ms INTEGER"),
        ] {
            let has_col: i64 = self.conn.query_row(
                "SELECT COUNT(*) FROM pragma_table_info('tool_fingerprints') WHERE name = ?1",
                params![col],
                |r| r.get(0),
            )?;
            if has_col == 0 {
                self.conn
                    .execute_batch(&format!("ALTER TABLE tool_fingerprints ADD COLUMN {decl}"))
                    .with_context(|| format!("adding {col} column (v3 -> v4)"))?;
            }
        }
        Ok(())
    }

    /// Add the `protocol_version`, `client_protocol_version` and
    /// `protocol_version_source` columns to a pre-v6 `sessions` table so a session
    /// records the MCP protocol version it negotiated. All three are nullable, so
    /// existing rows backfill to NULL (a legacy session has no observed version). A
    /// no-op when the table is absent (fresh db, handled by the CREATE in
    /// [`Store::init_schema`]) or the columns already exist (a v6 file).
    ///
    /// Kept separate from the CREATE batch, and gated on an explicit column probe,
    /// for the same reason as [`Store::migrate_v3_add_server_key`]: `ALTER TABLE ADD
    /// COLUMN` is not conditional in SQLite, so running it on an existing column is
    /// an error. The `protocol_version_source` CHECK constraint added here matches
    /// the CREATE; a NULL backfill passes it (a CHECK only rejects an explicit
    /// out-of-set value).
    fn migrate_v6_add_session_protocol_columns(&self) -> Result<()> {
        let table_exists = self
            .conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='sessions'",
                [],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !table_exists {
            return Ok(());
        }
        for (col, decl) in [
            ("protocol_version", "protocol_version TEXT"),
            ("client_protocol_version", "client_protocol_version TEXT"),
            (
                "protocol_version_source",
                "protocol_version_source TEXT CHECK (protocol_version_source IN ('initialize','header'))",
            ),
        ] {
            let has_col: i64 = self.conn.query_row(
                "SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name = ?1",
                params![col],
                |r| r.get(0),
            )?;
            if has_col == 0 {
                self.conn
                    .execute_batch(&format!("ALTER TABLE sessions ADD COLUMN {decl}"))
                    .with_context(|| format!("adding {col} column (v5 -> v6)"))?;
            }
        }
        Ok(())
    }

    /// Add the four structured-identity columns to a pre-v7 `sessions` table
    /// (`program`, `argv_json`, `transport`, `server_id`) and the `raw_len` column to a
    /// pre-v7 `messages` table. All are nullable, so existing rows backfill to NULL (a
    /// legacy session has no structured identity; a legacy message no recorded raw
    /// length). A no-op when a table is absent (fresh db, handled by the CREATE in
    /// [`Store::init_schema`]) or the columns already exist (a v7 file).
    ///
    /// Kept separate from the CREATE batch, and gated on an explicit column probe, for
    /// the same reason as [`Store::migrate_v3_add_server_key`]: `ALTER TABLE ADD COLUMN`
    /// is not conditional in SQLite. The `transport` CHECK constraint added here matches
    /// the CREATE; a NULL backfill passes it (a CHECK only rejects an explicit
    /// out-of-set value).
    fn migrate_v7_add_identity_columns(&self) -> Result<()> {
        for (table, columns) in [
            (
                "sessions",
                &[
                    ("program", "program TEXT"),
                    ("argv_json", "argv_json TEXT"),
                    (
                        "transport",
                        "transport TEXT CHECK (transport IN ('stdio','http'))",
                    ),
                    ("server_id", "server_id TEXT"),
                ][..],
            ),
            ("messages", &[("raw_len", "raw_len INTEGER")][..]),
        ] {
            let table_exists = self
                .conn
                .query_row(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
                    params![table],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if !table_exists {
                continue;
            }
            for (col, decl) in columns {
                let has_col: i64 = self.conn.query_row(
                    &format!("SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name = ?1"),
                    params![col],
                    |r| r.get(0),
                )?;
                if has_col == 0 {
                    self.conn
                        .execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {decl}"))
                        .with_context(|| format!("adding {col} column (v6 -> v7)"))?;
                }
            }
        }
        Ok(())
    }

    /// Open a new session with no structured identity; returns its id. Used by
    /// identity-less callers (legacy paths and tests); the four v7 identity columns are
    /// left NULL. Production callers use [`Store::begin_session_with_identity`].
    pub fn begin_session(&self, label: &str, command: &str) -> Result<i64> {
        self.conn
            .execute(
                "INSERT INTO sessions (label, command, started_at_ms) VALUES (?1, ?2, ?3)",
                params![label, command, now_ms()],
            )
            .context("beginning session")?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Open a new session carrying its structured server identity (schema v7); returns
    /// its id. Call once per `wrap`/gateway upstream. `command` still stores the
    /// human-readable display string (unchanged), while `program`/`argv_json`/
    /// `transport`/`server_id` record the structured identity: for stdio, `program` is
    /// `argv[0]` and `argv_json` the full argv as a JSON array; for HTTP both are `None`.
    /// `server_id` is `policy::server_identity_hash` — the cross-session
    /// fingerprint-scope key. Best-effort like [`Store::begin_session`].
    pub fn begin_session_with_identity(
        &self,
        label: &str,
        command: &str,
        program: Option<&str>,
        argv_json: Option<&str>,
        transport: &str,
        server_id: &str,
    ) -> Result<i64> {
        self.conn
            .execute(
                "INSERT INTO sessions
                    (label, command, started_at_ms, program, argv_json, transport, server_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![label, command, now_ms(), program, argv_json, transport, server_id],
            )
            .context("beginning session with identity")?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Stamp a session's end time. Best-effort: safe to skip if the proxy dies.
    pub fn end_session(&self, id: i64) -> Result<()> {
        self.conn
            .execute(
                "UPDATE sessions SET ended_at_ms = ?2 WHERE id = ?1",
                params![id, now_ms()],
            )
            .context("ending session")?;
        Ok(())
    }

    /// Record the MCP protocol version observed for a session. `negotiated` is the
    /// version the server selected, `client_proposed` the version the client
    /// offered, and `source` how it was seen (`"initialize"` for the handshake,
    /// `"header"` for an `MCP-Protocol-Version` header). Best-effort like the other
    /// writers: any failure is returned so the caller (a storage thread off the wire
    /// path) can log-and-continue. The precedence rule (`initialize` wins over
    /// `header`, `header` writes only once) lives in the caller, not here — this is a
    /// plain `UPDATE`.
    pub fn set_session_protocol(
        &self,
        session_id: i64,
        client_proposed: Option<&str>,
        negotiated: Option<&str>,
        source: &str,
    ) -> Result<()> {
        self.conn
            .execute(
                "UPDATE sessions
                    SET protocol_version = ?2,
                        client_protocol_version = ?3,
                        protocol_version_source = ?4
                 WHERE id = ?1",
                params![session_id, negotiated, client_proposed, source],
            )
            .context("recording session protocol version")?;
        Ok(())
    }

    /// Persist one record under `session_id`, recording the full raw frame (`raw_len`
    /// left NULL). Errors are returned, not panicked, so the tap loop can
    /// drop-and-continue.
    pub fn insert(&self, session_id: i64, rec: &Record) -> Result<()> {
        self.insert_with_raw_len(session_id, rec, None)
    }

    /// Persist one record under `session_id` with an explicit `raw_len`. Used by the
    /// metadata-only recording mode, which stores `rec.raw` as an empty string and puts
    /// the original frame's byte length in `raw_len` — so size accounting and the
    /// dashboard can still show how big the (unrecorded) body was. A full recording
    /// passes `raw_len = None` (via [`Store::insert`]).
    pub fn insert_with_raw_len(
        &self,
        session_id: i64,
        rec: &Record,
        raw_len: Option<i64>,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO messages
                    (session_id, ts_ms, direction, raw, method, rpc_id, is_valid_json, is_error, raw_len)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    session_id,
                    rec.ts_ms,
                    rec.direction.as_str(),
                    rec.raw,
                    rec.method,
                    rec.rpc_id,
                    rec.is_valid_json as i64,
                    rec.is_error as i64,
                    raw_len,
                ],
            )
            .context("inserting message")?;
        Ok(())
    }

    /// All sessions, newest first, each with a live message count.
    pub fn list_sessions(&self) -> Result<Vec<SessionSummary>> {
        let mut stmt = self.conn.prepare(
            "SELECT s.id, s.label, s.command, s.started_at_ms, s.ended_at_ms,
                    (SELECT COUNT(*) FROM messages m WHERE m.session_id = s.id),
                    s.protocol_version, s.client_protocol_version, s.protocol_version_source,
                    s.program, s.argv_json, s.transport, s.server_id
             FROM sessions s
             ORDER BY s.id DESC",
        )?;
        let rows = stmt
            .query_map([], map_session_summary)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// A single session by id, with a live message count, or `None` if unknown.
    /// Same shape as [`Store::list_sessions`]'s rows, for a single-session lookup.
    pub fn session(&self, id: i64) -> Result<Option<SessionSummary>> {
        let row = self
            .conn
            .query_row(
                "SELECT s.id, s.label, s.command, s.started_at_ms, s.ended_at_ms,
                        (SELECT COUNT(*) FROM messages m WHERE m.session_id = s.id),
                        s.protocol_version, s.client_protocol_version, s.protocol_version_source,
                        s.program, s.argv_json, s.transport, s.server_id
                 FROM sessions s
                 WHERE s.id = ?1",
                params![id],
                map_session_summary,
            )
            .optional()?;
        Ok(row)
    }

    /// A filtered, paged window of a session's messages, plus the total match
    /// count (ignoring the page window) so callers can render pagination.
    /// Rows come back in chronological (`id ASC`) order.
    pub fn messages(
        &self,
        session_id: i64,
        filter: &MessageFilter,
    ) -> Result<(u64, Vec<MessageRow>)> {
        let (where_sql, params) = build_where(session_id, filter);

        let total: i64 = self.conn.query_row(
            &format!("SELECT COUNT(*) FROM messages WHERE {where_sql}"),
            params_from_iter(params.iter()),
            |r| r.get(0),
        )?;

        let mut page_params = params.clone();
        page_params.push(Value::Integer(filter.limit as i64));
        page_params.push(Value::Integer(filter.offset as i64));
        let mut stmt = self.conn.prepare(&format!(
            "SELECT id, ts_ms, direction, method, rpc_id, is_valid_json, is_error,
                    COALESCE(raw_len, length(CAST(raw AS BLOB))), substr(raw, 1, 200)
             FROM messages
             WHERE {where_sql}
             ORDER BY id ASC
             LIMIT ? OFFSET ?"
        ))?;
        let rows = stmt
            .query_map(params_from_iter(page_params.iter()), map_message_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok((total as u64, rows))
    }

    /// A single message with its full raw body, or `None` if the id is unknown.
    pub fn message(&self, id: i64) -> Result<Option<MessageDetail>> {
        let detail = self
            .conn
            .query_row(
                "SELECT id, session_id, ts_ms, direction, method, rpc_id,
                        is_valid_json, is_error, COALESCE(raw_len, length(CAST(raw AS BLOB))),
                        substr(raw, 1, 200), raw, raw_len
                 FROM messages WHERE id = ?1",
                params![id],
                |r| {
                    let dir: String = r.get(3)?;
                    Ok(MessageDetail {
                        id: r.get(0)?,
                        session_id: r.get(1)?,
                        ts_ms: r.get(2)?,
                        direction: parse_direction(&dir, 3)?,
                        method: r.get(4)?,
                        rpc_id: r.get(5)?,
                        is_valid_json: r.get(6)?,
                        is_error: r.get(7)?,
                        size: r.get::<_, i64>(8)? as u64,
                        preview: r.get(9)?,
                        raw: r.get(10)?,
                        raw_len: r.get(11)?,
                    })
                },
            )
            .optional()?;
        Ok(detail)
    }

    /// Per-method counts and request->response latency, plus session totals.
    ///
    /// Latency pairs each c2s request (with a non-null `rpc_id`) to the earliest
    /// s2c frame sharing that `rpc_id` at or after the request time, via a
    /// correlated subquery — so a request never fans out across duplicate ids and
    /// notifications (null `rpc_id`) stay unpaired (latency `NULL`).
    pub fn stats(&self, session_id: i64) -> Result<Stats> {
        let mut stmt = self.conn.prepare(
            "SELECT method,
                    COUNT(*),
                    AVG(latency),
                    MAX(latency)
             FROM (
                SELECT req.method AS method,
                       (SELECT MIN(resp.ts_ms)
                          FROM messages resp
                         WHERE resp.session_id = req.session_id
                           AND resp.direction = 's2c'
                           AND resp.rpc_id = req.rpc_id
                           AND resp.ts_ms >= req.ts_ms) - req.ts_ms AS latency
                  FROM messages req
                 WHERE req.session_id = ?1
                   AND req.direction = 'c2s'
                   AND req.method IS NOT NULL
             )
             GROUP BY method
             ORDER BY COUNT(*) DESC, method ASC",
        )?;
        let per_method = stmt
            .query_map(params![session_id], |r| {
                Ok(MethodStat {
                    method: r.get(0)?,
                    count: r.get::<_, i64>(1)? as u64,
                    avg_latency_ms: r.get(2)?,
                    max_latency_ms: r.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let totals = self.conn.query_row(
            "SELECT COUNT(*),
                    COALESCE(SUM(CASE WHEN is_valid_json = 0 THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN is_error = 1 THEN 1 ELSE 0 END), 0)
             FROM messages WHERE session_id = ?1",
            params![session_id],
            |r| {
                Ok(Totals {
                    messages: r.get::<_, i64>(0)? as u64,
                    invalid: r.get::<_, i64>(1)? as u64,
                    errors: r.get::<_, i64>(2)? as u64,
                })
            },
        )?;

        Ok(Stats {
            per_method,
            totals,
        })
    }

    /// The raw response body of a session's *most recent* `tools/list` round-trip
    /// (context-bloat analysis reads a server's current tool catalog off this),
    /// or `None` if the session never sent a `tools/list` request or the matching
    /// response never arrived.
    ///
    /// Finds the latest c2s `tools/list` request (`id DESC`) and pairs it with the
    /// earliest non-error s2c response sharing its `rpc_id` at or after the
    /// request's `ts_ms` — the same request/response pairing rule [`Store::stats`]
    /// uses for latency, but keyed to one specific request instead of aggregated.
    pub fn latest_tools_list_raw(&self, session_id: i64) -> Result<Option<String>> {
        let req: Option<(i64, Option<String>)> = self
            .conn
            .query_row(
                "SELECT ts_ms, rpc_id FROM messages
                 WHERE session_id = ?1 AND direction = 'c2s' AND method = 'tools/list'
                 ORDER BY id DESC LIMIT 1",
                params![session_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((req_ts_ms, Some(rpc_id))) = req else {
            return Ok(None);
        };
        let raw = self
            .conn
            .query_row(
                "SELECT raw FROM messages
                 WHERE session_id = ?1 AND direction = 's2c' AND method IS NULL
                   AND is_error = 0 AND rpc_id = ?2 AND ts_ms >= ?3
                 ORDER BY ts_ms ASC, id ASC LIMIT 1",
                params![session_id, rpc_id, req_ts_ms],
                |r| r.get(0),
            )
            .optional()?;
        Ok(raw)
    }

    /// Append one security event under `session_id`. Append-only: there is no
    /// update or delete counterpart. Like [`Store::insert`], errors are returned
    /// so the tap loop can log-and-continue.
    pub fn insert_security_event(&self, session_id: i64, ev: &SecurityEvent) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO security_events
                    (session_id, ts_ms, kind, rule, detail, tool_name, rpc_id, action_taken)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    session_id,
                    ev.ts_ms,
                    ev.kind.as_str(),
                    ev.rule,
                    ev.detail,
                    ev.tool_name,
                    ev.rpc_id,
                    ev.action_taken.as_str(),
                ],
            )
            .context("inserting security event")?;
        Ok(())
    }

    /// Record an observed tool definition — hashed under every algorithm version
    /// (`fp_v1`, `fp_v2`, `fp_v3`) — under `server_key` and classify it against history:
    ///
    /// - `New`: first fingerprint ever seen for this `(server_key, tool)`.
    /// - `Unchanged`: matches the *most recent* recorded fingerprint.
    /// - `Reverted`: matches a *historical* (non-most-recent) fingerprint — the
    ///   definition oscillated back (A -> B -> A).
    /// - `Changed`: a fingerprint never seen before for this `(server_key, tool)`.
    ///
    /// The caller decides whether a `Changed`/`Reverted` outcome warrants a
    /// `fingerprint_change` event; `New`/`Unchanged` are silent.
    ///
    /// **Recency, not membership.** Comparison keys on the row with the greatest
    /// `last_seen_ts_ms` (COALESCEd to `first_seen_ts_ms` for legacy rows), so a
    /// server that flips a tool between two definitions is caught each way — a plain
    /// set-membership check would silently accept the flip-back.
    ///
    /// **Dual-hash migration.** A stored row is compared on the hash matching its own
    /// `fp_version` (`fp_v1` for a v1 row, `fp_v2` for a v2 row, `fp_v3` otherwise).
    /// When an older row still matches on its version's hash, it is silently re-pinned
    /// to the current algorithm (its `fingerprint`/`fp_version` are rewritten to
    /// `fp_v3`) and reported `Unchanged` — no false-positive alert for the algorithm
    /// bump. An older-version *mismatch* is a genuine change and alerts as usual.
    ///
    /// The comparison scope is `(server_key, tool_name)` and deliberately spans
    /// sessions: the canonical rug-pull is a server approved on one `wrap` that then
    /// mutates a tool on a *later* one. `session_id` is stored for traceability.
    ///
    /// **Lazy re-key (v7).** The scope key is now the structured `server_id`
    /// (`policy::server_identity_hash`), but rows recorded before v7 are keyed on the
    /// old `legacy_key` (stdio: `argv.join(" ")`; http: the URL). To avoid resetting an
    /// established baseline on upgrade, when `server_id` has no history for this
    /// `(server, tool)` but `legacy_key` does, the server's whole fingerprint history is
    /// re-keyed from `legacy_key` to `server_id` **inside the same transaction** as the
    /// comparison and insert. The re-key is safe against the `UNIQUE (server_key,
    /// tool_name, fingerprint)` index: it only runs while `server_id` holds no rows for
    /// this tool, and a fresh `server_id` (a sha256 never used pre-v7) only gains rows
    /// via this re-key or via first-sighting inserts of tools that have no legacy
    /// baseline either — the migrated tools and the freshly-inserted ones never share a
    /// `tool_name`, so no `(tool, fingerprint)` can collide. `server_id ==
    /// legacy_key` (identity-less callers passing the same value for both) skips the
    /// re-key and behaves exactly as before.
    ///
    /// Append-only for distinct fingerprints: `Changed` inserts a new row and keeps
    /// the prior one(s); `Unchanged`/`Reverted` only refresh an existing row's
    /// `last_seen_ts_ms` (and re-pin a v1 row), so a tool's fingerprint history is
    /// preserved.
    #[allow(clippy::too_many_arguments)]
    pub fn record_fingerprint(
        &self,
        session_id: i64,
        server_id: &str,
        legacy_key: &str,
        tool_name: &str,
        fp_v1: &str,
        fp_v2: &str,
        fp_v3: &str,
        ts_ms: i64,
    ) -> Result<FingerprintOutcome> {
        // Re-key + compare + insert are one atomic unit: an upgrade must not leave a
        // half-migrated scope, and (in the gateway's multi-connection layout) the write
        // must be serialised. Use `BEGIN IMMEDIATE` so the write lock is taken up front:
        // a DEFERRED transaction would read first and only promote to a writer on the
        // UPDATE/INSERT, and two connections promoting at once is the one deadlock
        // `busy_timeout` cannot resolve (the same hazard `init_schema` avoids). On any
        // error the transaction is rolled back before the error propagates.
        self.conn
            .execute_batch("BEGIN IMMEDIATE")
            .context("beginning fingerprint transaction")?;
        match self.record_fingerprint_txn(
            session_id, server_id, legacy_key, tool_name, fp_v1, fp_v2, fp_v3, ts_ms,
        ) {
            Ok(outcome) => {
                // A failed COMMIT must not leak an open transaction: the connection
                // lives for the whole session, and every later `BEGIN IMMEDIATE` on it
                // would fail ("transaction within a transaction"), silently disabling
                // fingerprinting until restart. Roll back best-effort, then propagate.
                if let Err(e) = self
                    .conn
                    .execute_batch("COMMIT")
                    .context("committing fingerprint transaction")
                {
                    let _ = self.conn.execute_batch("ROLLBACK");
                    return Err(e);
                }
                Ok(outcome)
            }
            Err(e) => {
                // Best-effort rollback; the original error is what matters to the caller.
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    /// The body of [`Store::record_fingerprint`], run inside the caller's
    /// `BEGIN IMMEDIATE` transaction: load the structured-`server_id` history, lazily
    /// re-key a pre-v7 `legacy_key` baseline onto it, then classify and record.
    #[allow(clippy::too_many_arguments)]
    fn record_fingerprint_txn(
        &self,
        session_id: i64,
        server_id: &str,
        legacy_key: &str,
        tool_name: &str,
        fp_v1: &str,
        fp_v2: &str,
        fp_v3: &str,
        ts_ms: i64,
    ) -> Result<FingerprintOutcome> {
        // Load history for the structured server_id first. If it has none for this
        // (server, tool) but the pre-v7 legacy_key does, migrate the whole server's
        // history to server_id once (idempotent: after the batch UPDATE, legacy_key holds
        // no rows, so this never fires twice).
        let mut rows = self.fingerprint_history(server_id, tool_name)?;
        if rows.is_empty() && server_id != legacy_key {
            let legacy = self.fingerprint_history(legacy_key, tool_name)?;
            if !legacy.is_empty() {
                self.conn
                    .execute(
                        "UPDATE tool_fingerprints SET server_key = ?1 WHERE server_key = ?2",
                        params![server_id, legacy_key],
                    )
                    .context("re-keying fingerprints to the structured server_id")?;
                rows = self.fingerprint_history(server_id, tool_name)?;
            }
        }

        self.classify_fingerprint(
            &rows, session_id, server_id, tool_name, fp_v1, fp_v2, fp_v3, ts_ms,
        )
    }

    /// History for one `(server_key, tool)`, most recent observation first. A NULL
    /// `last_seen` (legacy pre-v4 row) falls back to `first_seen` for ordering. Returns
    /// owned rows so the borrowed statement is dropped before any write in the same
    /// transaction.
    fn fingerprint_history(
        &self,
        server_key: &str,
        tool_name: &str,
    ) -> Result<Vec<(i64, String, i64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, fingerprint, fp_version
             FROM tool_fingerprints
             WHERE server_key = ?1 AND tool_name = ?2
             ORDER BY COALESCE(last_seen_ts_ms, first_seen_ts_ms) DESC, id DESC",
        )?;
        let rows = stmt
            .query_map(params![server_key, tool_name], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Classify an observation against `rows` (already scoped to `server_id`/tool, most
    /// recent first) and record it: insert a fresh baseline, touch a matched row, or
    /// insert a changed one. The New/Unchanged/Reverted/Changed decision and the
    /// dual-hash matching rule (a stored row is compared on the hash matching its own
    /// `fp_version`).
    #[allow(clippy::too_many_arguments)]
    fn classify_fingerprint(
        &self,
        rows: &[(i64, String, i64)],
        session_id: i64,
        server_id: &str,
        tool_name: &str,
        fp_v1: &str,
        fp_v2: &str,
        fp_v3: &str,
        ts_ms: i64,
    ) -> Result<FingerprintOutcome> {
        // First sighting: pin the current (v3) baseline and stay silent.
        if rows.is_empty() {
            self.insert_fingerprint(session_id, server_id, tool_name, fp_v3, ts_ms)?;
            return Ok(FingerprintOutcome::New);
        }

        // Does the observation match a stored row? Each row is compared on the hash
        // matching its own algorithm version (dual-hash transition): a v1 row on the
        // v1 hash, a v2 row on the v2 hash, a v3 (or newer) row on the v3 hash.
        let matches = |fingerprint: &str, fp_version: i64| -> bool {
            match fp_version {
                v if v <= 1 => fingerprint == fp_v1,
                2 => fingerprint == fp_v2,
                _ => fingerprint == fp_v3,
            }
        };

        // Matches the current (most-recent) definition -> Unchanged.
        let (latest_id, latest_fp, latest_ver) = &rows[0];
        if matches(latest_fp, *latest_ver) {
            self.touch_fingerprint(*latest_id, *latest_ver, fp_v3, ts_ms)?;
            return Ok(FingerprintOutcome::Unchanged);
        }

        // Matches an older definition -> the tool oscillated back (Reverted).
        if let Some((id, _, ver)) = rows.iter().find(|(_, fp, ver)| matches(fp, *ver)) {
            self.touch_fingerprint(*id, *ver, fp_v3, ts_ms)?;
            return Ok(FingerprintOutcome::Reverted);
        }

        // A definition never seen before for this (server, tool) -> Changed.
        self.insert_fingerprint(session_id, server_id, tool_name, fp_v3, ts_ms)?;
        Ok(FingerprintOutcome::Changed)
    }

    /// Insert a fresh v3 fingerprint row (first_seen == last_seen == `ts_ms`).
    fn insert_fingerprint(
        &self,
        session_id: i64,
        server_key: &str,
        tool_name: &str,
        fp_v3: &str,
        ts_ms: i64,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO tool_fingerprints
                    (session_id, server_key, tool_name, fingerprint,
                     first_seen_ts_ms, last_seen_ts_ms, fp_version)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5, 3)",
                params![session_id, server_key, tool_name, fp_v3, ts_ms],
            )
            .context("recording tool fingerprint")?;
        Ok(())
    }

    /// Refresh a matched row's `last_seen_ts_ms`. A legacy row hashed under an older
    /// algorithm (`fp_version < 3`) is additionally re-pinned to v3 (its `fingerprint`
    /// becomes `fp_v3`, `fp_version` becomes 3), folding the fields the newer algorithm
    /// covers (annotations, outputSchema) into the baseline without an alert. A v3 row
    /// keeps its fingerprint (already `fp_v3`), avoiding any UNIQUE churn.
    fn touch_fingerprint(
        &self,
        id: i64,
        fp_version: i64,
        fp_v3: &str,
        ts_ms: i64,
    ) -> Result<()> {
        if fp_version < 3 {
            self.conn.execute(
                "UPDATE tool_fingerprints
                    SET last_seen_ts_ms = ?2, fingerprint = ?3, fp_version = 3
                 WHERE id = ?1",
                params![id, ts_ms, fp_v3],
            )
        } else {
            self.conn.execute(
                "UPDATE tool_fingerprints SET last_seen_ts_ms = ?2 WHERE id = ?1",
                params![id, ts_ms],
            )
        }
        .context("refreshing tool fingerprint")?;
        Ok(())
    }

    /// A paged window of a session's security events plus the total match count
    /// (ignoring the window), for the dashboard. Rows come back oldest-first
    /// (`id ASC`).
    pub fn security_events(
        &self,
        session_id: i64,
        limit: u32,
        offset: u32,
    ) -> Result<(u64, Vec<SecurityEventRow>)> {
        let total: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM security_events WHERE session_id = ?1",
            params![session_id],
            |r| r.get(0),
        )?;
        let mut stmt = self.conn.prepare(
            "SELECT id, session_id, ts_ms, kind, rule, detail, tool_name, rpc_id, action_taken
             FROM security_events
             WHERE session_id = ?1
             ORDER BY id ASC
             LIMIT ?2 OFFSET ?3",
        )?;
        let rows = stmt
            .query_map(
                params![session_id, limit as i64, offset as i64],
                map_security_event_row,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok((total as u64, rows))
    }

    /// Per-kind counts plus the blocked count for a session, for the alert badge.
    pub fn security_event_counts(&self, session_id: i64) -> Result<SecurityCounts> {
        let counts = self.conn.query_row(
            "SELECT
                COALESCE(SUM(CASE WHEN kind = 'policy_deny' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN kind = 'secret_leak' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN kind = 'fingerprint_change' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN action_taken = 'blocked' THEN 1 ELSE 0 END), 0)
             FROM security_events WHERE session_id = ?1",
            params![session_id],
            |r| {
                Ok(SecurityCounts {
                    policy_deny: r.get::<_, i64>(0)? as u64,
                    secret_leak: r.get::<_, i64>(1)? as u64,
                    fingerprint_change: r.get::<_, i64>(2)? as u64,
                    blocked: r.get::<_, i64>(3)? as u64,
                })
            },
        )?;
        Ok(counts)
    }

    /// Append one fault-injection event under `session_id`. Append-only, like
    /// [`Store::insert_security_event`]: no update or delete counterpart.
    pub fn insert_inject_event(&self, session_id: i64, ev: &InjectEvent) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO inject_events
                    (session_id, ts_ms, direction, rule, fault, detail, method, rpc_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    session_id,
                    ev.ts_ms,
                    ev.direction.as_str(),
                    ev.rule,
                    ev.fault.as_str(),
                    ev.detail,
                    ev.method,
                    ev.rpc_id,
                ],
            )
            .context("inserting inject event")?;
        Ok(())
    }

    /// A paged window of a session's fault-injection events plus the total match
    /// count (ignoring the window), for the dashboard. Rows come back oldest-first
    /// (`id ASC`) — mirrors [`Store::security_events`].
    pub fn inject_events(
        &self,
        session_id: i64,
        limit: u32,
        offset: u32,
    ) -> Result<(u64, Vec<InjectEventRow>)> {
        let total: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM inject_events WHERE session_id = ?1",
            params![session_id],
            |r| r.get(0),
        )?;
        let mut stmt = self.conn.prepare(
            "SELECT id, session_id, ts_ms, direction, rule, fault, detail, method, rpc_id
             FROM inject_events
             WHERE session_id = ?1
             ORDER BY id ASC
             LIMIT ?2 OFFSET ?3",
        )?;
        let rows = stmt
            .query_map(
                params![session_id, limit as i64, offset as i64],
                map_inject_event_row,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok((total as u64, rows))
    }

    /// Per-fault-kind counts for a session, for the dashboard's inject alert badge.
    /// Mirrors [`Store::security_event_counts`].
    pub fn inject_event_counts(&self, session_id: i64) -> Result<InjectCounts> {
        let counts = self.conn.query_row(
            "SELECT
                COALESCE(SUM(CASE WHEN fault = 'delay' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN fault = 'error' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN fault = 'drop' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN fault = 'truncate' THEN 1 ELSE 0 END), 0)
             FROM inject_events WHERE session_id = ?1",
            params![session_id],
            |r| {
                Ok(InjectCounts {
                    delay: r.get::<_, i64>(0)? as u64,
                    error: r.get::<_, i64>(1)? as u64,
                    drop: r.get::<_, i64>(2)? as u64,
                    truncate: r.get::<_, i64>(3)? as u64,
                })
            },
        )?;
        Ok(counts)
    }

    // -- data lifecycle (WF4): prune / delete / size / vacuum ----------------

    /// Delete one session and every row that belongs to it (`messages`,
    /// `security_events`, `inject_events`) in a single transaction, returning the row
    /// counts removed. Returns `None` if no session has this id (so a caller can answer
    /// 404). **`tool_fingerprints` rows are never deleted** — they are the cross-session
    /// rug-pull trust baseline and must outlive the session that first recorded them
    /// (the dangling `session_id` there is for traceability only).
    pub fn delete_session(&self, id: i64) -> Result<Option<PruneStats>> {
        let exists = self
            .conn
            .query_row("SELECT 1 FROM sessions WHERE id = ?1", params![id], |_| Ok(()))
            .optional()?
            .is_some();
        if !exists {
            return Ok(None);
        }
        let stats = self.delete_with_fk_disabled(|| self.delete_session_rows(id))?;
        Ok(Some(stats))
    }

    /// Delete every session started strictly before `cutoff_ms` (and all of its
    /// messages/security/inject rows) in a single transaction; returns the row counts
    /// removed. Keeps `tool_fingerprints` (see [`Store::delete_session`]). The companion
    /// [`Store::preview_sessions_before`] counts the same set without deleting, for a
    /// dry run.
    pub fn prune_sessions_before(&self, cutoff_ms: i64) -> Result<PruneStats> {
        self.delete_with_fk_disabled(|| {
            let sub = "SELECT id FROM sessions WHERE started_at_ms < ?1";
            let messages = self.conn.execute(
                &format!("DELETE FROM messages WHERE session_id IN ({sub})"),
                params![cutoff_ms],
            )?;
            let security_events = self.conn.execute(
                &format!("DELETE FROM security_events WHERE session_id IN ({sub})"),
                params![cutoff_ms],
            )?;
            let inject_events = self.conn.execute(
                &format!("DELETE FROM inject_events WHERE session_id IN ({sub})"),
                params![cutoff_ms],
            )?;
            let sessions = self
                .conn
                .execute("DELETE FROM sessions WHERE started_at_ms < ?1", params![cutoff_ms])?;
            Ok(PruneStats {
                sessions: sessions as u64,
                messages: messages as u64,
                security_events: security_events as u64,
                inject_events: inject_events as u64,
            })
        })
    }

    /// Count (without deleting) what [`Store::prune_sessions_before`] would remove for
    /// `cutoff_ms` — the dry-run counterpart.
    pub fn preview_sessions_before(&self, cutoff_ms: i64) -> Result<PruneStats> {
        let sub = "SELECT id FROM sessions WHERE started_at_ms < ?1";
        let count = |table: &str, extra: &str| -> Result<u64> {
            let n: i64 = self.conn.query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE {extra}"),
                params![cutoff_ms],
                |r| r.get(0),
            )?;
            Ok(n as u64)
        };
        Ok(PruneStats {
            sessions: count("sessions", "started_at_ms < ?1")?,
            messages: count("messages", &format!("session_id IN ({sub})"))?,
            security_events: count("security_events", &format!("session_id IN ({sub})"))?,
            inject_events: count("inject_events", &format!("session_id IN ({sub})"))?,
        })
    }

    /// Count (without deleting) the rows one session id occupies, for a `--max-size`
    /// dry run's per-session accounting. A missing id yields all-zero counts.
    pub fn preview_session(&self, id: i64) -> Result<PruneStats> {
        let count = |table: &str, col: &str| -> Result<u64> {
            let n: i64 = self.conn.query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE {col} = ?1"),
                params![id],
                |r| r.get(0),
            )?;
            Ok(n as u64)
        };
        Ok(PruneStats {
            sessions: count("sessions", "id")?,
            messages: count("messages", "session_id")?,
            security_events: count("security_events", "session_id")?,
            inject_events: count("inject_events", "session_id")?,
        })
    }

    /// The id of the oldest session (earliest `started_at_ms`), or `None` when the db has
    /// no sessions. Used by `prune --max-size` to drop oldest-first.
    pub fn oldest_session(&self) -> Result<Option<i64>> {
        let id = self
            .conn
            .query_row(
                "SELECT id FROM sessions ORDER BY started_at_ms ASC, id ASC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        Ok(id)
    }

    /// Every session, oldest-first, with an estimate of the raw bytes it occupies (the
    /// summed byte length of its `messages.raw`). Drives the `--max-size` dry-run
    /// preview: it walks this list oldest-first, accumulating `est_bytes`, to estimate
    /// which sessions a real run would drop.
    pub fn session_size_estimates(&self) -> Result<Vec<SessionSize>> {
        let mut stmt = self.conn.prepare(
            "SELECT s.id, s.started_at_ms,
                    COALESCE((SELECT SUM(length(CAST(m.raw AS BLOB)))
                                FROM messages m WHERE m.session_id = s.id), 0)
             FROM sessions s
             ORDER BY s.started_at_ms ASC, s.id ASC",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(SessionSize {
                    id: r.get(0)?,
                    started_at_ms: r.get(1)?,
                    est_bytes: r.get::<_, i64>(2)?.max(0) as u64,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Delete the oldest sessions until *live* data ([`Store::db_used_bytes`]) is at or
    /// under `target_bytes`, returning the row counts removed. Oldest-first, one session
    /// per transaction (via [`Store::delete_session`]); if a session races away between
    /// the pick and the delete it stops rather than spinning. Does **not** vacuum — the
    /// caller decides when to realise the freed pages on disk (both `prune --max-size`
    /// and the dashboard vacuum afterwards). Keeps `tool_fingerprints` (see
    /// [`Store::delete_session`]). [`Store::preview_max_size`] is the dry-run counterpart.
    pub fn prune_to_max_size(&self, target_bytes: u64) -> Result<PruneStats> {
        let mut acc = PruneStats::default();
        loop {
            if self.db_used_bytes()? <= target_bytes {
                break;
            }
            let Some(oldest) = self.oldest_session()? else {
                break; // nothing left to delete
            };
            match self.delete_session(oldest)? {
                Some(s) => acc += s,
                None => break, // raced away; stop rather than spin
            }
        }
        Ok(acc)
    }

    /// Count (without deleting) what [`Store::prune_to_max_size`] would remove for
    /// `target_bytes`: walk [`Store::session_size_estimates`] oldest-first, subtracting
    /// each session's estimated bytes from the current live size and accumulating its row
    /// counts, until the running size would drop to the target. The space figure is an
    /// estimate — a real vacuum's exact reclaim can't be known without deleting — so this
    /// is for a `--dry-run` preview only.
    pub fn preview_max_size(&self, target_bytes: u64) -> Result<PruneStats> {
        let mut remaining = self.db_used_bytes()?;
        let mut acc = PruneStats::default();
        for s in self.session_size_estimates()? {
            if remaining <= target_bytes {
                break;
            }
            acc += self.preview_session(s.id)?;
            remaining = remaining.saturating_sub(s.est_bytes);
        }
        Ok(acc)
    }

    /// The on-disk size of the database file: `page_count * page_size`. In WAL mode a
    /// delete frees pages onto the freelist (reused, not returned to the OS), so this
    /// does not shrink until [`Store::vacuum`]; use [`Store::db_used_bytes`] to gauge
    /// live data during a prune loop.
    pub fn db_size_bytes(&self) -> Result<u64> {
        let page_count: i64 = self.conn.query_row("PRAGMA page_count", [], |r| r.get(0))?;
        let page_size: i64 = self.conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        Ok((page_count.max(0) * page_size.max(0)) as u64)
    }

    /// Bytes of *live* data: `(page_count - freelist_count) * page_size`, i.e. roughly
    /// the size the file would shrink to after a VACUUM. `prune --max-size` deletes the
    /// oldest sessions until this drops to the target, then vacuums to realise it on
    /// disk (the freed pages a plain delete leaves on the freelist are why
    /// [`Store::db_size_bytes`] alone can't drive the loop).
    pub fn db_used_bytes(&self) -> Result<u64> {
        let page_count: i64 = self.conn.query_row("PRAGMA page_count", [], |r| r.get(0))?;
        let freelist: i64 = self.conn.query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
        let page_size: i64 = self.conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        Ok(((page_count - freelist).max(0) * page_size.max(0)) as u64)
    }

    /// Rebuild the database file, returning freed pages to the OS (the on-disk size then
    /// reflects live data only). Must run outside a transaction; the lifecycle callers
    /// invoke it after their deletes have committed.
    pub fn vacuum(&self) -> Result<()> {
        self.conn.execute_batch("VACUUM").context("vacuuming database")?;
        Ok(())
    }

    /// Every message of a session, oldest-first, with its full body and `raw_len`, for
    /// `mcpglass export`. Read-only.
    pub fn export_messages(&self, session_id: i64) -> Result<Vec<MessageExportRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ts_ms, direction, method, rpc_id, is_valid_json, is_error, raw, raw_len
             FROM messages WHERE session_id = ?1 ORDER BY id ASC",
        )?;
        let rows = stmt
            .query_map(params![session_id], |r| {
                let dir: String = r.get(2)?;
                Ok(MessageExportRow {
                    id: r.get(0)?,
                    ts_ms: r.get(1)?,
                    direction: parse_direction(&dir, 2)?,
                    method: r.get(3)?,
                    rpc_id: r.get(4)?,
                    is_valid_json: r.get(5)?,
                    is_error: r.get(6)?,
                    raw: r.get(7)?,
                    raw_len: r.get(8)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Delete the child + session rows for one id, assuming an open transaction. Children
    /// first, then the session (`tool_fingerprints` is intentionally left intact).
    fn delete_session_rows(&self, id: i64) -> Result<PruneStats> {
        let messages = self
            .conn
            .execute("DELETE FROM messages WHERE session_id = ?1", params![id])?;
        let security_events = self
            .conn
            .execute("DELETE FROM security_events WHERE session_id = ?1", params![id])?;
        let inject_events = self
            .conn
            .execute("DELETE FROM inject_events WHERE session_id = ?1", params![id])?;
        let sessions = self
            .conn
            .execute("DELETE FROM sessions WHERE id = ?1", params![id])?;
        Ok(PruneStats {
            sessions: sessions as u64,
            messages: messages as u64,
            security_events: security_events as u64,
            inject_events: inject_events as u64,
        })
    }

    /// Run a delete `f` in a transaction with foreign-key enforcement disabled for its
    /// duration, then restored. Deleting a session while **keeping** its
    /// `tool_fingerprints` rows (whose `session_id` is intentionally left dangling — the
    /// cross-session rug-pull baseline must outlive its session) would otherwise trip the
    /// `tool_fingerprints.session_id REFERENCES sessions(id)` constraint on the bundled
    /// SQLite (which enforces foreign keys). `PRAGMA foreign_keys` can only be toggled
    /// *outside* a transaction, so it is set here around [`Store::in_immediate_txn`], and
    /// restored to its previous value afterwards.
    fn delete_with_fk_disabled<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        let was_on: i64 = self
            .conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap_or(1);
        let _ = self.conn.execute_batch("PRAGMA foreign_keys = OFF");
        let result = self.in_immediate_txn(f);
        if was_on != 0 {
            let _ = self.conn.execute_batch("PRAGMA foreign_keys = ON");
        }
        result
    }

    /// Run `f` inside a `BEGIN IMMEDIATE` transaction, committing on `Ok` and rolling
    /// back on any error (and on a failed commit). Modelled on the transaction handling
    /// in [`Store::record_fingerprint`]: `IMMEDIATE` takes the write lock up front so
    /// two writers (e.g. the tap thread and a dashboard-driven delete) can't deadlock on
    /// a read->write promotion that `busy_timeout` can't resolve.
    fn in_immediate_txn<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        self.conn
            .execute_batch("BEGIN IMMEDIATE")
            .context("beginning transaction")?;
        match f() {
            Ok(v) => {
                if let Err(e) = self
                    .conn
                    .execute_batch("COMMIT")
                    .context("committing transaction")
                {
                    let _ = self.conn.execute_batch("ROLLBACK");
                    return Err(e);
                }
                Ok(v)
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }
}

/// Build the shared `WHERE` fragment (using anonymous `?` placeholders) and its
/// bound values for the message list + count queries.
fn build_where(session_id: i64, f: &MessageFilter) -> (String, Vec<Value>) {
    let mut clauses = vec!["session_id = ?".to_owned()];
    let mut params = vec![Value::Integer(session_id)];
    if let Some(d) = f.direction {
        clauses.push("direction = ?".to_owned());
        params.push(Value::Text(d.as_str().to_owned()));
    }
    if let Some(m) = &f.method {
        clauses.push("method = ?".to_owned());
        params.push(Value::Text(m.clone()));
    }
    if let Some(q) = &f.q {
        // instr(): literal substring, so `%`/`_` in the query are not wildcards.
        clauses.push("instr(raw, ?) > 0".to_owned());
        params.push(Value::Text(q.clone()));
    }
    (clauses.join(" AND "), params)
}

/// Map a `sessions` row (joined with its live message count, the three v6 protocol
/// columns, and the four v7 identity columns, in that column order) to a
/// [`SessionSummary`]. Shared by [`Store::list_sessions`] and [`Store::session`].
fn map_session_summary(r: &rusqlite::Row) -> rusqlite::Result<SessionSummary> {
    Ok(SessionSummary {
        id: r.get(0)?,
        label: r.get(1)?,
        command: r.get(2)?,
        started_at_ms: r.get(3)?,
        ended_at_ms: r.get(4)?,
        message_count: r.get::<_, i64>(5)? as u64,
        protocol_version: r.get(6)?,
        client_protocol_version: r.get(7)?,
        protocol_version_source: r.get(8)?,
        program: r.get(9)?,
        argv_json: r.get(10)?,
        transport: r.get(11)?,
        server_id: r.get(12)?,
    })
}

fn map_message_row(r: &rusqlite::Row) -> rusqlite::Result<MessageRow> {
    let dir: String = r.get(2)?;
    Ok(MessageRow {
        id: r.get(0)?,
        ts_ms: r.get(1)?,
        direction: parse_direction(&dir, 2)?,
        method: r.get(3)?,
        rpc_id: r.get(4)?,
        is_valid_json: r.get(5)?,
        is_error: r.get(6)?,
        size: r.get::<_, i64>(7)? as u64,
        preview: r.get(8)?,
    })
}

/// The `direction` CHECK constraint makes an unknown token impossible, but map it
/// to a conversion error rather than assuming.
fn parse_direction(s: &str, col: usize) -> rusqlite::Result<Direction> {
    s.parse::<Direction>().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            col,
            rusqlite::types::Type::Text,
            format!("unexpected direction {s:?}").into(),
        )
    })
}

fn map_security_event_row(r: &rusqlite::Row) -> rusqlite::Result<SecurityEventRow> {
    let kind: String = r.get(3)?;
    let action: String = r.get(8)?;
    Ok(SecurityEventRow {
        id: r.get(0)?,
        session_id: r.get(1)?,
        ts_ms: r.get(2)?,
        kind: parse_token(&kind, 3, "security event kind")?,
        rule: r.get(4)?,
        detail: r.get(5)?,
        tool_name: r.get(6)?,
        rpc_id: r.get(7)?,
        action_taken: parse_token(&action, 8, "action_taken")?,
    })
}

fn map_inject_event_row(r: &rusqlite::Row) -> rusqlite::Result<InjectEventRow> {
    let dir: String = r.get(3)?;
    let fault: String = r.get(5)?;
    Ok(InjectEventRow {
        id: r.get(0)?,
        session_id: r.get(1)?,
        ts_ms: r.get(2)?,
        direction: parse_direction(&dir, 3)?,
        rule: r.get(4)?,
        fault: parse_token(&fault, 5, "inject fault")?,
        detail: r.get(6)?,
        method: r.get(7)?,
        rpc_id: r.get(8)?,
    })
}

/// Parse a CHECK-constrained token back into its enum. The constraint makes an
/// unknown value impossible, but map it to a conversion error rather than assume.
fn parse_token<T: std::str::FromStr>(s: &str, col: usize, what: &str) -> rusqlite::Result<T> {
    s.parse::<T>().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            col,
            rusqlite::types::Type::Text,
            format!("unexpected {what} {s:?}").into(),
        )
    })
}

/// Open the physical sqlite file at `db_path` in WAL mode, creating parent
/// dirs as needed. Does not touch schema/`user_version`; callers must follow
/// up with `init_schema`.
fn open_physical(db_path: &Path) -> Result<Connection> {
    if let Some(parent) = db_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating db dir {}", parent.display()))?;
        }
    }
    // The sessions db records full raw traffic, including any secret in flight — treat
    // it as sensitive at rest. On Unix, restrict it to the owner (0600) before SQLite
    // opens it: pre-creating a fresh file 0600 also makes SQLite create the -wal/-shm
    // sidecars with the same mode (it matches them to the main db file). On Windows the
    // default %LOCALAPPDATA% ACL already limits the file to the current user, so no ACL
    // work is done here. Best-effort throughout: a permission failure is never a reason
    // to fail opening the db (fail-open).
    #[cfg(unix)]
    restrict_file_permissions(db_path);
    let conn = Connection::open(db_path)
        .with_context(|| format!("opening db {}", db_path.display()))?;
    // WAL still allows only one writer at a time. The stdio `wrap` path has a single
    // writer, but the HTTP gateway runs one storage session per upstream — i.e.
    // several writer connections on this same db. Set the busy timeout FIRST, before
    // the mode-switching pragmas below, so every subsequent lock acquisition (WAL
    // switch, inserts) waits-and-retries instead of failing fast with SQLITE_BUSY.
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .context("setting busy_timeout")?;
    // WAL lets a separate reader (e.g. the dashboard) observe the live session
    // without blocking the writer.
    conn.pragma_update(None, "journal_mode", "WAL")
        .context("enabling WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .context("setting synchronous")?;
    Ok(conn)
}

/// Probe `db_path` on a short-lived connection for the Phase-0 (v0) layout:
/// `user_version == 0` with a `messages` table. Returns `false` if the path
/// doesn't exist or can't be probed, leaving it for the real open to surface.
///
/// Public so a read-only caller (the dashboard) can decide *before* opening a
/// [`Store`] whether caching the connection is safe: [`Store::open`] hands
/// back an empty in-memory store for a v0 file, so a cached handle would stay
/// pinned to "no data" even after the tap writer's [`Store::open_with_log`]
/// migrates the file on disk. See `dashboard::serve`.
pub fn is_legacy_v0(db_path: &Path) -> bool {
    if !db_path.exists() {
        return false;
    }
    match Connection::open(db_path) {
        Ok(probe) => {
            let version: i64 = probe
                .pragma_query_value(None, "user_version", |r| r.get(0))
                .unwrap_or(SCHEMA_VERSION);
            let has_messages = probe
                .query_row(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='messages'",
                    [],
                    |_| Ok(()),
                )
                .optional()
                .map(|o| o.is_some())
                .unwrap_or(false);
            version == 0 && has_messages
        }
        // Can't even open it to probe: leave it for the real open to surface.
        Err(_) => false,
    }
}

/// Move an existing Phase-0 (`user_version = 0` with a `messages` table) file to
/// `<db>.v0-backup` so a clean v1 file can take its place. Phase-0 data is
/// disposable. On any failure we fall open: leave the file and let `init_schema`
/// do what it can. Best-effort throughout; the connection is not open yet.
fn migrate_legacy_v0(db_path: &Path, log: &dyn Fn(&str)) {
    // Probing on a short-lived connection keeps the file unlocked before we
    // rename it (Windows will not rename a file with an open handle).
    if !is_legacy_v0(db_path) {
        return;
    }

    let backup = append_suffix(db_path, ".v0-backup");
    match std::fs::rename(db_path, &backup) {
        Ok(()) => {
            // The WAL/SHM sidecars belong to the discarded db; drop them so the
            // fresh file starts clean rather than adopting stale journal state.
            for suffix in ["-wal", "-shm"] {
                let _ = std::fs::remove_file(append_suffix(db_path, suffix));
            }
            log(&format!(
                "migrated legacy v0 db to {} (phase-0 data discarded)",
                backup.display()
            ));
        }
        Err(e) => {
            // Fail-open: continue on the existing file. init_schema adds what it
            // can; degraded recording is acceptable, a hard failure is not.
            log(&format!(
                "could not back up legacy v0 db ({e}); continuing on existing file"
            ));
        }
    }
}

/// Restrict `path` to owner-only read/write (0600). If the file does not exist yet it
/// is pre-created empty with that mode (so SQLite opens an already-restricted file and
/// matches its -wal/-shm sidecars to it); an existing file has its mode reset
/// best-effort. Any failure is ignored — hardening must never block opening the db.
#[cfg(unix)]
fn restrict_file_permissions(path: &Path) {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if path.exists() {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    } else {
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(path);
    }
}

/// `path` with `suffix` appended to the full file name (not a path component).
fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A private temp dir unique to each test, cleaned on drop.
    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "mcpglass-test-{}-{}-{:?}",
                tag,
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }
        fn db(&self) -> PathBuf {
            self.0.join("sessions.db")
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Record a fingerprint on a fresh (all-v3) db: `fp` is the v3 hash and the v1/v2
    /// hashes are distinct derived strings. Since fresh-db rows are all v3, matching
    /// keys on the v3 value, so `fp` alone drives New/Unchanged/Changed/Reverted.
    fn rf(store: &Store, sid: i64, srv: &str, tool: &str, fp: &str, ts: i64) -> FingerprintOutcome {
        // Pass `srv` as both server_id and legacy_key: identical keys skip the lazy
        // re-key, so this exercises the classification logic exactly as pre-v7.
        store
            .record_fingerprint(sid, srv, srv, tool, &format!("{fp}-v1"), &format!("{fp}-v2"), fp, ts)
            .unwrap()
    }

    fn rec(direction: Direction, ts_ms: i64, raw: &str) -> Record {
        let p = proxy_core::parse_line(raw.as_bytes(), direction);
        Record {
            ts_ms,
            direction,
            raw: raw.to_owned(),
            method: p.method,
            rpc_id: p.rpc_id,
            is_valid_json: p.is_valid_json,
            is_error: p.is_error,
        }
    }

    #[test]
    fn begin_end_and_list_sessions() {
        let tmp = TempDir::new("sessions");
        let store = Store::open(&tmp.db()).unwrap();
        let s1 = store.begin_session("first", "echo a").unwrap();
        let s2 = store.begin_session("second", "echo b").unwrap();
        store
            .insert(s1, &rec(Direction::C2s, 1, r#"{"id":1,"method":"ping"}"#))
            .unwrap();
        store.end_session(s1).unwrap();

        let sessions = store.list_sessions().unwrap();
        assert_eq!(sessions.len(), 2);
        // Newest first.
        assert_eq!(sessions[0].id, s2);
        assert_eq!(sessions[1].id, s1);
        assert_eq!(sessions[1].label, "first");
        assert_eq!(sessions[1].message_count, 1);
        assert!(sessions[1].ended_at_ms.is_some());
        assert!(sessions[0].ended_at_ms.is_none());
    }

    /// Hand-build a v0 file: the old single-table schema, user_version left 0.
    fn write_legacy_v0_db(db: &Path) {
        let conn = Connection::open(db).unwrap();
        conn.execute_batch(
            "CREATE TABLE messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_ms INTEGER NOT NULL,
                direction TEXT NOT NULL,
                raw TEXT NOT NULL,
                method TEXT,
                rpc_id TEXT,
                is_valid_json INTEGER NOT NULL
            );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO messages (ts_ms, direction, raw, is_valid_json)
             VALUES (1, 'c2s', 'old', 1)",
            [],
        )
        .unwrap();
    }

    #[test]
    fn writer_open_migrates_legacy_v0_file() {
        let tmp = TempDir::new("v0-writer");
        let db = tmp.db();
        write_legacy_v0_db(&db);

        let store = Store::open_with_log(&db, &|_| {}).unwrap();
        // Old file preserved as a backup...
        assert!(append_suffix(&db, ".v0-backup").exists());
        // ...and the new file is a clean, functional v1 (empty, insert works).
        let version: i64 = store
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        let sid = store.begin_session("fresh", "echo").unwrap();
        store
            .insert(sid, &rec(Direction::C2s, 2, r#"{"id":1,"method":"ping"}"#))
            .unwrap();
        let (total, _) = store.messages(sid, &page(50)).unwrap();
        assert_eq!(total, 1);
    }

    #[test]
    fn read_only_open_does_not_migrate_and_sees_no_data() {
        let tmp = TempDir::new("v0-reader");
        let db = tmp.db();
        write_legacy_v0_db(&db);

        // The dashboard's read-only path must never rename/delete the file...
        let store = Store::open(&db).unwrap();
        assert!(db.exists());
        assert!(!append_suffix(&db, ".v0-backup").exists());
        // ...and must see it as empty rather than erroring on a missing
        // `sessions` table.
        assert!(store.list_sessions().unwrap().is_empty());
        let (total, rows) = store.messages(1, &page(50)).unwrap();
        assert_eq!(total, 0);
        assert!(rows.is_empty());

        // The on-disk v0 file is untouched; a later writer open can still
        // migrate it normally.
        let writer = Store::open_with_log(&db, &|_| {}).unwrap();
        assert!(append_suffix(&db, ".v0-backup").exists());
        assert!(writer.list_sessions().unwrap().is_empty());
    }

    fn page(limit: u32) -> MessageFilter {
        MessageFilter {
            limit,
            ..Default::default()
        }
    }

    #[test]
    fn message_filter_and_pagination() {
        let tmp = TempDir::new("filter");
        let store = Store::open(&tmp.db()).unwrap();
        let sid = store.begin_session("s", "echo").unwrap();
        store
            .insert(sid, &rec(Direction::C2s, 1, r#"{"id":1,"method":"initialize"}"#))
            .unwrap();
        store
            .insert(sid, &rec(Direction::S2c, 2, r#"{"id":1,"result":{"ok":true}}"#))
            .unwrap();
        store
            .insert(sid, &rec(Direction::C2s, 3, r#"{"id":2,"method":"tools/list"}"#))
            .unwrap();
        store
            .insert(sid, &rec(Direction::S2c, 4, r#"{"id":2,"result":{"tools":[]}}"#))
            .unwrap();

        // Direction filter.
        let (total, rows) = store
            .messages(
                sid,
                &MessageFilter {
                    direction: Some(Direction::C2s),
                    ..page(50)
                },
            )
            .unwrap();
        assert_eq!(total, 2);
        assert!(rows.iter().all(|r| r.direction == Direction::C2s));

        // Method filter.
        let (total, rows) = store
            .messages(
                sid,
                &MessageFilter {
                    method: Some("tools/list".to_owned()),
                    ..page(50)
                },
            )
            .unwrap();
        assert_eq!(total, 1);
        assert_eq!(rows[0].method.as_deref(), Some("tools/list"));

        // Raw substring filter.
        let (total, _) = store
            .messages(
                sid,
                &MessageFilter {
                    q: Some("\"ok\":true".to_owned()),
                    ..page(50)
                },
            )
            .unwrap();
        assert_eq!(total, 1);

        // Pagination: total ignores the window, rows respect it and stay ordered.
        let (total, rows) = store
            .messages(
                sid,
                &MessageFilter {
                    limit: 2,
                    offset: 1,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(total, 4);
        assert_eq!(rows.len(), 2);
        assert!(rows[0].id < rows[1].id);
    }

    #[test]
    fn preview_truncates_at_200_chars_without_splitting_utf8() {
        let tmp = TempDir::new("preview");
        let store = Store::open(&tmp.db()).unwrap();
        let sid = store.begin_session("s", "echo").unwrap();
        // 300 multi-byte chars: preview must be exactly the first 200, intact.
        let raw: String = "あ".repeat(300);
        store
            .insert(sid, &rec(Direction::S2c, 1, &raw))
            .unwrap();
        let (_, rows) = store.messages(sid, &page(50)).unwrap();
        assert_eq!(rows[0].preview.chars().count(), 200);
        assert!(rows[0].preview.chars().all(|c| c == 'あ'));
        // size is the byte length of the full raw (300 * 3 bytes for 'あ').
        assert_eq!(rows[0].size, 900);
    }

    #[test]
    fn stats_pairs_latency_and_counts_errors() {
        let tmp = TempDir::new("stats");
        let store = Store::open(&tmp.db()).unwrap();
        let sid = store.begin_session("s", "echo").unwrap();
        // ping: request at 100, response at 150  -> latency 50.
        store
            .insert(sid, &rec(Direction::C2s, 100, r#"{"id":1,"method":"ping"}"#))
            .unwrap();
        store
            .insert(sid, &rec(Direction::S2c, 150, r#"{"id":1,"result":{}}"#))
            .unwrap();
        // ping again: request at 200, response at 260 -> latency 60.
        store
            .insert(sid, &rec(Direction::C2s, 200, r#"{"id":2,"method":"ping"}"#))
            .unwrap();
        store
            .insert(sid, &rec(Direction::S2c, 260, r#"{"id":2,"result":{}}"#))
            .unwrap();
        // A notification: has a method, no id -> must NOT be paired.
        store
            .insert(
                sid,
                &rec(Direction::C2s, 300, r#"{"method":"notifications/x"}"#),
            )
            .unwrap();
        // An error response to a tools/call request.
        store
            .insert(sid, &rec(Direction::C2s, 400, r#"{"id":3,"method":"tools/call"}"#))
            .unwrap();
        store
            .insert(
                sid,
                &rec(
                    Direction::S2c,
                    470,
                    r#"{"id":3,"error":{"code":-32601,"message":"no"}}"#,
                ),
            )
            .unwrap();
        // A non-JSON line -> counts as invalid.
        store
            .insert(sid, &rec(Direction::S2c, 500, "not json"))
            .unwrap();

        let stats = store.stats(sid).unwrap();

        let ping = stats
            .per_method
            .iter()
            .find(|m| m.method == "ping")
            .expect("ping stats");
        assert_eq!(ping.count, 2);
        assert_eq!(ping.avg_latency_ms, Some(55.0)); // (50 + 60) / 2
        assert_eq!(ping.max_latency_ms, Some(60));

        // Notification is counted once but never paired -> no latency.
        let notif = stats
            .per_method
            .iter()
            .find(|m| m.method == "notifications/x")
            .expect("notification stats");
        assert_eq!(notif.count, 1);
        assert_eq!(notif.avg_latency_ms, None);
        assert_eq!(notif.max_latency_ms, None);

        let call = stats
            .per_method
            .iter()
            .find(|m| m.method == "tools/call")
            .expect("tools/call stats");
        assert_eq!(call.max_latency_ms, Some(70));

        assert_eq!(stats.totals.messages, 8);
        assert_eq!(stats.totals.invalid, 1);
        assert_eq!(stats.totals.errors, 1);
    }

    #[test]
    fn message_detail_returns_full_raw_or_none() {
        let tmp = TempDir::new("detail");
        let store = Store::open(&tmp.db()).unwrap();
        let sid = store.begin_session("s", "echo").unwrap();
        let raw = r#"{"id":1,"method":"ping","params":{"big":"payload"}}"#;
        store.insert(sid, &rec(Direction::C2s, 1, raw)).unwrap();
        let (_, rows) = store.messages(sid, &page(50)).unwrap();
        let id = rows[0].id;

        let detail = store.message(id).unwrap().expect("detail");
        assert_eq!(detail.raw, raw);
        assert_eq!(detail.session_id, sid);
        assert_eq!(detail.direction, Direction::C2s);
        assert!(store.message(999_999).unwrap().is_none());
    }

    fn sec_event(kind: SecurityEventKind, action: ActionTaken) -> SecurityEvent {
        SecurityEvent {
            ts_ms: 1,
            kind,
            rule: "rule".to_owned(),
            detail: "masked detail".to_owned(),
            tool_name: Some("tool".to_owned()),
            rpc_id: Some("7".to_owned()),
            action_taken: action,
        }
    }

    /// Hand-build a v1 file: the v1 schema (sessions + messages) with a session
    /// and a message, `user_version` stamped 1.
    fn write_legacy_v1_db(db: &Path) {
        let conn = Connection::open(db).unwrap();
        conn.execute_batch(
            "BEGIN;
            CREATE TABLE sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                label TEXT NOT NULL,
                command TEXT NOT NULL,
                started_at_ms INTEGER NOT NULL,
                ended_at_ms INTEGER
            );
            CREATE TABLE messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL REFERENCES sessions(id),
                ts_ms INTEGER NOT NULL,
                direction TEXT NOT NULL CHECK (direction IN ('c2s','s2c')),
                raw TEXT NOT NULL,
                method TEXT,
                rpc_id TEXT,
                is_valid_json INTEGER NOT NULL,
                is_error INTEGER NOT NULL DEFAULT 0
            );
            PRAGMA user_version = 1;
            COMMIT;",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO sessions (label, command, started_at_ms) VALUES ('old', 'echo old', 42)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO messages
                (session_id, ts_ms, direction, raw, method, rpc_id, is_valid_json, is_error)
             VALUES (1, 100, 'c2s', '{\"id\":1,\"method\":\"ping\"}', 'ping', '1', 1, 0)",
            [],
        )
        .unwrap();
    }

    #[test]
    fn v1_to_v7_additive_upgrade_preserves_data() {
        let tmp = TempDir::new("v1-upgrade");
        let db = tmp.db();
        write_legacy_v1_db(&db);

        // Opening a v1 file upgrades it in place to the current schema...
        let store = Store::open(&db).unwrap();
        let version: i64 = store
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        assert_eq!(SCHEMA_VERSION, 7);

        // ...without disturbing the pre-existing v1 data.
        let sessions = store.list_sessions().unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].label, "old");
        assert_eq!(sessions[0].message_count, 1);
        let (total, rows) = store.messages(1, &page(50)).unwrap();
        assert_eq!(total, 1);
        assert_eq!(rows[0].method.as_deref(), Some("ping"));

        // The new v2/v3 tables are present and usable on the upgraded file.
        store
            .insert_security_event(1, &sec_event(SecurityEventKind::PolicyDeny, ActionTaken::Blocked))
            .unwrap();
        let (n, ev_rows) = store.security_events(1, 50, 0).unwrap();
        assert_eq!(n, 1);
        assert_eq!(ev_rows.len(), 1);
        assert_eq!(rf(&store, 1, "srv", "t", "fp", 1), FingerprintOutcome::New);
    }

    /// Hand-build a v2 file: the v2 schema (sessions + messages + security_events +
    /// the *pre-v3* tool_fingerprints without `server_key`) with one row in each,
    /// `user_version` stamped 2.
    fn write_legacy_v2_db(db: &Path) {
        let conn = Connection::open(db).unwrap();
        conn.execute_batch(
            "BEGIN;
            CREATE TABLE sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                label TEXT NOT NULL,
                command TEXT NOT NULL,
                started_at_ms INTEGER NOT NULL,
                ended_at_ms INTEGER
            );
            CREATE TABLE messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL REFERENCES sessions(id),
                ts_ms INTEGER NOT NULL,
                direction TEXT NOT NULL CHECK (direction IN ('c2s','s2c')),
                raw TEXT NOT NULL,
                method TEXT,
                rpc_id TEXT,
                is_valid_json INTEGER NOT NULL,
                is_error INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL REFERENCES sessions(id),
                ts_ms INTEGER NOT NULL,
                kind TEXT NOT NULL CHECK (kind IN ('policy_deny','secret_leak','fingerprint_change')),
                rule TEXT NOT NULL,
                detail TEXT NOT NULL,
                tool_name TEXT,
                rpc_id TEXT,
                action_taken TEXT NOT NULL CHECK (action_taken IN ('flagged','blocked'))
            );
            CREATE TABLE tool_fingerprints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL REFERENCES sessions(id),
                tool_name TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                first_seen_ts_ms INTEGER NOT NULL,
                UNIQUE (session_id, tool_name, fingerprint)
            );
            PRAGMA user_version = 2;
            COMMIT;",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO sessions (label, command, started_at_ms) VALUES ('old', 'echo old', 42)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO messages
                (session_id, ts_ms, direction, raw, method, rpc_id, is_valid_json, is_error)
             VALUES (1, 100, 'c2s', '{\"id\":1,\"method\":\"ping\"}', 'ping', '1', 1, 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO security_events
                (session_id, ts_ms, kind, rule, detail, tool_name, rpc_id, action_taken)
             VALUES (1, 100, 'policy_deny', 'r', 'd', 't', '1', 'flagged')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO tool_fingerprints
                (session_id, tool_name, fingerprint, first_seen_ts_ms)
             VALUES (1, 'legacy_tool', 'legacy_fp', 100)",
            [],
        )
        .unwrap();
    }

    #[test]
    fn v2_to_v7_additive_upgrade_preserves_data() {
        let tmp = TempDir::new("v2-upgrade");
        let db = tmp.db();
        write_legacy_v2_db(&db);

        // Opening a v2 file upgrades it in place to v7 via ALTER TABLE ADD COLUMN...
        let store = Store::open(&db).unwrap();
        let version: i64 = store
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, 7);

        // ...preserving all pre-existing v2 rows (sessions/messages/events).
        let sessions = store.list_sessions().unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].label, "old");
        assert_eq!(sessions[0].message_count, 1);
        let (n, _) = store.security_events(1, 50, 0).unwrap();
        assert_eq!(n, 1);

        // The pre-v3 fingerprint row survives, now carrying an empty server_key.
        let (fp_session, fp_server): (i64, String) = store
            .conn
            .query_row(
                "SELECT session_id, server_key FROM tool_fingerprints WHERE tool_name = 'legacy_tool'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(fp_session, 1);
        assert_eq!(fp_server, "");

        // New fingerprints record under the v3 server_key scope on the upgraded file.
        assert_eq!(rf(&store, 1, "srv", "t", "fp", 200), FingerprintOutcome::New);

        // Re-opening the upgraded file is a no-op (ALTERs not re-run) and still v7.
        let store2 = Store::open(&db).unwrap();
        let version2: i64 = store2
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version2, 7);
    }

    #[test]
    fn security_events_insert_and_paginate() {
        let tmp = TempDir::new("secev");
        let store = Store::open(&tmp.db()).unwrap();
        let sid = store.begin_session("s", "echo").unwrap();
        for i in 0..5 {
            let ev = SecurityEvent {
                ts_ms: i,
                kind: SecurityEventKind::SecretLeak,
                rule: format!("pattern{i}"),
                detail: "***".to_owned(),
                tool_name: None,
                rpc_id: Some(i.to_string()),
                action_taken: ActionTaken::Flagged,
            };
            store.insert_security_event(sid, &ev).unwrap();
        }

        // total ignores the window; rows respect it and stay ordered (id ASC).
        let (total, rows) = store.security_events(sid, 2, 1).unwrap();
        assert_eq!(total, 5);
        assert_eq!(rows.len(), 2);
        assert!(rows[0].id < rows[1].id);
        // offset 1 -> the second-oldest event.
        assert_eq!(rows[0].rule, "pattern1");
        assert_eq!(rows[0].kind, SecurityEventKind::SecretLeak);
        assert_eq!(rows[0].action_taken, ActionTaken::Flagged);
        assert_eq!(rows[0].tool_name, None);
        assert_eq!(rows[0].rpc_id.as_deref(), Some("1"));
        assert_eq!(rows[0].session_id, sid);
    }

    #[test]
    fn security_events_empty_session_returns_zero() {
        let tmp = TempDir::new("secev-empty");
        let store = Store::open(&tmp.db()).unwrap();
        let sid = store.begin_session("s", "echo").unwrap();
        let (total, rows) = store.security_events(sid, 50, 0).unwrap();
        assert_eq!(total, 0);
        assert!(rows.is_empty());
        let counts = store.security_event_counts(sid).unwrap();
        assert_eq!(counts.policy_deny, 0);
        assert_eq!(counts.secret_leak, 0);
        assert_eq!(counts.fingerprint_change, 0);
        assert_eq!(counts.blocked, 0);
    }

    #[test]
    fn security_event_counts_by_kind_and_blocked() {
        let tmp = TempDir::new("seccount");
        let store = Store::open(&tmp.db()).unwrap();
        let sid = store.begin_session("s", "echo").unwrap();
        store
            .insert_security_event(sid, &sec_event(SecurityEventKind::PolicyDeny, ActionTaken::Blocked))
            .unwrap();
        store
            .insert_security_event(sid, &sec_event(SecurityEventKind::PolicyDeny, ActionTaken::Flagged))
            .unwrap();
        store
            .insert_security_event(sid, &sec_event(SecurityEventKind::SecretLeak, ActionTaken::Flagged))
            .unwrap();
        store
            .insert_security_event(
                sid,
                &sec_event(SecurityEventKind::FingerprintChange, ActionTaken::Blocked),
            )
            .unwrap();

        let c = store.security_event_counts(sid).unwrap();
        assert_eq!(c.policy_deny, 2);
        assert_eq!(c.secret_leak, 1);
        assert_eq!(c.fingerprint_change, 1);
        assert_eq!(c.blocked, 2);
    }

    #[test]
    fn record_fingerprint_new_unchanged_changed() {
        let tmp = TempDir::new("fp");
        let store = Store::open(&tmp.db()).unwrap();
        let sid = store.begin_session("s", "echo").unwrap();
        let srv = "echo";

        // First sighting of a tool -> New.
        assert_eq!(rf(&store, sid, srv, "search", "aaa", 1), FingerprintOutcome::New);
        // Same tool, same fingerprint -> Unchanged.
        assert_eq!(rf(&store, sid, srv, "search", "aaa", 2), FingerprintOutcome::Unchanged);
        // Same tool, a brand-new fingerprint -> Changed (rug-pull suspicion).
        assert_eq!(rf(&store, sid, srv, "search", "bbb", 3), FingerprintOutcome::Changed);
        // A different tool is New again, independent of `search`.
        assert_eq!(rf(&store, sid, srv, "fetch", "aaa", 4), FingerprintOutcome::New);
    }

    #[test]
    fn record_fingerprint_reverts_on_oscillation() {
        // A -> B -> A: returning to a previously-seen definition is Reverted, not
        // Unchanged — a set-membership check would miss the flip-back.
        let tmp = TempDir::new("fp-oscillation");
        let store = Store::open(&tmp.db()).unwrap();
        let sid = store.begin_session("s", "echo").unwrap();
        let srv = "echo";

        assert_eq!(rf(&store, sid, srv, "search", "aaa", 1), FingerprintOutcome::New);
        assert_eq!(rf(&store, sid, srv, "search", "bbb", 2), FingerprintOutcome::Changed);
        // Back to aaa: it is in history but no longer the most recent -> Reverted.
        assert_eq!(rf(&store, sid, srv, "search", "aaa", 3), FingerprintOutcome::Reverted);
        // Flip forward to bbb again: bbb is now the older one -> Reverted again.
        assert_eq!(rf(&store, sid, srv, "search", "bbb", 4), FingerprintOutcome::Reverted);
        // Re-observing the current definition (aaa is now most recent) -> Unchanged.
        assert_eq!(rf(&store, sid, srv, "search", "bbb", 5), FingerprintOutcome::Unchanged);
    }

    #[test]
    fn record_fingerprint_detects_rug_pull_across_sessions() {
        let tmp = TempDir::new("fp-cross-session");
        let store = Store::open(&tmp.db()).unwrap();
        let srv = "npx some-server";

        // Session 1 approves `search` under fingerprint aaa.
        let s1 = store.begin_session("run1", srv).unwrap();
        assert_eq!(rf(&store, s1, srv, "search", "aaa", 1), FingerprintOutcome::New);

        // A LATER session wrapping the SAME server re-advertises `search`...
        let s2 = store.begin_session("run2", srv).unwrap();
        // ...with the same definition -> Unchanged (no false positive across runs).
        assert_eq!(rf(&store, s2, srv, "search", "aaa", 2), FingerprintOutcome::Unchanged);
        // ...but a mutated definition is caught as Changed even though it is the
        // first time THIS session saw the tool (the canonical rug-pull).
        assert_eq!(rf(&store, s2, srv, "search", "bbb", 3), FingerprintOutcome::Changed);
    }

    #[test]
    fn record_fingerprint_isolates_distinct_server_keys() {
        let tmp = TempDir::new("fp-server-isolation");
        let store = Store::open(&tmp.db()).unwrap();
        let sid = store.begin_session("s", "echo").unwrap();

        // The same tool name under a different server_key is a different tool: its
        // fingerprint does not interfere with the other server's history.
        assert_eq!(rf(&store, sid, "server-a", "search", "aaa", 1), FingerprintOutcome::New);
        assert_eq!(rf(&store, sid, "server-b", "search", "zzz", 2), FingerprintOutcome::New);
        // server-a's `search` re-advertised as aaa is still Unchanged; server-b's
        // divergent fingerprint never counted as a change for server-a.
        assert_eq!(rf(&store, sid, "server-a", "search", "aaa", 3), FingerprintOutcome::Unchanged);
    }

    #[test]
    fn record_fingerprint_keeps_history_append_only() {
        let tmp = TempDir::new("fp-history");
        let store = Store::open(&tmp.db()).unwrap();
        let sid = store.begin_session("s", "echo").unwrap();
        let srv = "echo";
        rf(&store, sid, srv, "search", "aaa", 1);
        assert_eq!(rf(&store, sid, srv, "search", "bbb", 2), FingerprintOutcome::Changed);

        // Both fingerprint rows are retained (no overwrite on a change).
        let count: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM tool_fingerprints
                 WHERE server_key = ?1 AND tool_name = 'search'",
                params![srv],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 2);

        // Re-recording the older fingerprint is now Reverted (oscillation), and the
        // current one is Unchanged — history is preserved either way (still 2 rows).
        assert_eq!(rf(&store, sid, srv, "search", "aaa", 3), FingerprintOutcome::Reverted);
        assert_eq!(rf(&store, sid, srv, "search", "aaa", 4), FingerprintOutcome::Unchanged);
        let count2: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM tool_fingerprints
                 WHERE server_key = ?1 AND tool_name = 'search'",
                params![srv],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count2, 2);
    }

    /// Hand-build a v3 file: the v1/v2 tables plus the *pre-v4* tool_fingerprints
    /// (with `server_key` but no `fp_version` / `last_seen_ts_ms`) carrying one
    /// legacy v1 fingerprint row, `user_version` stamped 3.
    fn write_legacy_v3_db(db: &Path, legacy_v1_fp: &str) {
        let conn = Connection::open(db).unwrap();
        conn.execute_batch(
            "BEGIN;
            CREATE TABLE sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                label TEXT NOT NULL,
                command TEXT NOT NULL,
                started_at_ms INTEGER NOT NULL,
                ended_at_ms INTEGER
            );
            CREATE TABLE messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL REFERENCES sessions(id),
                ts_ms INTEGER NOT NULL,
                direction TEXT NOT NULL CHECK (direction IN ('c2s','s2c')),
                raw TEXT NOT NULL,
                method TEXT,
                rpc_id TEXT,
                is_valid_json INTEGER NOT NULL,
                is_error INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL REFERENCES sessions(id),
                ts_ms INTEGER NOT NULL,
                kind TEXT NOT NULL CHECK (kind IN ('policy_deny','secret_leak','fingerprint_change')),
                rule TEXT NOT NULL,
                detail TEXT NOT NULL,
                tool_name TEXT,
                rpc_id TEXT,
                action_taken TEXT NOT NULL CHECK (action_taken IN ('flagged','blocked'))
            );
            CREATE TABLE tool_fingerprints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL REFERENCES sessions(id),
                tool_name TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                first_seen_ts_ms INTEGER NOT NULL,
                server_key TEXT NOT NULL DEFAULT '',
                UNIQUE (server_key, tool_name, fingerprint)
            );
            PRAGMA user_version = 3;
            COMMIT;",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO sessions (label, command, started_at_ms) VALUES ('old', 'srv', 42)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO tool_fingerprints
                (session_id, server_key, tool_name, fingerprint, first_seen_ts_ms)
             VALUES (1, 'srv', 'search', ?1, 100)",
            params![legacy_v1_fp],
        )
        .unwrap();
    }

    #[test]
    fn v3_to_v7_additive_upgrade_preserves_and_backfills_fingerprints() {
        let tmp = TempDir::new("v3-upgrade");
        let db = tmp.db();
        write_legacy_v3_db(&db, "legacy_v1");

        // Opening a v3 file upgrades it in place to v7 via ALTER TABLE ADD COLUMN...
        let store = Store::open(&db).unwrap();
        let version: i64 = store
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, 7);

        // ...the legacy fingerprint row survives, backfilled to fp_version=1 with a
        // NULL last_seen_ts_ms (recency then falls back to first_seen_ts_ms).
        let (fp_version, last_seen): (i64, Option<i64>) = store
            .conn
            .query_row(
                "SELECT fp_version, last_seen_ts_ms FROM tool_fingerprints WHERE tool_name = 'search'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(fp_version, 1);
        assert_eq!(last_seen, None);

        // Re-opening the upgraded file is a no-op (ALTERs not re-run) and still v7.
        let store2 = Store::open(&db).unwrap();
        let version2: i64 = store2
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version2, 7);
    }

    #[test]
    fn record_fingerprint_dual_hash_silently_repins_matching_v1_row() {
        // A legacy v1 row whose v1 hash still matches is re-pinned to v3 with no
        // alert (Unchanged) — the algorithm bump must not be a false positive.
        let tmp = TempDir::new("fp-dualhash-repin");
        let db = tmp.db();
        write_legacy_v3_db(&db, "v1hashA");
        let store = Store::open(&db).unwrap();

        // v1 matches the stored legacy hash -> Unchanged, and the row is re-pinned.
        assert_eq!(
            store.record_fingerprint(1, "srv", "srv", "search", "v1hashA", "v2hashA", "v3hashA", 200).unwrap(),
            FingerprintOutcome::Unchanged
        );
        let (fp_version, fingerprint): (i64, String) = store
            .conn
            .query_row(
                "SELECT fp_version, fingerprint FROM tool_fingerprints WHERE tool_name = 'search'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(fp_version, 3, "legacy v1 row should be re-pinned to v3");
        assert_eq!(fingerprint, "v3hashA");

        // Now that the baseline folds in annotations + outputSchema, a later change to
        // one of those (same v1, different v3) IS detected as a change.
        assert_eq!(
            store.record_fingerprint(1, "srv", "srv", "search", "v1hashA", "v2hashA", "v3hashB", 300).unwrap(),
            FingerprintOutcome::Changed
        );
    }

    #[test]
    fn record_fingerprint_dual_hash_alerts_when_v1_changed() {
        // A legacy v1 row whose v1 hash no longer matches is a genuine change.
        let tmp = TempDir::new("fp-dualhash-alert");
        let db = tmp.db();
        write_legacy_v3_db(&db, "v1hashA");
        let store = Store::open(&db).unwrap();

        assert_eq!(
            store.record_fingerprint(1, "srv", "srv", "search", "v1hashB", "v2hashB", "v3hashB", 200).unwrap(),
            FingerprintOutcome::Changed
        );
    }

    /// Hand-build a v4 file: the full v4 schema (sessions/messages/security_events/
    /// tool_fingerprints with `fp_version`/`last_seen_ts_ms`, no `inject_events`
    /// table yet) with one row in each, `user_version` stamped 4.
    fn write_legacy_v4_db(db: &Path) {
        let conn = Connection::open(db).unwrap();
        conn.execute_batch(
            "BEGIN;
            CREATE TABLE sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                label TEXT NOT NULL,
                command TEXT NOT NULL,
                started_at_ms INTEGER NOT NULL,
                ended_at_ms INTEGER
            );
            CREATE TABLE messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL REFERENCES sessions(id),
                ts_ms INTEGER NOT NULL,
                direction TEXT NOT NULL CHECK (direction IN ('c2s','s2c')),
                raw TEXT NOT NULL,
                method TEXT,
                rpc_id TEXT,
                is_valid_json INTEGER NOT NULL,
                is_error INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL REFERENCES sessions(id),
                ts_ms INTEGER NOT NULL,
                kind TEXT NOT NULL CHECK (kind IN ('policy_deny','secret_leak','fingerprint_change')),
                rule TEXT NOT NULL,
                detail TEXT NOT NULL,
                tool_name TEXT,
                rpc_id TEXT,
                action_taken TEXT NOT NULL CHECK (action_taken IN ('flagged','blocked'))
            );
            CREATE TABLE tool_fingerprints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL REFERENCES sessions(id),
                tool_name TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                first_seen_ts_ms INTEGER NOT NULL,
                server_key TEXT NOT NULL DEFAULT '',
                fp_version INTEGER NOT NULL DEFAULT 1,
                last_seen_ts_ms INTEGER,
                UNIQUE (server_key, tool_name, fingerprint)
            );
            PRAGMA user_version = 4;
            COMMIT;",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO sessions (label, command, started_at_ms) VALUES ('old', 'srv', 42)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO messages
                (session_id, ts_ms, direction, raw, method, rpc_id, is_valid_json, is_error)
             VALUES (1, 100, 'c2s', '{\"id\":1,\"method\":\"ping\"}', 'ping', '1', 1, 0)",
            [],
        )
        .unwrap();
    }

    #[test]
    fn v4_to_v7_additive_upgrade_adds_inject_events() {
        let tmp = TempDir::new("v4-upgrade");
        let db = tmp.db();
        write_legacy_v4_db(&db);

        // Opening a v4 file upgrades it in place to v7 (inject_events + session
        // protocol columns + v7 identity columns)...
        let store = Store::open(&db).unwrap();
        let version: i64 = store
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, 7);

        // ...preserving the pre-existing v4 rows...
        let sessions = store.list_sessions().unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].label, "old");
        assert_eq!(sessions[0].message_count, 1);

        // ...and inject_events is present and usable on the upgraded file.
        store
            .insert_inject_event(
                1,
                &InjectEvent {
                    ts_ms: 10,
                    direction: Direction::C2s,
                    rule: "slow-tool".to_owned(),
                    fault: InjectFault::Delay,
                    detail: "delayed 500ms".to_owned(),
                    method: Some("tools/call".to_owned()),
                    rpc_id: Some("1".to_owned()),
                },
            )
            .unwrap();
        let (total, rows) = store.inject_events(1, 50, 0).unwrap();
        assert_eq!(total, 1);
        assert_eq!(rows.len(), 1);

        // Re-opening the upgraded file is a no-op and still v7.
        let store2 = Store::open(&db).unwrap();
        let version2: i64 = store2
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version2, 7);
    }

    /// Hand-build a v5 file: the full v5 schema (sessions *without* the v6 protocol
    /// columns, plus messages/security_events/tool_fingerprints/inject_events) with a
    /// session and a message, `user_version` stamped 5.
    fn write_legacy_v5_db(db: &Path) {
        let conn = Connection::open(db).unwrap();
        conn.execute_batch(
            "BEGIN;
            CREATE TABLE sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                label TEXT NOT NULL,
                command TEXT NOT NULL,
                started_at_ms INTEGER NOT NULL,
                ended_at_ms INTEGER
            );
            CREATE TABLE messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL REFERENCES sessions(id),
                ts_ms INTEGER NOT NULL,
                direction TEXT NOT NULL CHECK (direction IN ('c2s','s2c')),
                raw TEXT NOT NULL,
                method TEXT,
                rpc_id TEXT,
                is_valid_json INTEGER NOT NULL,
                is_error INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL REFERENCES sessions(id),
                ts_ms INTEGER NOT NULL,
                kind TEXT NOT NULL CHECK (kind IN ('policy_deny','secret_leak','fingerprint_change')),
                rule TEXT NOT NULL,
                detail TEXT NOT NULL,
                tool_name TEXT,
                rpc_id TEXT,
                action_taken TEXT NOT NULL CHECK (action_taken IN ('flagged','blocked'))
            );
            CREATE TABLE tool_fingerprints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL REFERENCES sessions(id),
                tool_name TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                first_seen_ts_ms INTEGER NOT NULL,
                server_key TEXT NOT NULL DEFAULT '',
                fp_version INTEGER NOT NULL DEFAULT 1,
                last_seen_ts_ms INTEGER,
                UNIQUE (server_key, tool_name, fingerprint)
            );
            CREATE TABLE inject_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL REFERENCES sessions(id),
                ts_ms INTEGER NOT NULL,
                direction TEXT NOT NULL CHECK (direction IN ('c2s','s2c')),
                rule TEXT NOT NULL,
                fault TEXT NOT NULL CHECK (fault IN ('delay','error','drop','truncate')),
                detail TEXT NOT NULL,
                method TEXT,
                rpc_id TEXT
            );
            PRAGMA user_version = 5;
            COMMIT;",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO sessions (label, command, started_at_ms) VALUES ('old', 'srv', 42)",
            [],
        )
        .unwrap();
        // A pre-existing v2 fingerprint row: the v2 -> v3 dual-hash transition must not
        // false-positive when this tool is re-observed after the upgrade.
        conn.execute(
            "INSERT INTO tool_fingerprints
                (session_id, server_key, tool_name, fingerprint, first_seen_ts_ms, last_seen_ts_ms, fp_version)
             VALUES (1, 'srv', 'search', 'v2only', 100, 100, 2)",
            [],
        )
        .unwrap();
    }

    #[test]
    fn v5_to_v7_additive_upgrade_adds_session_protocol_columns() {
        let tmp = TempDir::new("v5-upgrade");
        let db = tmp.db();
        write_legacy_v5_db(&db);

        // Opening a v5 file upgrades it in place to v7 (the three nullable v6 protocol
        // columns plus the four v7 identity columns), leaving the pre-existing row's
        // protocol and identity fields NULL.
        let store = Store::open(&db).unwrap();
        let version: i64 = store
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, 7);

        let row = store.session(1).unwrap().expect("session");
        assert_eq!(row.label, "old");
        assert_eq!(row.protocol_version, None);
        assert_eq!(row.client_protocol_version, None);
        assert_eq!(row.protocol_version_source, None);
        // The v7 identity columns backfill to NULL on a legacy row.
        assert_eq!(row.program, None);
        assert_eq!(row.argv_json, None);
        assert_eq!(row.transport, None);
        assert_eq!(row.server_id, None);

        // Re-opening the upgraded file is a no-op (ALTERs not re-run) and still v7.
        let store2 = Store::open(&db).unwrap();
        let version2: i64 = store2
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version2, 7);
    }

    /// Hand-build a v6 file: the full v6 schema (sessions *with* the three protocol
    /// columns but *without* the v7 identity columns; messages *without* `raw_len`; plus
    /// security_events/tool_fingerprints/inject_events) with a session, `user_version`
    /// stamped 6.
    fn write_legacy_v6_db(db: &Path) {
        let conn = Connection::open(db).unwrap();
        conn.execute_batch(
            "BEGIN;
            CREATE TABLE sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                label TEXT NOT NULL,
                command TEXT NOT NULL,
                started_at_ms INTEGER NOT NULL,
                ended_at_ms INTEGER,
                protocol_version TEXT,
                client_protocol_version TEXT,
                protocol_version_source TEXT CHECK (protocol_version_source IN ('initialize','header'))
            );
            CREATE TABLE messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL REFERENCES sessions(id),
                ts_ms INTEGER NOT NULL,
                direction TEXT NOT NULL CHECK (direction IN ('c2s','s2c')),
                raw TEXT NOT NULL,
                method TEXT,
                rpc_id TEXT,
                is_valid_json INTEGER NOT NULL,
                is_error INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL REFERENCES sessions(id),
                ts_ms INTEGER NOT NULL,
                kind TEXT NOT NULL CHECK (kind IN ('policy_deny','secret_leak','fingerprint_change')),
                rule TEXT NOT NULL,
                detail TEXT NOT NULL,
                tool_name TEXT,
                rpc_id TEXT,
                action_taken TEXT NOT NULL CHECK (action_taken IN ('flagged','blocked'))
            );
            CREATE TABLE tool_fingerprints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL REFERENCES sessions(id),
                tool_name TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                first_seen_ts_ms INTEGER NOT NULL,
                server_key TEXT NOT NULL DEFAULT '',
                fp_version INTEGER NOT NULL DEFAULT 1,
                last_seen_ts_ms INTEGER,
                UNIQUE (server_key, tool_name, fingerprint)
            );
            CREATE TABLE inject_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL REFERENCES sessions(id),
                ts_ms INTEGER NOT NULL,
                direction TEXT NOT NULL CHECK (direction IN ('c2s','s2c')),
                rule TEXT NOT NULL,
                fault TEXT NOT NULL CHECK (fault IN ('delay','error','drop','truncate')),
                detail TEXT NOT NULL,
                method TEXT,
                rpc_id TEXT
            );
            PRAGMA user_version = 6;
            COMMIT;",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO sessions (label, command, started_at_ms) VALUES ('old', 'npx some-server', 42)",
            [],
        )
        .unwrap();
    }

    #[test]
    fn v6_to_v7_additive_upgrade_adds_identity_columns() {
        let tmp = TempDir::new("v6-upgrade");
        let db = tmp.db();
        write_legacy_v6_db(&db);

        // Opening a v6 file upgrades it in place to v7 (four sessions identity columns +
        // messages.raw_len), leaving the pre-existing row's identity fields NULL.
        let store = Store::open(&db).unwrap();
        let version: i64 = store
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, 7);

        let row = store.session(1).unwrap().expect("session");
        assert_eq!(row.command, "npx some-server");
        assert_eq!(row.program, None);
        assert_eq!(row.argv_json, None);
        assert_eq!(row.transport, None);
        assert_eq!(row.server_id, None);

        // The new messages.raw_len column exists and is usable.
        let has_raw_len: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('messages') WHERE name = 'raw_len'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(has_raw_len, 1);

        // Re-opening the upgraded file is a no-op (ALTERs not re-run) and still v7.
        let store2 = Store::open(&db).unwrap();
        let version2: i64 = store2
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version2, 7);
    }

    #[test]
    fn record_fingerprint_lazy_rekeys_legacy_scope_without_alert() {
        // The rug-pull baseline must survive the v7 identity upgrade: a fingerprint
        // recorded pre-v7 under the joined-command `server_key` must be found and
        // re-keyed to the structured `server_id` on first sighting — Unchanged, no
        // reset, and no residual rows under the legacy key. This is the sole guard
        // against the lazy re-key silently zeroing the baseline.
        let tmp = TempDir::new("fp-lazy-rekey");
        let db = tmp.db();
        write_legacy_v6_db(&db);
        // Seed a pre-v7 baseline for `search` under the legacy (joined-command) key.
        {
            let conn = Connection::open(&db).unwrap();
            conn.execute(
                "INSERT INTO tool_fingerprints
                    (session_id, server_key, tool_name, fingerprint, first_seen_ts_ms, last_seen_ts_ms, fp_version)
                 VALUES (1, 'npx some-server', 'search', 'v3base', 100, 100, 3)",
                [],
            )
            .unwrap();
        }
        let store = Store::open(&db).unwrap(); // upgrades to v7

        let server_id = "structured-server-id"; // stands in for server_identity_hash(...)
        let legacy_key = "npx some-server";
        // First sighting under the structured id, same definition -> Unchanged (re-key).
        assert_eq!(
            store
                .record_fingerprint(1, server_id, legacy_key, "search", "v1x", "v2x", "v3base", 200)
                .unwrap(),
            FingerprintOutcome::Unchanged
        );

        // The whole baseline moved to server_id: none left under the legacy key.
        let legacy_rows: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM tool_fingerprints WHERE server_key = 'npx some-server'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(legacy_rows, 0, "legacy-scoped rows must be re-keyed, not left behind");
        let new_rows: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM tool_fingerprints WHERE server_key = ?1",
                params![server_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(new_rows, 1, "the baseline is now scoped to the structured server_id");

        // A genuine post-upgrade change is still caught under the structured id.
        assert_eq!(
            store
                .record_fingerprint(1, server_id, legacy_key, "search", "v1y", "v2y", "v3changed", 300)
                .unwrap(),
            FingerprintOutcome::Changed
        );
    }

    #[test]
    fn begin_session_with_identity_round_trips_and_argv_json_is_lossless() {
        let tmp = TempDir::new("session-identity");
        let store = Store::open(&tmp.db()).unwrap();

        // A JSON argv array whose tokens carry whitespace, an (escaped) double quote,
        // and a backslash — exactly the cases the pre-v7 `argv.join(" ")` +
        // `split_command` round-trip could not preserve. The storage layer must persist
        // and return it byte-for-byte (the serde round-trip itself is proven losslessly
        // in `replay.rs`, whose crate has serde_json). The `program` is `argv[0]`.
        let program = r"C:\Program Files\srv\mcp.exe";
        let argv_json = r#"["C:\\Program Files\\srv\\mcp.exe","--flag","a \"b\" c\\d"]"#;
        let sid = store
            .begin_session_with_identity(
                "srv",
                "display command",
                Some(program),
                Some(argv_json),
                "stdio",
                "server-id-hash",
            )
            .unwrap();

        let row = store.session(sid).unwrap().expect("session");
        assert_eq!(row.command, "display command");
        assert_eq!(row.program.as_deref(), Some(program));
        assert_eq!(row.transport.as_deref(), Some("stdio"));
        assert_eq!(row.server_id.as_deref(), Some("server-id-hash"));
        // The argv_json column is returned verbatim, including the backslashes and the
        // escaped quote that a joined-string representation would have mangled.
        assert_eq!(row.argv_json.as_deref(), Some(argv_json));

        // An HTTP identity leaves program/argv_json NULL.
        let hid = store
            .begin_session_with_identity(
                "up",
                "http://127.0.0.1:9000/u/x",
                None,
                None,
                "http",
                "http-id-hash",
            )
            .unwrap();
        let hrow = store.session(hid).unwrap().expect("session");
        assert_eq!(hrow.program, None);
        assert_eq!(hrow.argv_json, None);
        assert_eq!(hrow.transport.as_deref(), Some("http"));
    }

    #[test]
    fn record_fingerprint_v2_to_v3_repin_is_not_a_false_positive() {
        // A pre-existing v2 fingerprint row (e.g. a tool with no outputSchema, whose
        // v2 and v3 hashes differ only by the added Null outputSchema key) must be
        // recognised on its v2 hash and silently re-pinned to v3 — Unchanged, no alert.
        let tmp = TempDir::new("fp-v2-to-v3");
        let db = tmp.db();
        write_legacy_v5_db(&db);
        let store = Store::open(&db).unwrap();

        assert_eq!(
            store
                .record_fingerprint(1, "srv", "srv", "search", "v1x", "v2only", "v3new", 200)
                .unwrap(),
            FingerprintOutcome::Unchanged
        );
        let (fp_version, fingerprint): (i64, String) = store
            .conn
            .query_row(
                "SELECT fp_version, fingerprint FROM tool_fingerprints WHERE tool_name = 'search'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(fp_version, 3, "the v2 row should be re-pinned to v3");
        assert_eq!(fingerprint, "v3new");

        // Now that the baseline is the v3 hash, an outputSchema-only change (same v1/v2,
        // different v3) IS caught.
        assert_eq!(
            store
                .record_fingerprint(1, "srv", "srv", "search", "v1x", "v2only", "v3changed", 300)
                .unwrap(),
            FingerprintOutcome::Changed
        );
    }

    #[test]
    fn set_session_protocol_round_trips_through_session_summary() {
        let tmp = TempDir::new("session-protocol");
        let store = Store::open(&tmp.db()).unwrap();
        let sid = store.begin_session("s", "echo").unwrap();

        // A fresh session has no recorded protocol version.
        let before = store.session(sid).unwrap().expect("session");
        assert_eq!(before.protocol_version, None);
        assert_eq!(before.client_protocol_version, None);
        assert_eq!(before.protocol_version_source, None);

        store
            .set_session_protocol(sid, Some("2025-06-18"), Some("2025-11-25"), "initialize")
            .unwrap();
        let after = store.session(sid).unwrap().expect("session");
        assert_eq!(after.client_protocol_version.as_deref(), Some("2025-06-18"));
        assert_eq!(after.protocol_version.as_deref(), Some("2025-11-25"));
        assert_eq!(after.protocol_version_source.as_deref(), Some("initialize"));

        // The header source path: no client-proposed version, just the negotiated one.
        store
            .set_session_protocol(sid, None, Some("2025-11-25"), "header")
            .unwrap();
        let hdr = store.session(sid).unwrap().expect("session");
        assert_eq!(hdr.client_protocol_version, None);
        assert_eq!(hdr.protocol_version.as_deref(), Some("2025-11-25"));
        assert_eq!(hdr.protocol_version_source.as_deref(), Some("header"));

        // list_sessions surfaces the same fields.
        let listed = store.list_sessions().unwrap();
        assert_eq!(listed[0].protocol_version.as_deref(), Some("2025-11-25"));
    }

    #[test]
    fn session_returns_row_or_none() {
        let tmp = TempDir::new("session-lookup");
        let store = Store::open(&tmp.db()).unwrap();
        let sid = store.begin_session("s", "echo").unwrap();
        store
            .insert(sid, &rec(Direction::C2s, 1, r#"{"id":1,"method":"ping"}"#))
            .unwrap();

        let found = store.session(sid).unwrap().expect("session");
        assert_eq!(found.id, sid);
        assert_eq!(found.label, "s");
        assert_eq!(found.message_count, 1);

        assert!(store.session(999_999).unwrap().is_none());
    }

    #[test]
    fn latest_tools_list_raw_pairs_the_most_recent_request() {
        let tmp = TempDir::new("tools-list-latest");
        let store = Store::open(&tmp.db()).unwrap();
        let sid = store.begin_session("s", "echo").unwrap();

        // First tools/list round-trip (id "1").
        store
            .insert(sid, &rec(Direction::C2s, 100, r#"{"id":1,"method":"tools/list"}"#))
            .unwrap();
        store
            .insert(
                sid,
                &rec(Direction::S2c, 110, r#"{"id":1,"result":{"tools":["old"]}}"#),
            )
            .unwrap();
        // Second, later tools/list round-trip (id "2") -> this is the "latest".
        store
            .insert(sid, &rec(Direction::C2s, 200, r#"{"id":2,"method":"tools/list"}"#))
            .unwrap();
        let latest_resp = r#"{"id":2,"result":{"tools":["new"]}}"#;
        store
            .insert(sid, &rec(Direction::S2c, 210, latest_resp))
            .unwrap();

        let raw = store.latest_tools_list_raw(sid).unwrap();
        assert_eq!(raw.as_deref(), Some(latest_resp));
    }

    #[test]
    fn latest_tools_list_raw_skips_error_response() {
        let tmp = TempDir::new("tools-list-error");
        let store = Store::open(&tmp.db()).unwrap();
        let sid = store.begin_session("s", "echo").unwrap();

        store
            .insert(sid, &rec(Direction::C2s, 100, r#"{"id":1,"method":"tools/list"}"#))
            .unwrap();
        // An error response must not be treated as the matching result.
        store
            .insert(
                sid,
                &rec(Direction::S2c, 110, r#"{"id":1,"error":{"code":-1,"message":"no"}}"#),
            )
            .unwrap();

        assert!(store.latest_tools_list_raw(sid).unwrap().is_none());
    }

    #[test]
    fn latest_tools_list_raw_none_without_request_or_response() {
        let tmp = TempDir::new("tools-list-none");
        let store = Store::open(&tmp.db()).unwrap();
        let sid = store.begin_session("s", "echo").unwrap();

        // No tools/list request at all.
        assert!(store.latest_tools_list_raw(sid).unwrap().is_none());

        // A request with no matching response yet.
        store
            .insert(sid, &rec(Direction::C2s, 100, r#"{"id":1,"method":"tools/list"}"#))
            .unwrap();
        assert!(store.latest_tools_list_raw(sid).unwrap().is_none());
    }

    #[test]
    fn inject_events_insert_and_query_round_trip() {
        let tmp = TempDir::new("inject-events");
        let store = Store::open(&tmp.db()).unwrap();
        let sid = store.begin_session("s", "echo").unwrap();

        for i in 0..3 {
            store
                .insert_inject_event(
                    sid,
                    &InjectEvent {
                        ts_ms: i,
                        direction: Direction::S2c,
                        rule: format!("rule{i}"),
                        fault: InjectFault::Error,
                        detail: "synthetic error".to_owned(),
                        method: Some("tools/call".to_owned()),
                        rpc_id: Some(i.to_string()),
                    },
                )
                .unwrap();
        }

        let (total, rows) = store.inject_events(sid, 2, 1).unwrap();
        assert_eq!(total, 3);
        assert_eq!(rows.len(), 2);
        assert!(rows[0].id < rows[1].id);
        // offset 1 -> the second-oldest event.
        assert_eq!(rows[0].rule, "rule1");
        assert_eq!(rows[0].session_id, sid);
        assert_eq!(rows[0].direction, Direction::S2c);
        assert_eq!(rows[0].fault, InjectFault::Error);
        assert_eq!(rows[0].detail, "synthetic error");
        assert_eq!(rows[0].method.as_deref(), Some("tools/call"));
        assert_eq!(rows[0].rpc_id.as_deref(), Some("1"));

        let (total_missing, rows_missing) = store.inject_events(999_999, 50, 0).unwrap();
        assert_eq!(total_missing, 0);
        assert!(rows_missing.is_empty());
    }

    #[test]
    fn inject_events_empty_session_returns_zero() {
        let tmp = TempDir::new("injev-empty");
        let store = Store::open(&tmp.db()).unwrap();
        let sid = store.begin_session("s", "echo").unwrap();
        let (total, rows) = store.inject_events(sid, 50, 0).unwrap();
        assert_eq!(total, 0);
        assert!(rows.is_empty());
        let counts = store.inject_event_counts(sid).unwrap();
        assert_eq!(counts.delay, 0);
        assert_eq!(counts.error, 0);
        assert_eq!(counts.drop, 0);
        assert_eq!(counts.truncate, 0);
    }

    #[test]
    fn inject_event_counts_by_fault() {
        let tmp = TempDir::new("injcount");
        let store = Store::open(&tmp.db()).unwrap();
        let sid = store.begin_session("s", "echo").unwrap();
        for fault in [
            InjectFault::Delay,
            InjectFault::Delay,
            InjectFault::Error,
            InjectFault::Drop,
            InjectFault::Truncate,
        ] {
            store
                .insert_inject_event(
                    sid,
                    &InjectEvent {
                        ts_ms: 0,
                        direction: Direction::C2s,
                        rule: "r".to_owned(),
                        fault,
                        detail: "d".to_owned(),
                        method: None,
                        rpc_id: None,
                    },
                )
                .unwrap();
        }

        let c = store.inject_event_counts(sid).unwrap();
        assert_eq!(c.delay, 2);
        assert_eq!(c.error, 1);
        assert_eq!(c.drop, 1);
        assert_eq!(c.truncate, 1);
    }

    // -- data lifecycle (WF4) -----------------------------------------------

    /// Seed a session with `n` c2s messages, one security event, one inject event, and
    /// one tool fingerprint, then force its `started_at_ms` to `started`. Returns the id.
    fn seed_full_session(store: &Store, db: &Path, label: &str, started: i64, n: i64) -> i64 {
        let sid = store.begin_session(label, "echo srv").unwrap();
        for i in 0..n {
            store
                .insert(sid, &rec(Direction::C2s, i, &format!(r#"{{"id":{i},"method":"ping"}}"#)))
                .unwrap();
        }
        store
            .insert_security_event(
                sid,
                &SecurityEvent {
                    ts_ms: 0,
                    kind: SecurityEventKind::PolicyDeny,
                    rule: "r".to_owned(),
                    detail: "d".to_owned(),
                    tool_name: None,
                    rpc_id: None,
                    action_taken: ActionTaken::Flagged,
                },
            )
            .unwrap();
        store
            .insert_inject_event(
                sid,
                &InjectEvent {
                    ts_ms: 0,
                    direction: Direction::C2s,
                    rule: "r".to_owned(),
                    fault: InjectFault::Drop,
                    detail: "d".to_owned(),
                    method: None,
                    rpc_id: None,
                },
            )
            .unwrap();
        // A fingerprint scoped to this session — must survive pruning the session.
        rf(store, sid, "srv", &format!("tool-{label}"), "fp", 1);
        // Force a deterministic start time (begin_session stamps `now`).
        let conn = rusqlite::Connection::open(db).unwrap();
        conn.execute("UPDATE sessions SET started_at_ms = ?2 WHERE id = ?1", params![sid, started])
            .unwrap();
        sid
    }

    fn table_count(db: &Path, sql: &str) -> i64 {
        let conn = rusqlite::Connection::open(db).unwrap();
        conn.query_row(sql, [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn delete_session_removes_rows_but_keeps_fingerprints() {
        let tmp = TempDir::new("delete-session");
        let db = tmp.db();
        let store = Store::open(&db).unwrap();
        let sid = seed_full_session(&store, &db, "s", 100, 5);

        // Unknown id -> None (so the dashboard can 404).
        assert!(store.delete_session(9999).unwrap().is_none());

        let stats = store.delete_session(sid).unwrap().expect("session existed");
        assert_eq!(stats.sessions, 1);
        assert_eq!(stats.messages, 5);
        assert_eq!(stats.security_events, 1);
        assert_eq!(stats.inject_events, 1);

        assert_eq!(table_count(&db, "SELECT COUNT(*) FROM sessions"), 0);
        assert_eq!(table_count(&db, "SELECT COUNT(*) FROM messages"), 0);
        assert_eq!(table_count(&db, "SELECT COUNT(*) FROM security_events"), 0);
        assert_eq!(table_count(&db, "SELECT COUNT(*) FROM inject_events"), 0);
        // The fingerprint baseline outlives the session it was recorded in.
        assert_eq!(
            table_count(&db, "SELECT COUNT(*) FROM tool_fingerprints"),
            1,
            "tool fingerprints must never be pruned"
        );
    }

    #[test]
    fn prune_sessions_before_deletes_old_keeps_new_and_preview_matches() {
        let tmp = TempDir::new("prune-before");
        let db = tmp.db();
        let store = Store::open(&db).unwrap();
        let old = seed_full_session(&store, &db, "old", 100, 3);
        let new = seed_full_session(&store, &db, "new", 1000, 4);

        // Dry-run preview counts the old session (started_at_ms < 500) without deleting.
        let preview = store.preview_sessions_before(500).unwrap();
        assert_eq!(preview.sessions, 1);
        assert_eq!(preview.messages, 3);
        assert_eq!(table_count(&db, "SELECT COUNT(*) FROM sessions"), 2, "preview must not delete");

        let stats = store.prune_sessions_before(500).unwrap();
        assert_eq!(stats.sessions, 1);
        assert_eq!(stats.messages, 3);
        assert_eq!(stats.security_events, 1);
        assert_eq!(stats.inject_events, 1);

        // The new session and its rows remain; the old one is gone.
        assert!(store.session(new).unwrap().is_some());
        assert!(store.session(old).unwrap().is_none());
        assert_eq!(table_count(&db, "SELECT COUNT(*) FROM messages"), 4);
        // Both sessions' fingerprints survive.
        assert_eq!(table_count(&db, "SELECT COUNT(*) FROM tool_fingerprints"), 2);
    }

    #[test]
    fn size_helpers_and_vacuum() {
        let tmp = TempDir::new("size-helpers");
        let db = tmp.db();
        let store = Store::open(&db).unwrap();
        seed_full_session(&store, &db, "a", 100, 50);
        seed_full_session(&store, &db, "b", 200, 50);

        let size = store.db_size_bytes().unwrap();
        assert!(size > 0);
        // Used (freelist-adjusted) never exceeds the physical file size.
        assert!(store.db_used_bytes().unwrap() <= size);

        // Oldest is the earliest started_at_ms.
        let oldest = store.oldest_session().unwrap().unwrap();
        let sizes = store.session_size_estimates().unwrap();
        assert_eq!(sizes.len(), 2);
        assert_eq!(sizes[0].id, oldest, "estimates come oldest-first");
        assert!(sizes[0].est_bytes > 0);
        assert!(sizes[0].started_at_ms <= sizes[1].started_at_ms);

        // Deleting then vacuuming must not shrink below live data, and must not error.
        store.delete_session(oldest).unwrap();
        store.vacuum().unwrap();
        assert!(store.db_size_bytes().unwrap() > 0);
    }

    /// Seed one session whose messages carry a large padded body, so the session's
    /// footprint dwarfs the fixed schema/index/fingerprint overhead and `db_used_bytes`
    /// moves measurably (by many pages) as it is deleted — a precondition for testing a
    /// fractional `--max-size` target without page-granularity flakiness.
    fn seed_big_session(store: &Store, db: &Path, label: &str, started: i64) -> i64 {
        let sid = store.begin_session(label, "echo srv").unwrap();
        let pad = "x".repeat(4000);
        for i in 0..60 {
            store
                .insert(sid, &rec(Direction::C2s, i, &format!(r#"{{"id":{i},"pad":"{pad}"}}"#)))
                .unwrap();
        }
        rf(store, sid, "srv", &format!("tool-{label}"), "fp", 1);
        let conn = rusqlite::Connection::open(db).unwrap();
        conn.execute("UPDATE sessions SET started_at_ms = ?2 WHERE id = ?1", params![sid, started])
            .unwrap();
        sid
    }

    #[test]
    fn prune_to_max_size_deletes_oldest_first_and_keeps_fingerprints() {
        let tmp = TempDir::new("prune-max-size");
        let db = tmp.db();
        let store = Store::open(&db).unwrap();
        // Three large, roughly-equal sessions (~240 KB of body each) so the content
        // dominates fixed overhead and a fractional target is reachable page-wise.
        let oldest = seed_big_session(&store, &db, "oldest", 100);
        let middle = seed_big_session(&store, &db, "middle", 200);
        let newest = seed_big_session(&store, &db, "newest", 300);

        let full = store.db_used_bytes().unwrap();
        assert!(full > 0);

        // Target at 55% of full: reachable by dropping the two oldest (leaving ~1/3 of
        // the content plus overhead, comfortably under 55%). A dry-run preview counts
        // sessions to drop without touching the db.
        let target = full * 55 / 100;
        let preview = store.preview_max_size(target).unwrap();
        assert!(preview.sessions >= 1, "preview should plan to drop the oldest session(s)");
        assert_eq!(
            table_count(&db, "SELECT COUNT(*) FROM sessions"),
            3,
            "preview must not delete anything"
        );

        // The real run drops oldest-first until live data is at or under the target.
        let stats = store.prune_to_max_size(target).unwrap();
        assert!(stats.sessions >= 1);
        assert!(
            store.db_used_bytes().unwrap() <= target,
            "live data must be at or under the target after pruning"
        );

        // Oldest went first; the newest is always among the survivors here.
        assert!(store.session(oldest).unwrap().is_none(), "oldest must be deleted first");
        assert!(store.session(newest).unwrap().is_some(), "newest must survive");
        let _ = middle; // middle's fate depends on page granularity; not asserted.

        // Every fingerprint baseline survives, even for the deleted oldest session.
        assert_eq!(
            table_count(&db, "SELECT COUNT(*) FROM tool_fingerprints"),
            3,
            "tool fingerprints must never be pruned"
        );
    }

    #[test]
    fn prune_to_max_size_target_above_live_deletes_nothing() {
        let tmp = TempDir::new("prune-max-size-noop");
        let db = tmp.db();
        let store = Store::open(&db).unwrap();
        seed_full_session(&store, &db, "keep", 100, 10);
        let live = store.db_used_bytes().unwrap();

        // A target at or above current live data removes nothing.
        let stats = store.prune_to_max_size(live + 1).unwrap();
        assert_eq!(stats.sessions, 0);
        assert_eq!(table_count(&db, "SELECT COUNT(*) FROM sessions"), 1);
    }

    #[test]
    fn metadata_only_insert_records_raw_len_and_size() {
        let tmp = TempDir::new("metadata-only");
        let db = tmp.db();
        let store = Store::open(&db).unwrap();
        let sid = store.begin_session("meta", "echo").unwrap();

        // A full recording keeps its body; raw_len is NULL and size = body length.
        let body = r#"{"id":1,"method":"ping"}"#;
        store.insert(sid, &rec(Direction::C2s, 1, body)).unwrap();

        // A metadata-only recording: empty body, raw_len = original byte length.
        let meta = Record {
            ts_ms: 2,
            direction: Direction::S2c,
            raw: String::new(),
            method: None,
            rpc_id: Some("1".to_owned()),
            is_valid_json: true,
            is_error: false,
        };
        store.insert_with_raw_len(sid, &meta, Some(body.len() as i64)).unwrap();

        // The list surfaces raw_len as the size for the metadata-only row.
        let (_, rows) = store
            .messages(sid, &MessageFilter { limit: 100, ..Default::default() })
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].size as usize, body.len(), "full row size = body length");
        assert_eq!(rows[1].size as usize, body.len(), "metadata-only row size = raw_len");

        // The detail distinguishes the two: full row has raw_len None + a body; the
        // metadata-only row has an empty body and raw_len set.
        let full = store.message(rows[0].id).unwrap().unwrap();
        assert_eq!(full.raw_len, None);
        assert!(!full.raw.is_empty());
        let m = store.message(rows[1].id).unwrap().unwrap();
        assert_eq!(m.raw_len, Some(body.len() as i64));
        assert!(m.raw.is_empty());
        assert_eq!(m.size as usize, body.len());
    }
}
