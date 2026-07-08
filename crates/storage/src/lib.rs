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
const SCHEMA_VERSION: i64 = 4;

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

        // BEGIN/COMMIT makes table creation and the `user_version = 4` stamp one
        // atomic unit, so a concurrent reader's legacy-v0 probe (see
        // `is_legacy_v0`) can never observe the `messages` table mid-creation
        // with `user_version` still at 0 and misclassify a fresh db as v0.
        //
        // `CREATE TABLE IF NOT EXISTS` makes the v1 -> v2/v3/v4 upgrade additive: on an
        // existing file the sessions/messages tables are left untouched, any missing
        // tables are appended, and `user_version` is bumped to 4.
        self.conn
            .execute_batch(
                "BEGIN;
                CREATE TABLE IF NOT EXISTS sessions (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    label         TEXT    NOT NULL,
                    command       TEXT    NOT NULL,
                    started_at_ms INTEGER NOT NULL,
                    ended_at_ms   INTEGER
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
                    is_error      INTEGER NOT NULL DEFAULT 0
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
                PRAGMA user_version = 4;
                COMMIT;",
            )
            .context("creating v4 schema")?;
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

    /// Open a new session; returns its id. Call once per `wrap` invocation.
    pub fn begin_session(&self, label: &str, command: &str) -> Result<i64> {
        self.conn
            .execute(
                "INSERT INTO sessions (label, command, started_at_ms) VALUES (?1, ?2, ?3)",
                params![label, command, now_ms()],
            )
            .context("beginning session")?;
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

    /// Persist one record under `session_id`. Errors are returned, not panicked,
    /// so the tap loop can drop-and-continue.
    pub fn insert(&self, session_id: i64, rec: &Record) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO messages
                    (session_id, ts_ms, direction, raw, method, rpc_id, is_valid_json, is_error)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    session_id,
                    rec.ts_ms,
                    rec.direction.as_str(),
                    rec.raw,
                    rec.method,
                    rec.rpc_id,
                    rec.is_valid_json as i64,
                    rec.is_error as i64,
                ],
            )
            .context("inserting message")?;
        Ok(())
    }

    /// All sessions, newest first, each with a live message count.
    pub fn list_sessions(&self) -> Result<Vec<SessionSummary>> {
        let mut stmt = self.conn.prepare(
            "SELECT s.id, s.label, s.command, s.started_at_ms, s.ended_at_ms,
                    (SELECT COUNT(*) FROM messages m WHERE m.session_id = s.id)
             FROM sessions s
             ORDER BY s.id DESC",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(SessionSummary {
                    id: r.get(0)?,
                    label: r.get(1)?,
                    command: r.get(2)?,
                    started_at_ms: r.get(3)?,
                    ended_at_ms: r.get(4)?,
                    message_count: r.get::<_, i64>(5)? as u64,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
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
                    length(CAST(raw AS BLOB)), substr(raw, 1, 200)
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
                        is_valid_json, is_error, length(CAST(raw AS BLOB)),
                        substr(raw, 1, 200), raw
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

    /// Record an observed tool definition — hashed under both algorithm versions
    /// (`fp_v1`, `fp_v2`) — under `server_key` and classify it against history:
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
    /// **Dual-hash migration.** A stored row hashed under v1 is compared on `fp_v1`;
    /// a v2 row on `fp_v2`. When a v1 row still matches on v1, it is silently
    /// re-pinned to v2 (its `fingerprint`/`fp_version` are rewritten to the v2 hash)
    /// and reported `Unchanged` — no false-positive alert for the algorithm bump.
    /// A v1 *mismatch* is a genuine change and alerts as usual.
    ///
    /// The comparison scope is `(server_key, tool_name)` and deliberately spans
    /// sessions: the canonical rug-pull is a server approved on one `wrap` that then
    /// mutates a tool on a *later* one. `session_id` is stored for traceability.
    ///
    /// Append-only for distinct fingerprints: `Changed` inserts a new row and keeps
    /// the prior one(s); `Unchanged`/`Reverted` only refresh an existing row's
    /// `last_seen_ts_ms` (and re-pin a v1 row), so a tool's fingerprint history is
    /// preserved.
    pub fn record_fingerprint(
        &self,
        session_id: i64,
        server_key: &str,
        tool_name: &str,
        fp_v1: &str,
        fp_v2: &str,
        ts_ms: i64,
    ) -> Result<FingerprintOutcome> {
        // Load history for this (server, tool), most recent observation first. A
        // NULL last_seen (legacy pre-v4 row) falls back to first_seen for ordering.
        let mut stmt = self.conn.prepare(
            "SELECT id, fingerprint, fp_version
             FROM tool_fingerprints
             WHERE server_key = ?1 AND tool_name = ?2
             ORDER BY COALESCE(last_seen_ts_ms, first_seen_ts_ms) DESC, id DESC",
        )?;
        let rows: Vec<(i64, String, i64)> = stmt
            .query_map(params![server_key, tool_name], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        // First sighting: pin the v2 baseline and stay silent.
        if rows.is_empty() {
            self.insert_fingerprint(session_id, server_key, tool_name, fp_v2, ts_ms)?;
            return Ok(FingerprintOutcome::New);
        }

        // Does the observation match a stored row? A v1 row is compared on the v1
        // hash (dual-hash transition), a v2 row on the v2 hash.
        let matches = |fingerprint: &str, fp_version: i64| -> bool {
            if fp_version <= 1 {
                fingerprint == fp_v1
            } else {
                fingerprint == fp_v2
            }
        };

        // Matches the current (most-recent) definition -> Unchanged.
        let (latest_id, latest_fp, latest_ver) = &rows[0];
        if matches(latest_fp, *latest_ver) {
            self.touch_fingerprint(*latest_id, *latest_ver, fp_v2, ts_ms)?;
            return Ok(FingerprintOutcome::Unchanged);
        }

        // Matches an older definition -> the tool oscillated back (Reverted).
        if let Some((id, _, ver)) = rows.iter().find(|(_, fp, ver)| matches(fp, *ver)) {
            self.touch_fingerprint(*id, *ver, fp_v2, ts_ms)?;
            return Ok(FingerprintOutcome::Reverted);
        }

        // A definition never seen before for this (server, tool) -> Changed.
        self.insert_fingerprint(session_id, server_key, tool_name, fp_v2, ts_ms)?;
        Ok(FingerprintOutcome::Changed)
    }

    /// Insert a fresh v2 fingerprint row (first_seen == last_seen == `ts_ms`).
    fn insert_fingerprint(
        &self,
        session_id: i64,
        server_key: &str,
        tool_name: &str,
        fp_v2: &str,
        ts_ms: i64,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO tool_fingerprints
                    (session_id, server_key, tool_name, fingerprint,
                     first_seen_ts_ms, last_seen_ts_ms, fp_version)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5, 2)",
                params![session_id, server_key, tool_name, fp_v2, ts_ms],
            )
            .context("recording tool fingerprint")?;
        Ok(())
    }

    /// Refresh a matched row's `last_seen_ts_ms`. A legacy v1 row is additionally
    /// re-pinned to v2 (its `fingerprint` becomes `fp_v2`, `fp_version` becomes 2),
    /// folding the current annotations into the baseline without an alert. A v2 row
    /// keeps its fingerprint (already `fp_v2`), avoiding any UNIQUE churn.
    fn touch_fingerprint(
        &self,
        id: i64,
        fp_version: i64,
        fp_v2: &str,
        ts_ms: i64,
    ) -> Result<()> {
        if fp_version <= 1 {
            self.conn.execute(
                "UPDATE tool_fingerprints
                    SET last_seen_ts_ms = ?2, fingerprint = ?3, fp_version = 2
                 WHERE id = ?1",
                params![id, ts_ms, fp_v2],
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

    /// Record a fingerprint on a fresh (all-v2) db: `fp` is the v2 hash and the v1
    /// hash is a distinct derived string. Since fresh-db rows are all v2, matching
    /// keys on the v2 value, so `fp` alone drives New/Unchanged/Changed/Reverted.
    fn rf(store: &Store, sid: i64, srv: &str, tool: &str, fp: &str, ts: i64) -> FingerprintOutcome {
        store
            .record_fingerprint(sid, srv, tool, &format!("{fp}-v1"), fp, ts)
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
    fn v1_to_v4_additive_upgrade_preserves_data() {
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
        assert_eq!(SCHEMA_VERSION, 4);

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
    fn v2_to_v4_additive_upgrade_preserves_data() {
        let tmp = TempDir::new("v2-upgrade");
        let db = tmp.db();
        write_legacy_v2_db(&db);

        // Opening a v2 file upgrades it in place to v4 via ALTER TABLE ADD COLUMN...
        let store = Store::open(&db).unwrap();
        let version: i64 = store
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, 4);

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

        // Re-opening the upgraded file is a no-op (ALTERs not re-run) and still v4.
        let store2 = Store::open(&db).unwrap();
        let version2: i64 = store2
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version2, 4);
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
    fn v3_to_v4_additive_upgrade_preserves_and_backfills_fingerprints() {
        let tmp = TempDir::new("v3-upgrade");
        let db = tmp.db();
        write_legacy_v3_db(&db, "legacy_v1");

        // Opening a v3 file upgrades it in place to v4 via ALTER TABLE ADD COLUMN...
        let store = Store::open(&db).unwrap();
        let version: i64 = store
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, 4);

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

        // Re-opening the upgraded file is a no-op (ALTERs not re-run) and still v4.
        let store2 = Store::open(&db).unwrap();
        let version2: i64 = store2
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version2, 4);
    }

    #[test]
    fn record_fingerprint_dual_hash_silently_repins_matching_v1_row() {
        // A legacy v1 row whose v1 hash still matches is re-pinned to v2 with no
        // alert (Unchanged) — the algorithm bump must not be a false positive.
        let tmp = TempDir::new("fp-dualhash-repin");
        let db = tmp.db();
        write_legacy_v3_db(&db, "v1hashA");
        let store = Store::open(&db).unwrap();

        // v1 matches the stored legacy hash -> Unchanged, and the row is re-pinned.
        assert_eq!(
            store.record_fingerprint(1, "srv", "search", "v1hashA", "v2hashA", 200).unwrap(),
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
        assert_eq!(fp_version, 2, "legacy v1 row should be re-pinned to v2");
        assert_eq!(fingerprint, "v2hashA");

        // Now that the baseline folds in annotations, a later annotations-only change
        // (same v1, different v2) IS detected as a change.
        assert_eq!(
            store.record_fingerprint(1, "srv", "search", "v1hashA", "v2hashB", 300).unwrap(),
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
            store.record_fingerprint(1, "srv", "search", "v1hashB", "v2hashB", 200).unwrap(),
            FingerprintOutcome::Changed
        );
    }
}
