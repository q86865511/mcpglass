//! SQLite sink for tapped MCP messages.
//!
//! This lives entirely on the tap path. Every fallible operation returns a
//! `Result` so the caller can log-and-continue: a storage failure must never
//! propagate into the forwarding path (fail-open).

use std::path::Path;

use anyhow::{Context, Result};
use proxy_core::Direction;
use rusqlite::Connection;

/// One captured JSON-RPC frame, ready to persist.
pub struct Record {
    pub ts_ms: i64,
    pub direction: Direction,
    /// The raw framed line, verbatim (lossy-UTF-8 if the source was not UTF-8).
    pub raw: String,
    pub method: Option<String>,
    pub rpc_id: Option<String>,
    pub is_valid_json: bool,
}

/// Owns a single write connection. Intended to run on one dedicated thread that
/// drains the tap channel; rusqlite `Connection` is not `Sync`.
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open (creating parent dirs and schema as needed) in WAL mode.
    pub fn open(db_path: &Path) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating db dir {}", parent.display()))?;
            }
        }
        let conn = Connection::open(db_path)
            .with_context(|| format!("opening db {}", db_path.display()))?;
        // WAL lets a separate reader (e.g. a future dashboard) observe the live
        // session without blocking the writer.
        conn.pragma_update(None, "journal_mode", "WAL")
            .context("enabling WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .context("setting synchronous")?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<()> {
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS messages (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts_ms         INTEGER NOT NULL,
                    direction     TEXT    NOT NULL CHECK (direction IN ('c2s','s2c')),
                    raw           TEXT    NOT NULL,
                    method        TEXT,
                    rpc_id        TEXT,
                    is_valid_json INTEGER NOT NULL
                );",
            )
            .context("creating messages table")?;
        Ok(())
    }

    /// Persist one record. Errors are returned, not panicked, so the tap loop
    /// can drop-and-continue.
    pub fn insert(&self, rec: &Record) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO messages (ts_ms, direction, raw, method, rpc_id, is_valid_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    rec.ts_ms,
                    rec.direction.as_str(),
                    rec.raw,
                    rec.method,
                    rec.rpc_id,
                    rec.is_valid_json as i64,
                ],
            )
            .context("inserting message")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_and_insert_roundtrip() {
        let dir = std::env::temp_dir().join(format!("mcpglass-test-{}", std::process::id()));
        let db = dir.join("sessions.db");
        let store = Store::open(&db).unwrap();
        store
            .insert(&Record {
                ts_ms: 123,
                direction: Direction::C2s,
                raw: r#"{"method":"ping"}"#.to_owned(),
                method: Some("ping".to_owned()),
                rpc_id: Some("1".to_owned()),
                is_valid_json: true,
            })
            .unwrap();
        let (dir_s, method): (String, Option<String>) = store
            .conn
            .query_row(
                "SELECT direction, method FROM messages WHERE ts_ms = 123",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(dir_s, "c2s");
        assert_eq!(method.as_deref(), Some("ping"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
