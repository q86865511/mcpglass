//! `mcpglass prune`: delete recorded sessions to reclaim disk or drop stale data.
//!
//! A lifecycle-management command and therefore a writer by design (unlike the
//! read-only diagnostic tools `replay`/`bloat`/`export`): it opens the session store
//! read-write and deletes rows. It never touches the live wire, so the fail-open
//! contract does not apply here.
//!
//! Two independent conditions can be combined; at least one is required:
//! * `--older-than <dur>` deletes every session started longer ago than the duration.
//! * `--max-size <bytes>` deletes the oldest sessions until the database is at or under
//!   the target size, then vacuums to realise the freed space on disk.
//!
//! `--dry-run` reports what would be removed without touching the database.
//!
//! **Tool fingerprints are never pruned.** They are the cross-session rug-pull trust
//! baseline: a server approved on one run that mutates a tool on a later one is caught
//! only because the baseline outlives the session that recorded it. A pruned session's
//! `session_id` on a fingerprint row is left dangling (traceability only).

use std::path::PathBuf;

use storage::{PruneStats, Store};

use crate::tap::now_ms;

/// CLI entry point for `mcpglass prune`. Returns a process exit code: 0 on success,
/// 1 on a store/IO error, 2 on a usage error (no condition, or an unparsable value).
pub async fn run(
    db: Option<PathBuf>,
    older_than: Option<String>,
    max_size: Option<String>,
    dry_run: bool,
    vacuum: bool,
) -> i32 {
    if older_than.is_none() && max_size.is_none() {
        eprintln!(
            "mcpglass: prune needs at least one condition: --older-than <dur> and/or --max-size <bytes>"
        );
        return 2;
    }

    // Parse the human-friendly values up front so a typo fails before we open anything.
    let cutoff_ms = match older_than.as_deref().map(parse_duration_ms).transpose() {
        Ok(v) => v.map(|dur_ms| now_ms() - dur_ms),
        Err(e) => {
            eprintln!("mcpglass: invalid --older-than: {e}");
            return 2;
        }
    };
    let max_bytes = match max_size.as_deref().map(parse_size_bytes).transpose() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("mcpglass: invalid --max-size: {e}");
            return 2;
        }
    };

    let db_path = db
        .or_else(|| crate::default_data_dir().map(|d| d.join("sessions.db")))
        .unwrap_or_else(|| std::env::temp_dir().join("mcpglass").join("sessions.db"));

    let store = match Store::open(&db_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("mcpglass: opening session store {}: {e:#}", db_path.display());
            return 1;
        }
    };

    let size_before = store.db_size_bytes().unwrap_or(0);
    let mut total = PruneStats::default();

    // --older-than: delete (or, in a dry run, count) every session before the cutoff.
    if let Some(cutoff) = cutoff_ms {
        let stats = if dry_run {
            store.preview_sessions_before(cutoff)
        } else {
            store.prune_sessions_before(cutoff)
        };
        match stats {
            Ok(s) => {
                total += s;
                println!(
                    "{} {} session(s) started before the cutoff ({} message(s), {} security + {} inject event(s))",
                    if dry_run { "would delete" } else { "deleted" },
                    s.sessions,
                    s.messages,
                    s.security_events,
                    s.inject_events,
                );
            }
            Err(e) => {
                eprintln!("mcpglass: prune --older-than failed: {e:#}");
                return 1;
            }
        }
    }

    // --max-size: drop oldest sessions until live data is at or under the target.
    if let Some(target) = max_bytes {
        match apply_max_size(&store, target, dry_run) {
            Ok(s) => {
                total += s;
                println!(
                    "{} {} oldest session(s) to reach the {} target ({} message(s))",
                    if dry_run { "would delete" } else { "deleted" },
                    s.sessions,
                    human_bytes(target),
                    s.messages,
                );
            }
            Err(e) => {
                eprintln!("mcpglass: prune --max-size failed: {e:#}");
                return 1;
            }
        }
    }

    // Realise freed space on disk: --max-size always vacuums; --older-than only when
    // --vacuum is given (a delete alone leaves freed pages on the WAL freelist for
    // reuse, so the file doesn't shrink without a vacuum).
    if !dry_run && (max_bytes.is_some() || vacuum) {
        if let Err(e) = store.vacuum() {
            eprintln!("mcpglass: vacuum failed: {e:#}");
            return 1;
        }
    }

    let size_after = store.db_size_bytes().unwrap_or(size_before);
    if dry_run {
        println!(
            "dry run: nothing was changed. Would remove {} session(s) / {} message(s) total (db is {} now).",
            total.sessions,
            total.messages,
            human_bytes(size_before),
        );
    } else {
        println!(
            "done: removed {} session(s) / {} message(s) total. Database {} -> {}.",
            total.sessions,
            total.messages,
            human_bytes(size_before),
            human_bytes(size_after),
        );
    }
    0
}

/// Delete (or preview) the oldest sessions until live data is at or under `target`
/// bytes. The real run measures live bytes via [`Store::db_used_bytes`] and deletes
/// oldest-first until it drops to the target; the dry run walks
/// [`Store::session_size_estimates`] oldest-first, subtracting each session's estimated
/// bytes from the current live size, and counts the sessions it would remove (the
/// space figure is an estimate — labelled as such — since a real vacuum's exact
/// reclaim can't be known without deleting).
fn apply_max_size(store: &Store, target: u64, dry_run: bool) -> anyhow::Result<PruneStats> {
    if dry_run {
        let mut remaining = store.db_used_bytes()?;
        let mut acc = PruneStats::default();
        for s in store.session_size_estimates()? {
            if remaining <= target {
                break;
            }
            acc += store.preview_session(s.id)?;
            remaining = remaining.saturating_sub(s.est_bytes);
        }
        return Ok(acc);
    }

    let mut acc = PruneStats::default();
    loop {
        if store.db_used_bytes()? <= target {
            break;
        }
        let Some(oldest) = store.oldest_session()? else {
            break; // nothing left to delete
        };
        match store.delete_session(oldest)? {
            Some(s) => acc += s,
            None => break, // raced away; stop rather than spin
        }
    }
    Ok(acc)
}

/// Parse a duration like `7d`, `24h`, `30m`, `90s` into milliseconds. A bare number is
/// treated as seconds. Units are single-letter: `d`/`h`/`m`/`s`.
fn parse_duration_ms(s: &str) -> Result<i64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".to_owned());
    }
    let (num_str, unit_ms): (&str, i64) = match s.chars().last().unwrap() {
        'd' | 'D' => (&s[..s.len() - 1], 24 * 60 * 60 * 1000),
        'h' | 'H' => (&s[..s.len() - 1], 60 * 60 * 1000),
        'm' | 'M' => (&s[..s.len() - 1], 60 * 1000),
        's' | 'S' => (&s[..s.len() - 1], 1000),
        c if c.is_ascii_digit() => (s, 1000), // bare number = seconds
        c => return Err(format!("unknown duration unit {c:?} (use d/h/m/s)")),
    };
    let n: i64 = num_str
        .trim()
        .parse()
        .map_err(|_| format!("not a number: {num_str:?}"))?;
    if n < 0 {
        return Err("duration must not be negative".to_owned());
    }
    n.checked_mul(unit_ms).ok_or_else(|| "duration overflow".to_owned())
}

/// Parse a size like `500M`, `1G`, `250K`, or a bare byte count. Units are 1024-based
/// (`K`/`M`/`G`); a trailing `B` or no unit means bytes.
fn parse_size_bytes(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty size".to_owned());
    }
    let (num_str, mult): (&str, u64) = match s.chars().last().unwrap() {
        'k' | 'K' => (&s[..s.len() - 1], 1024),
        'm' | 'M' => (&s[..s.len() - 1], 1024 * 1024),
        'g' | 'G' => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        'b' | 'B' => (&s[..s.len() - 1], 1),
        c if c.is_ascii_digit() => (s, 1),
        c => return Err(format!("unknown size unit {c:?} (use K/M/G or a byte count)")),
    };
    let n: u64 = num_str
        .trim()
        .parse()
        .map_err(|_| format!("not a number: {num_str:?}"))?;
    n.checked_mul(mult).ok_or_else(|| "size overflow".to_owned())
}

/// Format a byte count as a short human-readable string (1024-based).
fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_units_and_bare_seconds() {
        assert_eq!(parse_duration_ms("7d").unwrap(), 7 * 24 * 60 * 60 * 1000);
        assert_eq!(parse_duration_ms("24h").unwrap(), 24 * 60 * 60 * 1000);
        assert_eq!(parse_duration_ms("30m").unwrap(), 30 * 60 * 1000);
        assert_eq!(parse_duration_ms("90s").unwrap(), 90 * 1000);
        assert_eq!(parse_duration_ms("120").unwrap(), 120 * 1000); // bare = seconds
        assert!(parse_duration_ms("").is_err());
        assert!(parse_duration_ms("5y").is_err());
        assert!(parse_duration_ms("-3d").is_err());
        assert!(parse_duration_ms("xd").is_err());
    }

    #[test]
    fn parse_size_units_and_bare_bytes() {
        assert_eq!(parse_size_bytes("500M").unwrap(), 500 * 1024 * 1024);
        assert_eq!(parse_size_bytes("1G").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size_bytes("250K").unwrap(), 250 * 1024);
        assert_eq!(parse_size_bytes("2048B").unwrap(), 2048);
        assert_eq!(parse_size_bytes("4096").unwrap(), 4096); // bare = bytes
        assert!(parse_size_bytes("").is_err());
        assert!(parse_size_bytes("10Z").is_err());
        assert!(parse_size_bytes("xM").is_err());
    }

    #[test]
    fn human_bytes_scales() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(1024 * 1024), "1.0 MiB");
    }
}
