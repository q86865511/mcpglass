//! `mcpglass bloat`: print a text report of how many context-window tokens a
//! session's advertised tool catalog (`tools/list`) would cost an LLM client,
//! using the zero-dependency heuristic in `proxy_core::bloat`. Read-only: opens
//! the session store, reads, prints — never writes.

use std::path::PathBuf;

use proxy_core::bloat::{
    analyze_tools_list_response, BloatReport, CHARS_PER_TOKEN, FAT_DESCRIPTION_TOKENS,
};
use storage::Store;

/// CLI entry point for `mcpglass bloat [--db P] [--session N] [--top N]`.
/// `session` defaults to the most recently started session recorded in the db.
pub async fn run(db: Option<PathBuf>, session: Option<i64>, top: usize) -> i32 {
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

    let session_id = match session {
        Some(id) => id,
        None => match store.list_sessions() {
            Ok(sessions) if !sessions.is_empty() => sessions[0].id,
            Ok(_) => {
                println!("no sessions recorded yet");
                return 0;
            }
            Err(e) => {
                eprintln!("mcpglass: listing sessions: {e:#}");
                return 1;
            }
        },
    };

    let raw = match store.latest_tools_list_raw(session_id) {
        Ok(Some(raw)) => raw,
        Ok(None) => {
            println!("no tools/list captured for this session");
            return 0;
        }
        Err(e) => {
            eprintln!("mcpglass: reading tools/list for session {session_id}: {e:#}");
            return 1;
        }
    };

    let value: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("mcpglass: parsing recorded tools/list response: {e}");
            return 1;
        }
    };

    match analyze_tools_list_response(&value) {
        Some(report) => {
            print_report(session_id, &report, top);
            0
        }
        None => {
            println!("no tools/list captured for this session");
            0
        }
    }
}

/// Render the report as a plain-text table on stdout.
fn print_report(session_id: i64, report: &BloatReport, top: usize) {
    println!(
        "Context bloat report for session {session_id} (approximate: ~{CHARS_PER_TOKEN} chars/token, not a real tokenizer)"
    );
    println!(
        "  {} tool(s), {} chars, ~{} tokens total",
        report.tool_count, report.total_chars, report.est_total_tokens
    );
    if report.tool_count == 0 {
        return;
    }

    let shown = top.min(report.tools.len());
    println!();
    println!("Top {shown} by estimated tokens:");
    println!("  {:<32} {:>10} {:>8} {:>7}", "tool", "est_tokens", "chars", "pct");
    for t in report.tools.iter().take(top) {
        let pct = if report.est_total_tokens > 0 {
            (t.est_tokens as f64 / report.est_total_tokens as f64) * 100.0
        } else {
            0.0
        };
        println!(
            "  {:<32} {:>10} {:>8} {:>6.1}%",
            t.name, t.est_tokens, t.total_chars, pct
        );
    }

    if !report.fat_tools.is_empty() {
        println!();
        println!("Trim candidates (description > {FAT_DESCRIPTION_TOKENS} est. tokens):");
        for name in &report.fat_tools {
            println!("  - {name}");
        }
    }
}
