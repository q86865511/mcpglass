//! `mcpglass export`: write one session to a self-contained JSON bundle with secrets
//! masked, for safe sharing (a bug report, a support ticket).
//!
//! A read-only diagnostic tool, like `replay`/`bloat`: it opens the session store
//! read-only, records nothing, and never touches the live wire. It **always masks** —
//! every recorded frame body, the command/label, and every argv token are run through
//! secret masking before they are written, and there is deliberately no `--no-mask`
//! flag. Masking covers the built-in patterns, plus the `custom_secret_patterns` of a
//! `--policy` file when one is passed (pass the same file the proxy ran with, so the
//! bundle hides exactly what the live scan would flag). If you need the raw, un-masked
//! data, share the sessions db file directly; the whole point of `export` is a bundle
//! that is safe to hand to someone else.

use std::path::PathBuf;

use policy::Policy;
use storage::Store;

/// CLI entry point for `mcpglass export --session <id> --out <path> [--policy <file>]`.
/// Returns a process exit code: 0 on success, 1 on any store/IO error, an unknown
/// session, or a `--policy` file that fails to load (an explicitly passed masking
/// config that silently does nothing is exactly the failure this tool must not have).
///
/// The bundle assembly + masking lives in [`dashboard::build_export_bundle`], shared
/// with the dashboard's export endpoint so both mask identically; this entry point only
/// resolves the policy, opens the store, and writes the result to `out`.
pub async fn run(db: Option<PathBuf>, session: i64, out: PathBuf, policy: Option<PathBuf>) -> i32 {
    // The policy contributes its `custom_secret_patterns` to masking; without one, the
    // default policy has none and masking is the built-in set exactly as before.
    let pol = match &policy {
        Some(p) => match Policy::load(p) {
            Ok(pol) => pol,
            Err(e) => {
                eprintln!("mcpglass: loading policy {}: {e:#}", p.display());
                return 1;
            }
        },
        None => Policy::default(),
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

    let bundle = match dashboard::build_export_bundle(&store, &pol, session) {
        Ok(Some(b)) => b,
        Ok(None) => {
            eprintln!("mcpglass: session {session} not found");
            return 1;
        }
        Err(e) => {
            eprintln!("mcpglass: exporting session {session}: {e:#}");
            return 1;
        }
    };

    let text = match serde_json::to_string_pretty(&bundle) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("mcpglass: serialising export bundle: {e}");
            return 1;
        }
    };
    if let Err(e) = std::fs::write(&out, text) {
        eprintln!("mcpglass: writing {}: {e}", out.display());
        return 1;
    }
    let message_count = bundle["messages"].as_array().map_or(0, Vec::len);
    println!(
        "exported session {session} ({message_count} message(s)) to {} — secrets masked ({})",
        out.display(),
        if pol.custom_secret_patterns.is_empty() {
            "built-in patterns; pass --policy to also mask custom patterns".to_owned()
        } else {
            format!(
                "built-in + {} custom pattern(s)",
                pol.custom_secret_patterns.len()
            )
        }
    );
    0
}
