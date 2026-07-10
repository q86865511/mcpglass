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
use serde_json::{json, Value};
use storage::{MessageExportRow, Store};

/// CLI entry point for `mcpglass export --session <id> --out <path> [--policy <file>]`.
/// Returns a process exit code: 0 on success, 1 on any store/IO error, an unknown
/// session, or a `--policy` file that fails to load (an explicitly passed masking
/// config that silently does nothing is exactly the failure this tool must not have).
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

    let summary = match store.session(session) {
        Ok(Some(s)) => s,
        Ok(None) => {
            eprintln!("mcpglass: session {session} not found");
            return 1;
        }
        Err(e) => {
            eprintln!("mcpglass: reading session {session}: {e:#}");
            return 1;
        }
    };

    let messages = match store.export_messages(session) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("mcpglass: reading messages for session {session}: {e:#}");
            return 1;
        }
    };
    // Security / inject event details are already stored in masked form (see the
    // scanning/masking on the tap path), so they are copied verbatim. A generous limit
    // pulls the whole session; the offset paging is a dashboard concern, not ours.
    let security = match store.security_events(session, u32::MAX, 0) {
        Ok((_, rows)) => rows,
        Err(e) => {
            eprintln!("mcpglass: reading security events for session {session}: {e:#}");
            return 1;
        }
    };
    let inject = match store.inject_events(session, u32::MAX, 0) {
        Ok((_, rows)) => rows,
        Err(e) => {
            eprintln!("mcpglass: reading inject events for session {session}: {e:#}");
            return 1;
        }
    };

    let bundle = json!({
        "mcpglass_version": env!("CARGO_PKG_VERSION"),
        "schema_version": storage::SCHEMA_VERSION,
        "session": {
            "id": summary.id,
            // Display command and label may themselves carry a token; mask defensively.
            "command": pol.mask_secrets(&summary.command),
            "label": pol.mask_secrets(&summary.label),
            "started_at_ms": summary.started_at_ms,
            "ended_at_ms": summary.ended_at_ms,
            "message_count": summary.message_count,
            "program": summary.program,
            "transport": summary.transport,
            "server_id": summary.server_id,
            // argv, per-token masked (each token can contain a secret, e.g. an API key
            // passed as a flag). `null` for an HTTP session or a legacy pre-v7 row.
            "argv": masked_argv(&pol, summary.argv_json.as_deref()),
            "protocol_version": summary.protocol_version,
            "client_protocol_version": summary.client_protocol_version,
            "protocol_version_source": summary.protocol_version_source,
        },
        "messages": messages.iter().map(|m| message_json(&pol, m)).collect::<Vec<_>>(),
        "security_events": security.iter().map(|e| json!({
            "id": e.id,
            "ts_ms": e.ts_ms,
            "kind": e.kind.as_str(),
            "rule": e.rule,
            "detail": e.detail,
            "tool_name": e.tool_name,
            "rpc_id": e.rpc_id,
            "action_taken": e.action_taken.as_str(),
        })).collect::<Vec<_>>(),
        "inject_events": inject.iter().map(|e| json!({
            "id": e.id,
            "ts_ms": e.ts_ms,
            "direction": e.direction.as_str(),
            "rule": e.rule,
            "fault": e.fault.as_str(),
            "detail": e.detail,
            "method": e.method,
            "rpc_id": e.rpc_id,
        })).collect::<Vec<_>>(),
    });

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
    println!(
        "exported session {session} ({} message(s)) to {} — secrets masked ({})",
        messages.len(),
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

/// One message as a masked JSON object. A metadata-only recording (empty `raw` +
/// non-null `raw_len`) is emitted with `raw: null` and its `raw_len`, so a consumer
/// sees the body was deliberately not recorded rather than an empty payload. A full
/// recording has its body run through [`Policy::mask_secrets`] (built-in patterns plus
/// the policy's custom ones).
fn message_json(pol: &Policy, m: &MessageExportRow) -> Value {
    let metadata_only = m.raw.is_empty() && m.raw_len.is_some();
    let raw = if metadata_only {
        Value::Null
    } else {
        Value::String(pol.mask_secrets(&m.raw))
    };
    json!({
        "id": m.id,
        "ts_ms": m.ts_ms,
        "direction": m.direction.as_str(),
        "method": m.method,
        "rpc_id": m.rpc_id,
        "is_valid_json": m.is_valid_json,
        "is_error": m.is_error,
        "raw": raw,
        "raw_len": m.raw_len,
    })
}

/// Parse a session's `argv_json` (a JSON array of strings) and mask each token, or
/// return `Value::Null` when there is no structured argv (HTTP / legacy session) or it
/// fails to parse.
fn masked_argv(pol: &Policy, argv_json: Option<&str>) -> Value {
    match argv_json.and_then(|j| serde_json::from_str::<Vec<String>>(j).ok()) {
        Some(argv) => Value::Array(
            argv.iter()
                .map(|tok| Value::String(pol.mask_secrets(tok)))
                .collect(),
        ),
        None => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proxy_core::Direction;

    fn row(raw: &str, raw_len: Option<i64>) -> MessageExportRow {
        MessageExportRow {
            id: 1,
            ts_ms: 1,
            direction: Direction::C2s,
            method: Some("tools/call".to_owned()),
            rpc_id: Some("1".to_owned()),
            is_valid_json: true,
            is_error: false,
            raw: raw.to_owned(),
            raw_len,
        }
    }

    #[test]
    fn message_raw_body_is_masked() {
        // A frame carrying an AWS key must come out masked, never verbatim.
        let pol = Policy::default();
        let raw = r#"{"id":1,"params":{"arguments":{"key":"AKIAIOSFODNN7EXAMPLE"}}}"#;
        let v = message_json(&pol, &row(raw, None));
        let out = v["raw"].as_str().unwrap();
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"), "raw key leaked: {out}");
        assert!(out.contains("AKIA") && out.contains('*'), "expected a masked key: {out}");
        assert!(v["raw_len"].is_null());
    }

    #[test]
    fn metadata_only_row_emits_null_raw_and_keeps_raw_len() {
        // Empty raw + a raw_len == metadata-only: raw is null, raw_len preserved.
        let v = message_json(&Policy::default(), &row("", Some(128)));
        assert!(v["raw"].is_null(), "metadata-only body must be null");
        assert_eq!(v["raw_len"].as_i64().unwrap(), 128);
    }

    #[test]
    fn argv_tokens_are_masked_per_token() {
        // A token that is itself a secret (a key passed as a flag value) is masked.
        let pol = Policy::default();
        let argv =
            serde_json::to_string(&vec!["srv", "--token", "AKIAIOSFODNN7EXAMPLE"]).unwrap();
        let v = masked_argv(&pol, Some(&argv));
        let arr = v.as_array().unwrap();
        assert_eq!(arr[0], "srv");
        assert_eq!(arr[1], "--token");
        assert!(!arr[2].as_str().unwrap().contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(arr[2].as_str().unwrap().contains('*'));
        // No structured argv -> null.
        assert!(masked_argv(&pol, None).is_null());
    }

    #[test]
    fn policy_custom_patterns_are_masked_too() {
        // A user's custom_secret_patterns must be hidden in the bundle exactly like the
        // built-ins — otherwise a token the live scan flags would leave the machine in
        // plaintext through the very tool that promises "safe to share".
        let pol = Policy::from_toml_str(
            r#"custom_secret_patterns = ["MYCORP_[A-Z0-9]{20}"]"#,
        )
        .unwrap();
        let raw = r#"{"params":{"arguments":{"k":"MYCORP_ABCDEFGHIJ0123456789"}}}"#;
        let v = message_json(&pol, &row(raw, None));
        let out = v["raw"].as_str().unwrap();
        assert!(!out.contains("MYCORP_ABCDEFGHIJ0123456789"), "custom secret leaked: {out}");
        assert!(out.contains('*'), "expected a masked span: {out}");
        // Without the policy, the same body passes through the built-in-only masker.
        let plain = message_json(&Policy::default(), &row(raw, None));
        assert!(plain["raw"].as_str().unwrap().contains("MYCORP_ABCDEFGHIJ0123456789"));
    }
}
