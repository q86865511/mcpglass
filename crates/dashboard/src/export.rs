//! Shared export-bundle assembly: turn one recorded session into a self-contained,
//! secret-masked JSON bundle.
//!
//! Both `mcpglass export` (the CLI) and the dashboard's
//! `GET /api/sessions/{id}/export` go through [`build_export_bundle`], so the masking
//! guarantee is identical on either path: every recorded frame body, the display
//! command/label, and every argv token are run through [`Policy::mask_secrets`], and
//! there is deliberately no un-masked option. Masking covers the built-in patterns plus
//! a policy's `custom_secret_patterns` when one is supplied. If you need the raw,
//! un-masked data, share the sessions db file directly — the whole point of an export
//! bundle is that it is safe to hand to someone else.

use policy::Policy;
use serde_json::{json, Value};
use storage::{MessageExportRow, Store};

/// Assemble the masked export bundle for `session_id`, or `Ok(None)` when no such
/// session exists (the caller answers 404 / "not found"). Every field that could carry
/// a secret — message bodies, the display command/label, argv tokens — is masked with
/// `pol`; security / inject event details are already stored in masked form (see the
/// tap-path scanning) and are copied verbatim.
pub fn build_export_bundle(
    store: &Store,
    pol: &Policy,
    session_id: i64,
) -> anyhow::Result<Option<Value>> {
    let Some(summary) = store.session(session_id)? else {
        return Ok(None);
    };
    let messages = store.export_messages(session_id)?;
    // A generous limit pulls the whole session; the offset paging is a dashboard list
    // concern, not the export's.
    let security = store.security_events(session_id, u32::MAX, 0)?.1;
    let inject = store.inject_events(session_id, u32::MAX, 0)?.1;

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
            "argv": masked_argv(pol, summary.argv_json.as_deref()),
            "protocol_version": summary.protocol_version,
            "client_protocol_version": summary.client_protocol_version,
            "protocol_version_source": summary.protocol_version_source,
        },
        "messages": messages.iter().map(|m| message_json(pol, m)).collect::<Vec<_>>(),
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
    Ok(Some(bundle))
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
