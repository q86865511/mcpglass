//! Security-layer integration for the `wrap` hot path: policy resolution at
//! startup, newline framing that stays fail-open on the forwarding path, and the
//! pure client->server decision function.
//!
//! Everything here is deliberately pure (no IO, no async): the async pumps in
//! `main.rs` execute the decisions this module produces. The fail-open contract
//! is enforced structurally — the only value that ever suppresses a forward is an
//! explicit [`FrameAction::BlockWithResponse`]/[`FrameAction::BlockSilent`], which
//! [`decide_c2s_frame`] returns *only* when `policy::evaluate_request` explicitly
//! blocks (i.e. `enforce` mode plus a matched rule). Anything unexpected
//! (un-parseable frame, oversized frame, non-`tools/call`) forwards.

use std::path::{Path, PathBuf};

use policy::{evaluate_request, Action, EventKind, Mode, Policy};
use serde_json::Value;
use storage::{ActionTaken, SecurityEvent, SecurityEventKind};

/// Resolve the effective policy before any byte is forwarded.
///
/// Precedence: an explicit `--policy` path must load; otherwise the default file
/// (`<data_dir>/policy.toml`) is used *only if it exists*; if it is absent we fall
/// back to `Policy::default()` (monitor, no allow/deny, secret_scan on). A file
/// that exists but fails to parse is **never** treated as "no policy": it returns
/// `Err` so the caller can abort startup. This is safe precisely because it runs
/// before forwarding begins — once bytes flow the only safe posture is fail-open,
/// but a mis-loaded *security* config at startup must fail loud, not silently open.
pub fn resolve_policy(
    explicit: Option<&Path>,
    default_path: Option<PathBuf>,
    enforce: bool,
) -> Result<Policy, String> {
    let mut policy = match explicit {
        // An explicitly named file must load; a missing/broken one is a hard error.
        Some(path) => {
            Policy::load(path).map_err(|e| format!("failed to load policy {}: {e:#}", path.display()))?
        }
        None => match default_path {
            // The default file is optional, but if present it must parse cleanly.
            Some(path) if path.exists() => Policy::load(&path)
                .map_err(|e| format!("failed to load policy {}: {e:#}", path.display()))?,
            _ => Policy::default(),
        },
    };
    // `--enforce` is a command-line override for the loaded mode.
    if enforce {
        policy.mode = Mode::Enforce;
    }
    Ok(policy)
}

/// A complete or pass-through unit produced by [`FramedStream`].
#[derive(Debug, PartialEq, Eq)]
pub enum Chunk {
    /// A complete frame (newline stripped). The caller decides/records it and,
    /// when forwarding, re-appends the `\n`.
    Frame(Vec<u8>),
    /// Bytes that must be forwarded verbatim without any decision or recording.
    /// Emitted only for an oversized (overflowing) frame — see [`FramedStream`].
    Raw(Vec<u8>),
}

/// Newline framing for a leg whose *forwarding* is derived from the frames (the
/// client->server leg blocks per message; the server->client leg writes
/// frame-atomically so injected block-responses can't corrupt a real frame).
///
/// This mirrors `proxy_core::LineSplitter` but with one load-bearing difference:
/// `LineSplitter` is a tap-only helper that silently *drops* an oversized frame,
/// because there forwarding happens separately on the raw bytes. Here forwarding
/// is driven by this splitter, so a dropped frame would mean **lost traffic**.
/// Instead, an overflow is surfaced as [`Chunk::Raw`] and forwarded verbatim
/// (fail-open): we give up deciding/recording that frame, never forwarding it.
pub struct FramedStream {
    /// Bytes of the current, not-yet-complete frame. In normal mode these are
    /// held back (unforwarded) until the frame completes; on overflow they are
    /// flushed as `Raw` and this stays empty until the next frame.
    buf: Vec<u8>,
    max_line_bytes: usize,
    /// True while inside a frame that already exceeded `max_line_bytes`; its bytes
    /// are being forwarded raw and it will neither be decided nor recorded.
    overflowed: bool,
}

impl FramedStream {
    pub fn new(max_line_bytes: usize) -> Self {
        Self {
            buf: Vec::new(),
            max_line_bytes,
            overflowed: false,
        }
    }

    /// Feed freshly read bytes; return the ordered actions they produce. Every
    /// input byte is accounted for: it is either buffered into a `Frame`, or
    /// forwarded verbatim via `Raw`. Nothing is dropped, so the caller can always
    /// keep the wire whole.
    pub fn push(&mut self, mut data: &[u8]) -> Vec<Chunk> {
        let mut out = Vec::new();
        while let Some(pos) = data.iter().position(|&b| b == b'\n') {
            let (head, rest) = data.split_at(pos);
            data = &rest[1..]; // consume the '\n'
            if self.overflowed {
                // Terminating newline of an oversized frame: forward its tail
                // (head + the '\n') verbatim, then resume normal framing.
                let mut raw = head.to_vec();
                raw.push(b'\n');
                out.push(Chunk::Raw(raw));
                self.overflowed = false;
                self.buf.clear();
            } else {
                self.buf.extend_from_slice(head);
                out.push(Chunk::Frame(std::mem::take(&mut self.buf)));
            }
        }
        // Remainder has no newline yet.
        if self.overflowed {
            // Still inside an oversized frame: keep forwarding raw as bytes arrive.
            if !data.is_empty() {
                out.push(Chunk::Raw(data.to_vec()));
            }
        } else if !data.is_empty() {
            self.buf.extend_from_slice(data);
            if self.buf.len() > self.max_line_bytes {
                // Overflow: we can no longer decide/record this frame. Fail-open:
                // flush what we buffered (never yet forwarded) and pass the rest
                // through raw until its terminating newline.
                out.push(Chunk::Raw(std::mem::take(&mut self.buf)));
                self.overflowed = true;
            }
        }
        out
    }

    /// At EOF, return any buffered but unterminated trailing frame so the caller
    /// can forward it verbatim (fail-open: an unterminated frame is not a decidable
    /// MCP message). Returns `None` when nothing is pending (including mid-overflow,
    /// whose bytes were already forwarded raw).
    pub fn finish(&mut self) -> Option<Vec<u8>> {
        if self.overflowed || self.buf.is_empty() {
            None
        } else {
            Some(std::mem::take(&mut self.buf))
        }
    }
}

/// What to do with one decided client->server frame.
#[derive(Debug, PartialEq, Eq)]
pub enum FrameAction {
    /// Forward the frame to the server unchanged (re-append the `\n`).
    Forward,
    /// Do not forward; write these bytes (a complete JSON-RPC error line, `\n`
    /// terminated) back to the client instead. This is an in-protocol refusal.
    BlockWithResponse(Vec<u8>),
    /// Do not forward and send nothing: the blocked request carried no id, so
    /// there is no legal response to synthesize. The frame is dropped.
    BlockSilent,
}

/// The result of deciding one client->server frame: the wire action plus the
/// security events to persist (present for both forward-with-flag and block).
/// (`storage::SecurityEvent` is not `PartialEq`, so this type isn't compared
/// wholesale — callers act on `action` and `events` directly.)
pub struct Decision {
    pub action: FrameAction,
    pub events: Vec<SecurityEvent>,
}

/// Decide a single client->server frame. Pure and infallible: it never blocks a
/// frame unless `policy` (in `enforce` mode) explicitly denies it.
///
/// Fail-open layering:
/// * a frame that is not valid JSON is forwarded with no events (Phase-1 parity);
/// * `evaluate_request` returns `Forward` for anything but a matched `tools/call`
///   under `enforce`, so monitor mode and unmatched calls always forward;
/// * only an explicit `Action::Block` yields a non-forward action here.
pub fn decide_c2s_frame(frame: &[u8], policy: &Policy, ts_ms: i64) -> Decision {
    // Non-JSON frames are not decidable protocol messages: forward as-is, exactly
    // as the transparent Phase-1 proxy did. No panic path, no block.
    let Ok(value) = serde_json::from_slice::<Value>(frame) else {
        return Decision {
            action: FrameAction::Forward,
            events: Vec::new(),
        };
    };

    let evaluation = evaluate_request(&value, policy);
    let blocked = evaluation.action == Action::Block;
    let action_taken = if blocked {
        ActionTaken::Blocked
    } else {
        ActionTaken::Flagged
    };

    // The request id is echoed verbatim in any synthesized error, and normalized
    // for the event row. `id` may be absent or null (a notification): both mean
    // "no legal response".
    let id_value = value.get("id").cloned();
    let rpc_id = id_value.as_ref().and_then(normalize_id);

    let events: Vec<SecurityEvent> = evaluation
        .events
        .iter()
        .map(|e| SecurityEvent {
            ts_ms,
            kind: map_kind(e.kind),
            rule: e.rule.clone(),
            detail: e.detail.clone(),
            tool_name: e.tool_name.clone(),
            rpc_id: rpc_id.clone(),
            action_taken,
        })
        .collect();

    let action = if blocked {
        // `blocked` implies at least one event fired; cite the first (the deny
        // rule is pushed before any secret hit, so it takes precedence).
        let rule = evaluation
            .events
            .first()
            .map(|e| e.rule.as_str())
            .unwrap_or("policy");
        match id_value.filter(|v| !v.is_null()) {
            Some(id) => FrameAction::BlockWithResponse(synthesize_error(&id, rule)),
            None => FrameAction::BlockSilent,
        }
    } else {
        FrameAction::Forward
    };

    Decision { action, events }
}

/// The JSON body of a JSON-RPC error response denying a blocked request, *without*
/// a trailing newline. Built via `serde_json` so the id (which may be a number or
/// string) and message are always correctly encoded.
///
/// The stdio transport wants a `\n`-terminated frame ([`synthesize_error`]); the
/// HTTP gateway wants the bare JSON body (an `application/json` response has no
/// newline framing). Both share this builder so the -32001 shape stays identical.
pub fn synthesize_error_body(id: &Value, rule: &str) -> Vec<u8> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32001,
            "message": format!("blocked by mcpglass policy: {rule}"),
        }
    });
    // The value is constructed from owned data and cannot fail to serialize.
    serde_json::to_vec(&body).expect("error response serializes")
}

/// A complete `\n`-terminated JSON-RPC error response for the stdio transport,
/// where each message is one newline-delimited frame.
fn synthesize_error(id: &Value, rule: &str) -> Vec<u8> {
    let mut bytes = synthesize_error_body(id, rule);
    bytes.push(b'\n');
    bytes
}

/// Normalize a JSON-RPC `id` to the text form used in storage (mirrors
/// `proxy_core::parse_line`): null -> none, string kept, anything else stringified.
fn normalize_id(id: &Value) -> Option<String> {
    match id {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        other => Some(other.to_string()),
    }
}

fn map_kind(kind: EventKind) -> SecurityEventKind {
    match kind {
        EventKind::PolicyDeny => SecurityEventKind::PolicyDeny,
        EventKind::SecretLeak => SecurityEventKind::SecretLeak,
        EventKind::FingerprintChange => SecurityEventKind::FingerprintChange,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn frames(chunks: Vec<Chunk>) -> Vec<String> {
        chunks
            .into_iter()
            .filter_map(|c| match c {
                Chunk::Frame(f) => Some(String::from_utf8_lossy(&f).into_owned()),
                Chunk::Raw(_) => None,
            })
            .collect()
    }

    // --- FramedStream -------------------------------------------------------

    #[test]
    fn frames_split_and_reassemble_across_reads() {
        let mut s = FramedStream::new(1024);
        assert!(s.push(b"{\"a\"").is_empty());
        assert!(s.push(b":1}").is_empty());
        assert_eq!(frames(s.push(b"\n")), vec![r#"{"a":1}"#]);
    }

    #[test]
    fn multiple_frames_in_one_read() {
        let mut s = FramedStream::new(1024);
        assert_eq!(frames(s.push(b"a\nbb\nccc\n")), vec!["a", "bb", "ccc"]);
    }

    #[test]
    fn remainder_is_buffered_not_forwarded_until_newline() {
        // A partial frame must NOT be surfaced (so the caller holds it back and can
        // still block it once complete).
        let mut s = FramedStream::new(1024);
        assert!(s.push(b"partial").is_empty());
        let out = s.push(b" tail\n");
        assert_eq!(frames(out), vec!["partial tail"]);
    }

    #[test]
    fn oversized_frame_is_forwarded_raw_and_stream_recovers() {
        // Cap 8: a 20-byte frame overflows -> emitted as Raw (never dropped),
        // and every input byte is preserved across the Raw chunks + newline.
        let mut s = FramedStream::new(8);
        let big = vec![b'x'; 20];
        let mut raw_total = Vec::new();
        for c in s.push(&big) {
            if let Chunk::Raw(b) = c {
                raw_total.extend_from_slice(&b);
            }
        }
        // Feed the terminating newline plus a following well-sized frame.
        for c in s.push(b"\nshort\n") {
            match c {
                Chunk::Raw(b) => raw_total.extend_from_slice(&b),
                Chunk::Frame(f) => assert_eq!(f, b"short"),
            }
        }
        // The oversized frame's bytes were all forwarded raw, including its '\n'.
        assert_eq!(raw_total, b"xxxxxxxxxxxxxxxxxxxx\n");
    }

    #[test]
    fn finish_flushes_unterminated_trailing_frame() {
        let mut s = FramedStream::new(1024);
        assert!(s.push(b"no newline").is_empty());
        assert_eq!(s.finish().unwrap(), b"no newline");
        // Idempotent: nothing left after finishing.
        assert!(s.finish().is_none());
    }

    #[test]
    fn finish_after_overflow_yields_nothing() {
        let mut s = FramedStream::new(4);
        // Overflow with no terminating newline: bytes already forwarded raw.
        let _ = s.push(b"abcdefgh");
        assert!(s.finish().is_none());
    }

    // --- decide_c2s_frame ---------------------------------------------------

    fn tools_call(name: &str, args: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": 42, "method": "tools/call",
            "params": { "name": name, "arguments": args }
        }))
        .unwrap()
    }

    #[test]
    fn non_json_forwards_with_no_events() {
        let d = decide_c2s_frame(b"not json at all", &Policy::default(), 1);
        assert_eq!(d.action, FrameAction::Forward);
        assert!(d.events.is_empty());
    }

    #[test]
    fn monitor_deny_forwards_but_flags() {
        let policy = Policy::from_toml_str("deny = [\"dangerous\"]").unwrap();
        let d = decide_c2s_frame(&tools_call("dangerous", json!({})), &policy, 7);
        assert_eq!(d.action, FrameAction::Forward);
        assert_eq!(d.events.len(), 1);
        assert_eq!(d.events[0].kind, SecurityEventKind::PolicyDeny);
        assert_eq!(d.events[0].action_taken, ActionTaken::Flagged);
        assert_eq!(d.events[0].rpc_id.as_deref(), Some("42"));
    }

    #[test]
    fn enforce_deny_blocks_with_error_echoing_the_id() {
        let policy = Policy::from_toml_str("mode = \"enforce\"\ndeny = [\"dangerous\"]").unwrap();
        let d = decide_c2s_frame(&tools_call("dangerous", json!({})), &policy, 7);
        let FrameAction::BlockWithResponse(resp) = &d.action else {
            panic!("expected a block response, got {:?}", d.action);
        };
        let v: Value = serde_json::from_slice(resp).unwrap();
        assert_eq!(v["id"], json!(42));
        assert_eq!(v["error"]["code"], json!(-32001));
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("dangerous"));
        assert!(resp.ends_with(b"\n"));
        assert_eq!(d.events[0].action_taken, ActionTaken::Blocked);
    }

    #[test]
    fn enforce_block_without_id_is_silent() {
        // A notification-shaped tools/call (no id) cannot be answered in-protocol.
        let frame = serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "method": "tools/call",
            "params": { "name": "dangerous", "arguments": {} }
        }))
        .unwrap();
        let policy = Policy::from_toml_str("mode = \"enforce\"\ndeny = [\"dangerous\"]").unwrap();
        let d = decide_c2s_frame(&frame, &policy, 1);
        assert_eq!(d.action, FrameAction::BlockSilent);
        assert_eq!(d.events.len(), 1);
        assert_eq!(d.events[0].action_taken, ActionTaken::Blocked);
    }

    #[test]
    fn secret_in_arguments_is_flagged_in_monitor() {
        let secret = format!("AKIA{}", "A".repeat(16));
        let d = decide_c2s_frame(
            &tools_call("send", json!({ "body": secret })),
            &Policy::default(),
            1,
        );
        assert_eq!(d.action, FrameAction::Forward);
        assert!(d
            .events
            .iter()
            .any(|e| e.kind == SecurityEventKind::SecretLeak));
        // The stored detail is masked, never the raw secret.
        assert!(d.events.iter().all(|e| e.detail != secret));
    }

    // --- resolve_policy -----------------------------------------------------

    #[test]
    fn resolve_falls_back_to_default_when_no_file() {
        let p = resolve_policy(None, Some(PathBuf::from("/no/such/file.toml")), false).unwrap();
        assert_eq!(p.mode, Mode::Monitor);
        assert!(p.secret_scan);
    }

    #[test]
    fn resolve_enforce_flag_overrides_mode() {
        let p = resolve_policy(None, None, true).unwrap();
        assert_eq!(p.mode, Mode::Enforce);
    }

    #[test]
    fn resolve_broken_explicit_policy_is_error() {
        let dir = std::env::temp_dir().join(format!("mcpglass-sec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.toml");
        std::fs::write(&path, "mode = \"enforce\"\ndeny = [").unwrap();
        assert!(resolve_policy(Some(&path), None, false).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
