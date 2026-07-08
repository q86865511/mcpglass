//! Pure security-policy core for the proxy: the policy model + TOML loading,
//! secret detection, tool fingerprinting, and a pure request decision function.
//!
//! Everything here is pure logic with **no IO on the hot path**. The caller runs
//! [`evaluate_request`] on the client->server leg to decide whether to forward or
//! block a `tools/call`, but this crate never forwards bytes, never touches the
//! DB, and never spawns: a bug here must at worst produce a wrong (and, in the
//! default `monitor` mode, purely advisory) verdict — it can never stall or
//! corrupt traffic.
//!
//! The default posture is deliberately conservative: **`monitor`** only observes
//! and emits events; **`enforce`** is opt-in and is the only mode that can return
//! [`Action::Block`].
//!
//! # Policy TOML
//!
//! ```toml
//! mode = "monitor"                       # "monitor" (default) | "enforce"
//! allow = ["read_file", "list_dir"]      # when non-empty, unlisted tools are denied
//! deny = ["dangerous_*", "rm"]           # takes priority over allow; trailing `*` = prefix wildcard
//! secret_scan = true                     # scan tools/call arguments for secrets (default true)
//! custom_secret_patterns = ["MYCORP_[A-Z0-9]{20}"]  # extra user regexes
//! ```

use std::path::Path;
use std::sync::OnceLock;

use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Enforcement posture. `Monitor` observes and emits events but never blocks;
/// `Enforce` is the only mode that can return [`Action::Block`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Observe only: events are still produced, but the action is always
    /// [`Action::Forward`]. This is the default.
    #[default]
    Monitor,
    /// Actively block: a request that produces any event is denied.
    Enforce,
}

/// A loaded, compiled security policy. Construct via [`Policy::default`],
/// [`Policy::from_toml_str`], or [`Policy::load`]; the compiled form of
/// `custom_secret_patterns` is built at load time so the hot path never compiles
/// a regex.
#[derive(Debug, Clone)]
pub struct Policy {
    pub mode: Mode,
    /// Tool-name allow-list. When non-empty, any `tools/call` whose tool is not
    /// listed is treated as a deny (exact match only).
    pub allow: Vec<String>,
    /// Tool-name deny-list; takes priority over `allow`. A trailing `*` is a
    /// prefix wildcard (`foo_*` matches `foo_bar`); otherwise the match is exact.
    pub deny: Vec<String>,
    /// Whether to scan `tools/call` arguments for secrets. Default `true`.
    pub secret_scan: bool,
    /// User-supplied secret regexes, kept verbatim for round-tripping/inspection.
    pub custom_secret_patterns: Vec<String>,
    /// Compiled form of `custom_secret_patterns`, built once at load. Positional
    /// index matches `custom_secret_patterns`; reported as `custom[i]`.
    custom_compiled: Vec<Regex>,
}

/// TOML shape, kept private so the public [`Policy`] stays free of serde
/// attributes. `deny_unknown_fields` catches config typos — a mistyped `deny`
/// silently disabling every deny rule is exactly the failure a security config
/// must not have.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyToml {
    #[serde(default)]
    mode: Mode,
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    deny: Vec<String>,
    #[serde(default = "default_true")]
    secret_scan: bool,
    #[serde(default)]
    custom_secret_patterns: Vec<String>,
}

fn default_true() -> bool {
    true
}

impl Default for Policy {
    /// `monitor`, empty allow/deny, `secret_scan = true`.
    fn default() -> Self {
        Self {
            mode: Mode::Monitor,
            allow: Vec::new(),
            deny: Vec::new(),
            secret_scan: true,
            custom_secret_patterns: Vec::new(),
            custom_compiled: Vec::new(),
        }
    }
}

impl Policy {
    /// Parse a policy from a TOML string. A malformed custom regex is a load-time
    /// error (fail loud here) rather than a silent no-op on the hot path.
    pub fn from_toml_str(s: &str) -> Result<Self> {
        let raw: PolicyToml = toml::from_str(s).context("parsing policy TOML")?;
        let custom_compiled = compile_custom(&raw.custom_secret_patterns)?;
        Ok(Self {
            mode: raw.mode,
            allow: raw.allow,
            deny: raw.deny,
            secret_scan: raw.secret_scan,
            custom_secret_patterns: raw.custom_secret_patterns,
            custom_compiled,
        })
    }

    /// Read and parse a policy file. A missing/unreadable file is an error.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading policy file {}", path.display()))?;
        Self::from_toml_str(&text)
    }

    /// The compiled custom secret regexes, for callers that scan directly.
    pub fn custom_secret_regexes(&self) -> &[Regex] {
        &self.custom_compiled
    }
}

fn compile_custom(patterns: &[String]) -> Result<Vec<Regex>> {
    patterns
        .iter()
        .map(|p| {
            Regex::new(p).with_context(|| format!("compiling custom secret pattern {p:?}"))
        })
        .collect()
}

/// One secret match. `matched_preview` is masked: only the first 4 and last 2
/// characters survive, the middle replaced by `*` — never the raw secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretHit {
    /// Which pattern matched (built-in name, e.g. `aws_access_key`, or
    /// `custom[i]` for the i-th custom pattern).
    pub pattern_name: String,
    pub matched_preview: String,
}

/// Built-in secret patterns, compiled once. Each `unwrap` is on a constant
/// pattern validated by the test suite; a bad one is a build-time bug, not a
/// runtime condition. High-entropy detection is deliberately absent (its false
/// positive rate is too high for a block decision); everything here is an
/// explicit, well-known credential shape.
fn builtin_patterns() -> &'static [(&'static str, Regex)] {
    static PATTERNS: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            // AWS access key id: AKIA + 16 base36 uppercase.
            ("aws_access_key", Regex::new(r"AKIA[0-9A-Z]{16}").unwrap()),
            // GitHub personal access token (classic): ghp_ + 36 alnum.
            ("github_token", Regex::new(r"ghp_[A-Za-z0-9]{36}").unwrap()),
            // GitHub fine-grained PAT: github_pat_ + base62/underscore body.
            (
                "github_pat",
                Regex::new(r"github_pat_[A-Za-z0-9_]{22,}").unwrap(),
            ),
            // Anthropic API key: sk-ant- prefix. Checked before the OpenAI shape
            // (which its `-` breaks anyway) so it is attributed correctly.
            (
                "anthropic_api_key",
                Regex::new(r"sk-ant-[A-Za-z0-9-]{20,}").unwrap(),
            ),
            // OpenAI API key: sk- + 20+ alnum (no `-`, so sk-ant- keys never match).
            ("openai_api_key", Regex::new(r"sk-[A-Za-z0-9]{20,}").unwrap()),
            // Slack token: xoxb/xoxa/xoxp/xoxr/xoxs- prefix.
            (
                "slack_token",
                Regex::new(r"xox[baprs]-[A-Za-z0-9-]{10,}").unwrap(),
            ),
            // Google API key: AIza + 35 url-safe chars.
            (
                "google_api_key",
                Regex::new(r"AIza[0-9A-Za-z_\-]{35}").unwrap(),
            ),
            // PEM private key header.
            (
                "private_key",
                Regex::new(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----").unwrap(),
            ),
            // JSON Web Token: base64url header.payload.signature, header/payload
            // both starting `eyJ` (base64 of `{"`). Requiring all three segments
            // keeps the false positive rate down.
            (
                "jwt",
                Regex::new(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+").unwrap(),
            ),
        ]
    })
}

/// Scan a single string for secrets using the built-in patterns plus `custom`.
/// Every match yields a [`SecretHit`] with a masked preview.
pub fn scan_secrets(text: &str, custom: &[Regex]) -> Vec<SecretHit> {
    let mut hits = Vec::new();
    for (name, re) in builtin_patterns() {
        for m in re.find_iter(text) {
            hits.push(SecretHit {
                pattern_name: (*name).to_owned(),
                matched_preview: mask(m.as_str()),
            });
        }
    }
    for (i, re) in custom.iter().enumerate() {
        for m in re.find_iter(text) {
            hits.push(SecretHit {
                pattern_name: format!("custom[{i}]"),
                matched_preview: mask(m.as_str()),
            });
        }
    }
    hits
}

/// Scan only the `params.arguments` of a request, recursing into every string
/// value it contains. Deliberately narrow: it never inspects the method name or
/// a tool's advertised schema, which keeps a tool literally named like a token,
/// or a schema documenting one, from tripping a false positive. A missing or
/// non-object `arguments` yields no hits.
pub fn scan_request_arguments(request_json: &Value, custom: &[Regex]) -> Vec<SecretHit> {
    let args = request_json
        .get("params")
        .and_then(|p| p.get("arguments"));
    match args {
        Some(v) if v.is_object() => {
            let mut strings = Vec::new();
            collect_strings(v, &mut strings);
            strings
                .iter()
                .flat_map(|s| scan_secrets(s, custom))
                .collect()
        }
        _ => Vec::new(),
    }
}

/// Recursively collect every JSON string value reachable from `v`.
fn collect_strings<'a>(v: &'a Value, out: &mut Vec<&'a str>) {
    match v {
        Value::String(s) => out.push(s),
        Value::Array(a) => a.iter().for_each(|e| collect_strings(e, out)),
        Value::Object(m) => m.values().for_each(|e| collect_strings(e, out)),
        _ => {}
    }
}

/// Mask a matched secret: keep the first 4 and last 2 characters, replace the
/// middle with `*` (capped so a long token does not yield a huge preview). A
/// short match (<= 6 chars) is fully starred.
fn mask(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len();
    if n <= 6 {
        return "*".repeat(n);
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[n - 2..].iter().collect();
    let stars = (n - 6).min(32);
    format!("{head}{}{tail}", "*".repeat(stars))
}

/// Stable fingerprint of a single tool definition: SHA-256 over a canonical
/// (recursively key-sorted) JSON of just `name` + `description` + `inputSchema`.
/// Extra fields a server may add (annotations, etc.) do not affect it, so the
/// fingerprint tracks the security-relevant surface only.
pub fn fingerprint_tool(tool: &Value) -> String {
    let subset = serde_json::json!({
        "name": tool.get("name").cloned().unwrap_or(Value::Null),
        "description": tool.get("description").cloned().unwrap_or(Value::Null),
        "inputSchema": tool.get("inputSchema").cloned().unwrap_or(Value::Null),
    });
    let mut canonical = String::new();
    write_canonical(&subset, &mut canonical);

    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    to_hex(&hasher.finalize())
}

/// Extract `(tool name, fingerprint)` for every tool in a `tools/list` response
/// (`result.tools[]`). Returns an empty vec for anything that is not a
/// tools/list response or whose shape does not match. Nameless tools are skipped.
pub fn fingerprints_from_tools_list(response_json: &Value) -> Vec<(String, String)> {
    let tools = response_json
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(|t| t.as_array());
    let Some(tools) = tools else {
        return Vec::new();
    };
    tools
        .iter()
        .filter_map(|tool| {
            let name = tool.get("name").and_then(|n| n.as_str())?;
            Some((name.to_owned(), fingerprint_tool(tool)))
        })
        .collect()
}

/// Canonical JSON writer: objects are emitted with keys sorted recursively so the
/// fingerprint is stable regardless of the source key order (and independent of
/// whether serde_json's `preserve_order` feature is enabled anywhere in the
/// build). Arrays keep their order — it is semantically significant.
fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Array(a) => {
            out.push('[');
            for (i, e) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(e, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                // A key is a JSON string; delegate its escaping to serde_json.
                out.push_str(&serde_json::to_string(k).expect("string serializes"));
                out.push(':');
                write_canonical(&m[*k], out);
            }
            out.push('}');
        }
        // Scalars and strings have no ordering; serde_json renders them canonically.
        other => out.push_str(&serde_json::to_string(other).expect("scalar serializes")),
    }
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Whether to forward a request. `Block` is only ever returned in `Enforce` mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Forward,
    Block,
}

/// A security event raised while evaluating a message. In `Monitor` mode events
/// are advisory (the action stays `Forward`); in `Enforce` mode any event blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEvent {
    pub kind: EventKind,
    /// The rule that matched: a tool name / deny pattern for policy events, or a
    /// secret pattern name for secret events.
    pub rule: String,
    /// Human-readable detail. For a secret this is the masked preview, never the
    /// raw value.
    pub detail: String,
    pub tool_name: Option<String>,
}

/// Kinds of security event. `FingerprintChange` is defined here for callers to
/// share but is **not** produced by [`evaluate_request`]: it belongs to the
/// server->client side, where storage compares a tool's fingerprint against its
/// recorded history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    PolicyDeny,
    SecretLeak,
    FingerprintChange,
}

/// The outcome of evaluating one request: what to do, plus every event observed
/// (present even when `action == Forward`, e.g. in `Monitor` mode).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestEvaluation {
    pub action: Action,
    pub events: Vec<PolicyEvent>,
}

/// Pure c2s decision function — the hot-path core. Non-`tools/call` requests
/// always forward with no events. For a `tools/call` it applies the deny/allow
/// rules to the tool name and (when `secret_scan` is on) scans the arguments;
/// each finding is an event. The action is `Block` iff the mode is `Enforce`
/// and at least one event fired, else `Forward`. Malformed input (missing
/// `params`, non-object `arguments`, absent tool name) never panics.
pub fn evaluate_request(request_json: &Value, policy: &Policy) -> RequestEvaluation {
    let mut events = Vec::new();

    let method = request_json.get("method").and_then(|m| m.as_str());
    if method != Some("tools/call") {
        return RequestEvaluation {
            action: Action::Forward,
            events,
        };
    }

    let tool_name = request_json
        .get("params")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str());

    if let Some(reason) = deny_reason(policy, tool_name) {
        let (rule, detail) = match reason {
            DenyReason::DenyList(pat) => (
                pat.clone(),
                format!("tool {:?} matches deny rule {pat:?}", tool_name.unwrap_or("")),
            ),
            DenyReason::NotAllowed => (
                tool_name.unwrap_or("<missing name>").to_owned(),
                match tool_name {
                    Some(n) => format!("tool {n:?} is not in the allow-list"),
                    None => "tools/call has no tool name under an active allow-list".to_owned(),
                },
            ),
        };
        events.push(PolicyEvent {
            kind: EventKind::PolicyDeny,
            rule,
            detail,
            tool_name: tool_name.map(str::to_owned),
        });
    }

    if policy.secret_scan {
        for hit in scan_request_arguments(request_json, &policy.custom_compiled) {
            events.push(PolicyEvent {
                kind: EventKind::SecretLeak,
                rule: hit.pattern_name,
                detail: hit.matched_preview,
                tool_name: tool_name.map(str::to_owned),
            });
        }
    }

    let action = if policy.mode == Mode::Enforce && !events.is_empty() {
        Action::Block
    } else {
        Action::Forward
    };
    RequestEvaluation { action, events }
}

/// Why a tool name is denied, if it is.
enum DenyReason {
    /// Matched a deny-list pattern (carried verbatim).
    DenyList(String),
    /// An allow-list is active and this tool is not on it (or has no name).
    NotAllowed,
}

fn deny_reason(policy: &Policy, name: Option<&str>) -> Option<DenyReason> {
    // Deny-list takes priority and only applies to a named tool.
    if let Some(n) = name {
        if let Some(pat) = policy.deny.iter().find(|pat| matches_rule(pat, n)) {
            return Some(DenyReason::DenyList(pat.clone()));
        }
    }
    // Active allow-list: an unnamed or unlisted tool is denied.
    if !policy.allow.is_empty() {
        let allowed = matches!(name, Some(n) if policy.allow.iter().any(|a| a == n));
        if !allowed {
            return Some(DenyReason::NotAllowed);
        }
    }
    None
}

/// Match a deny rule against a tool name: a trailing `*` is a prefix wildcard,
/// otherwise the comparison is exact.
fn matches_rule(pat: &str, name: &str) -> bool {
    match pat.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => name == pat,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // --- policy model + TOML loading ---------------------------------------

    #[test]
    fn default_is_monitor_with_secret_scan_on() {
        let p = Policy::default();
        assert_eq!(p.mode, Mode::Monitor);
        assert!(p.allow.is_empty());
        assert!(p.deny.is_empty());
        assert!(p.secret_scan);
        assert!(p.custom_secret_regexes().is_empty());
    }

    #[test]
    fn toml_round_trip_populates_all_fields() {
        let src = r#"
            mode = "enforce"
            allow = ["read_file", "list_dir"]
            deny = ["dangerous_*", "rm"]
            secret_scan = false
            custom_secret_patterns = ["MYCORP_[A-Z0-9]{20}"]
        "#;
        let p = Policy::from_toml_str(src).unwrap();
        assert_eq!(p.mode, Mode::Enforce);
        assert_eq!(p.allow, vec!["read_file", "list_dir"]);
        assert_eq!(p.deny, vec!["dangerous_*", "rm"]);
        assert!(!p.secret_scan);
        assert_eq!(p.custom_secret_patterns, vec!["MYCORP_[A-Z0-9]{20}"]);
        assert_eq!(p.custom_secret_regexes().len(), 1);
    }

    #[test]
    fn empty_toml_falls_back_to_defaults() {
        let p = Policy::from_toml_str("").unwrap();
        assert_eq!(p.mode, Mode::Monitor);
        assert!(p.secret_scan);
    }

    #[test]
    fn bad_toml_and_bad_custom_regex_are_errors() {
        // Malformed TOML.
        assert!(Policy::from_toml_str("mode = ").is_err());
        // Unknown key (typo guard).
        assert!(Policy::from_toml_str("deney = [\"x\"]").is_err());
        // Well-formed TOML but an invalid custom regex must fail at load.
        assert!(Policy::from_toml_str("custom_secret_patterns = [\"(\"]").is_err());
    }

    #[test]
    fn load_reads_file_and_missing_file_errors() {
        let dir = std::env::temp_dir().join(format!(
            "mcpglass-policy-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("policy.toml");
        std::fs::write(&path, "mode = \"enforce\"\n").unwrap();
        let p = Policy::load(&path).unwrap();
        assert_eq!(p.mode, Mode::Enforce);
        assert!(Policy::load(&dir.join("nope.toml")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- decision engine: allow/deny ---------------------------------------

    fn call(name: &str, args: Value) -> Value {
        json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": name, "arguments": args }
        })
    }

    #[test]
    fn monitor_deny_forwards_but_emits_event() {
        let p = Policy {
            deny: vec!["dangerous_tool".to_owned()],
            ..Policy::default()
        };
        let ev = evaluate_request(&call("dangerous_tool", json!({})), &p);
        assert_eq!(ev.action, Action::Forward);
        assert_eq!(ev.events.len(), 1);
        assert_eq!(ev.events[0].kind, EventKind::PolicyDeny);
        assert_eq!(ev.events[0].tool_name.as_deref(), Some("dangerous_tool"));
    }

    #[test]
    fn enforce_deny_blocks() {
        let p = Policy {
            mode: Mode::Enforce,
            deny: vec!["dangerous_tool".to_owned()],
            ..Policy::default()
        };
        let ev = evaluate_request(&call("dangerous_tool", json!({})), &p);
        assert_eq!(ev.action, Action::Block);
        assert_eq!(ev.events[0].rule, "dangerous_tool");
    }

    #[test]
    fn deny_wildcard_matches_prefix() {
        let p = Policy {
            mode: Mode::Enforce,
            deny: vec!["foo_*".to_owned()],
            ..Policy::default()
        };
        assert_eq!(
            evaluate_request(&call("foo_bar", json!({})), &p).action,
            Action::Block
        );
        // A name that shares no prefix is untouched.
        assert_eq!(
            evaluate_request(&call("other", json!({})), &p).action,
            Action::Forward
        );
    }

    #[test]
    fn allow_list_blocks_unlisted_allows_listed() {
        let p = Policy {
            mode: Mode::Enforce,
            allow: vec!["safe".to_owned()],
            ..Policy::default()
        };
        let blocked = evaluate_request(&call("other", json!({})), &p);
        assert_eq!(blocked.action, Action::Block);
        assert_eq!(blocked.events[0].rule, "other");

        let allowed = evaluate_request(&call("safe", json!({})), &p);
        assert_eq!(allowed.action, Action::Forward);
        assert!(allowed.events.is_empty());
    }

    #[test]
    fn deny_takes_priority_over_allow() {
        // A tool on both lists is denied.
        let p = Policy {
            mode: Mode::Enforce,
            allow: vec!["x".to_owned()],
            deny: vec!["x".to_owned()],
            ..Policy::default()
        };
        let ev = evaluate_request(&call("x", json!({})), &p);
        assert_eq!(ev.action, Action::Block);
        assert_eq!(ev.events[0].rule, "x");
    }

    // --- decision engine: malformed input ----------------------------------

    #[test]
    fn non_tools_call_forwards_without_events() {
        let p = Policy {
            mode: Mode::Enforce,
            deny: vec!["anything".to_owned()],
            ..Policy::default()
        };
        for req in [
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
            json!({"jsonrpc": "2.0", "method": "notifications/x"}),
        ] {
            let ev = evaluate_request(&req, &p);
            assert_eq!(ev.action, Action::Forward);
            assert!(ev.events.is_empty());
        }
    }

    #[test]
    fn malformed_tools_call_does_not_panic() {
        let p = Policy::default();
        // Missing params entirely.
        let a = evaluate_request(&json!({"method": "tools/call"}), &p);
        assert_eq!(a.action, Action::Forward);
        assert!(a.events.is_empty());
        // arguments present but not an object.
        let b = evaluate_request(
            &json!({"method": "tools/call", "params": {"name": "t", "arguments": "oops"}}),
            &p,
        );
        assert_eq!(b.action, Action::Forward);
        assert!(b.events.is_empty());
    }

    // --- secret scanning ----------------------------------------------------

    #[test]
    fn builtin_patterns_match_and_previews_are_masked() {
        let secrets = [
            ("aws_access_key", "AKIAIOSFODNN7EXAMPLE"),
            ("github_token", &format!("ghp_{}", "a".repeat(36))),
            ("github_pat", &format!("github_pat_{}", "b".repeat(30))),
            ("anthropic_api_key", &format!("sk-ant-api03-{}", "C".repeat(24))),
            ("openai_api_key", &format!("sk-{}", "d".repeat(24))),
            ("slack_token", "xoxb-123456789012"),
            ("google_api_key", &format!("AIza{}", "0".repeat(35))),
            ("private_key", "-----BEGIN PRIVATE KEY-----"),
            (
                "jwt",
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV",
            ),
        ];
        for (name, secret) in secrets {
            let hits = scan_secrets(secret, &[]);
            let hit = hits
                .iter()
                .find(|h| h.pattern_name == name)
                .unwrap_or_else(|| panic!("{name} did not match {secret:?}: {hits:?}"));
            // Preview never leaks the raw secret and is masked.
            assert_ne!(hit.matched_preview, *secret, "{name} preview unmasked");
            assert!(hit.matched_preview.contains('*'), "{name} not masked");
        }
    }

    #[test]
    fn mask_keeps_head_and_tail_only() {
        let hits = scan_secrets("AKIAIOSFODNN7EXAMPLE", &[]);
        let preview = &hits[0].matched_preview;
        assert!(preview.starts_with("AKIA"));
        assert!(preview.ends_with("LE"));
        assert!(!preview.contains("IOSFODNN"));
    }

    #[test]
    fn custom_pattern_matches_and_is_named_by_index() {
        let p = Policy::from_toml_str("custom_secret_patterns = [\"MYCORP_[A-Z0-9]{20}\"]").unwrap();
        let hits = scan_secrets("token MYCORP_ABCDEFGHIJ0123456789 end", p.custom_secret_regexes());
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].pattern_name, "custom[0]");
    }

    #[test]
    fn scan_only_covers_arguments_not_name_or_method() {
        // A key sitting in the tool NAME must not be scanned; only arguments are.
        let req = json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {
                "name": "AKIAIOSFODNN7EXAMPLE",
                "arguments": {
                    "note": format!("leak ghp_{}", "a".repeat(36)),
                    "nested": [format!("sk-{}", "d".repeat(24))]
                }
            }
        });
        let hits = scan_request_arguments(&req, &[]);
        let names: Vec<&str> = hits.iter().map(|h| h.pattern_name.as_str()).collect();
        assert!(names.contains(&"github_token"));
        assert!(names.contains(&"openai_api_key"));
        // The AWS key in `name` is never scanned.
        assert!(!names.contains(&"aws_access_key"), "name field was scanned: {hits:?}");
    }

    #[test]
    fn enforce_blocks_on_secret_monitor_only_flags() {
        let secret = format!("sk-{}", "d".repeat(24));
        let req = call("send", json!({ "body": secret }));

        let enforce = Policy {
            mode: Mode::Enforce,
            ..Policy::default()
        };
        let ev = evaluate_request(&req, &enforce);
        assert_eq!(ev.action, Action::Block);
        assert!(ev.events.iter().any(|e| e.kind == EventKind::SecretLeak));

        let monitor = Policy::default();
        let ev = evaluate_request(&req, &monitor);
        assert_eq!(ev.action, Action::Forward);
        assert!(ev.events.iter().any(|e| e.kind == EventKind::SecretLeak));
    }

    #[test]
    fn secret_scan_disabled_skips_scanning() {
        let secret = format!("sk-{}", "d".repeat(24));
        let p = Policy {
            mode: Mode::Enforce,
            secret_scan: false,
            ..Policy::default()
        };
        let ev = evaluate_request(&call("send", json!({ "body": secret })), &p);
        assert_eq!(ev.action, Action::Forward);
        assert!(ev.events.is_empty());
    }

    // --- fingerprinting -----------------------------------------------------

    #[test]
    fn fingerprint_is_stable_under_key_reorder() {
        let a = json!({
            "name": "read",
            "description": "reads a file",
            "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}
        });
        // Same content, keys in a different order at every level.
        let b = json!({
            "inputSchema": {"properties": {"path": {"type": "string"}}, "type": "object"},
            "description": "reads a file",
            "name": "read"
        });
        assert_eq!(fingerprint_tool(&a), fingerprint_tool(&b));
        // Extra, non-fingerprinted fields do not change it.
        let c = json!({
            "name": "read",
            "description": "reads a file",
            "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
            "annotations": {"title": "Reader"}
        });
        assert_eq!(fingerprint_tool(&a), fingerprint_tool(&c));
    }

    #[test]
    fn fingerprint_changes_when_description_changes() {
        let a = json!({"name": "read", "description": "reads", "inputSchema": {}});
        let b = json!({"name": "read", "description": "reads AND deletes", "inputSchema": {}});
        assert_ne!(fingerprint_tool(&a), fingerprint_tool(&b));
    }

    #[test]
    fn fingerprints_from_tools_list_extracts_pairs() {
        let t1 = json!({"name": "read", "description": "reads", "inputSchema": {}});
        let t2 = json!({"name": "write", "description": "writes", "inputSchema": {}});
        let resp = json!({
            "jsonrpc": "2.0", "id": 1,
            "result": {"tools": [t1.clone(), t2.clone()]}
        });
        let fps = fingerprints_from_tools_list(&resp);
        assert_eq!(fps.len(), 2);
        assert_eq!(fps[0], ("read".to_owned(), fingerprint_tool(&t1)));
        assert_eq!(fps[1], ("write".to_owned(), fingerprint_tool(&t2)));
    }

    #[test]
    fn fingerprints_from_non_tools_list_is_empty() {
        assert!(fingerprints_from_tools_list(&json!({"result": {}})).is_empty());
        assert!(fingerprints_from_tools_list(&json!({"method": "tools/call"})).is_empty());
        assert!(fingerprints_from_tools_list(&json!({"result": {"tools": "nope"}})).is_empty());
    }
}
