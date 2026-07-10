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

pub mod inject;
pub use inject::{Fault, InjectConfig, InjectDirection, InjectHit, Injector};

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

/// Mask every built-in secret occurrence in `text`, replacing each match in place with
/// its masked preview (the same head/tail masking [`scan_secrets`] uses for security
/// events). Pure and self-contained — it compiles no regex on the call path and needs
/// no policy — so a diagnostics exporter can mask a whole recorded frame (or an argv
/// token) before it leaves the machine. Only the built-in patterns are applied; to also
/// honor a policy's `custom_secret_patterns`, use [`Policy::mask_secrets`]. Applying the
/// patterns in sequence is safe: a masked span contains `*`, which no built-in shape
/// re-matches, so passes never compound.
pub fn mask_secrets(text: &str) -> String {
    mask_secrets_impl(text, &[])
}

fn mask_secrets_impl(text: &str, custom: &[Regex]) -> String {
    let mut out = text.to_owned();
    for (_, re) in builtin_patterns() {
        out = re
            .replace_all(&out, |caps: &regex::Captures| mask(&caps[0]))
            .into_owned();
    }
    // Custom patterns run after the built-ins. A user regex could in principle match
    // an already-masked span, which only masks harder — it can never un-mask.
    for re in custom {
        out = re
            .replace_all(&out, |caps: &regex::Captures| mask(&caps[0]))
            .into_owned();
    }
    out
}

impl Policy {
    /// [`mask_secrets`], but also applying this policy's compiled
    /// `custom_secret_patterns` — so an export masked under the same policy the proxy
    /// ran with hides exactly what the live secret scan would have flagged.
    pub fn mask_secrets(&self, text: &str) -> String {
        mask_secrets_impl(text, &self.custom_compiled)
    }
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

/// Current tool-fingerprint algorithm version. v1 hashed `name` + `description` +
/// `inputSchema`; **v2** additionally folds in `annotations` (missing -> Null), so
/// a server that quietly rewrites a tool's advertised annotations is caught;
/// **v3** additionally folds in `outputSchema` (missing -> Null, the MCP 2025-06-18
/// field describing a tool's structured result), so a server that quietly rewrites
/// the *shape of the result* a tool promises — a behavioural contract, and a real
/// rug-pull surface — is now caught too. Storage records new observations under this
/// version and uses the older hashes only to recognise a pre-existing v1/v2 row
/// during the dual-hash migration.
///
/// `icons` (the MCP 2025-11-25 field) is deliberately *not* folded in: icon `src`
/// values are frequently remote URLs that change for benign reasons (CDN rotation,
/// cache-busting), so fingerprinting them would be a high false-positive rate. It is
/// on the watch list for a future v4 once its real-world churn is understood.
pub const FP_VERSION: u32 = 3;

/// A tool definition hashed under every fingerprint algorithm version at once.
/// Storage needs all versions to compare an observation against history that may
/// have been recorded under an older algorithm: an existing v1/v2 record that still
/// matches on its own version's hash is silently re-pinned to `v3` (no change alert),
/// while a mismatch on that hash is a genuine change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolFingerprints {
    /// v1 hash: `name` + `description` + `inputSchema`.
    pub v1: String,
    /// v2 hash: the v1 fields plus `annotations` (missing -> Null).
    pub v2: String,
    /// v3 hash: the v2 fields plus `outputSchema` (missing -> Null).
    pub v3: String,
}

/// The v1 canonical subset — the fields the v1 algorithm fingerprints over.
fn fingerprint_subset_v1(tool: &Value) -> Value {
    serde_json::json!({
        "name": tool.get("name").cloned().unwrap_or(Value::Null),
        "description": tool.get("description").cloned().unwrap_or(Value::Null),
        "inputSchema": tool.get("inputSchema").cloned().unwrap_or(Value::Null),
    })
}

/// The v2 canonical subset — v1 plus `annotations` (missing -> Null).
fn fingerprint_subset_v2(tool: &Value) -> Value {
    let mut subset = fingerprint_subset_v1(tool);
    // `subset` is always a JSON object here, so this inserts the key.
    subset["annotations"] = tool.get("annotations").cloned().unwrap_or(Value::Null);
    subset
}

/// The v3 canonical subset — v2 plus `outputSchema` (missing -> Null, the same
/// convention v2 uses for `annotations`). `icons` is intentionally excluded (see
/// [`FP_VERSION`]).
fn fingerprint_subset_v3(tool: &Value) -> Value {
    let mut subset = fingerprint_subset_v2(tool);
    subset["outputSchema"] = tool.get("outputSchema").cloned().unwrap_or(Value::Null);
    subset
}

/// SHA-256 over the canonical (recursively key-sorted) JSON of `subset`.
fn hash_subset(subset: &Value) -> String {
    let mut canonical = String::new();
    write_canonical(subset, &mut canonical);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    to_hex(&hasher.finalize())
}

/// Stable **v1** fingerprint of a single tool definition: SHA-256 over a canonical
/// (recursively key-sorted) JSON of just `name` + `description` + `inputSchema`.
/// Extra fields a server may add (annotations, etc.) do not affect it. Retained as
/// the v1 hash for the dual-hash migration; new recordings pin to v2 (see
/// [`fingerprint_tool_versions`]).
pub fn fingerprint_tool(tool: &Value) -> String {
    hash_subset(&fingerprint_subset_v1(tool))
}

/// Fingerprint a tool under every algorithm version at once (see [`ToolFingerprints`]).
pub fn fingerprint_tool_versions(tool: &Value) -> ToolFingerprints {
    ToolFingerprints {
        v1: hash_subset(&fingerprint_subset_v1(tool)),
        v2: hash_subset(&fingerprint_subset_v2(tool)),
        v3: hash_subset(&fingerprint_subset_v3(tool)),
    }
}

/// Extract `(tool name, v1 fingerprint)` for every tool in a `tools/list` response
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

/// Like [`fingerprints_from_tools_list`], but yields both fingerprint versions per
/// tool for the dual-hash migration. Same shape contract: a non-tools/list or
/// malformed response yields an empty vec, nameless tools are skipped.
pub fn fingerprints_from_tools_list_versioned(
    response_json: &Value,
) -> Vec<(String, ToolFingerprints)> {
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
            Some((name.to_owned(), fingerprint_tool_versions(tool)))
        })
        .collect()
}

/// A server's stable identity, hashed into the `server_id` that scopes rug-pull
/// detection across sessions. Structured on purpose: two runs of the *same* program
/// with *different* argv (e.g. the same launcher pointed at different projects) are
/// distinct identities, and an argv token that contains whitespace, quotes, or
/// backslashes survives verbatim (unlike the pre-v7 `argv.join(" ")` heuristic).
///
/// There is deliberately **no** `env` field: environment is excluded from identity by
/// construction, so it can never leak into the hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerIdentity {
    /// A spawned stdio server, identified by its full argv (`argv[0]` is the program).
    Stdio { argv: Vec<String> },
    /// An HTTP (Streamable HTTP) upstream, identified by its URL verbatim.
    Http { url: String },
}

impl ServerIdentity {
    /// The on-disk `transport` token: `"stdio"` or `"http"`.
    pub fn transport(&self) -> &'static str {
        match self {
            ServerIdentity::Stdio { .. } => "stdio",
            ServerIdentity::Http { .. } => "http",
        }
    }

    /// The program (`argv[0]`) for an stdio identity; `None` for HTTP (or an empty argv).
    pub fn program(&self) -> Option<&str> {
        match self {
            ServerIdentity::Stdio { argv } => argv.first().map(String::as_str),
            ServerIdentity::Http { .. } => None,
        }
    }
}

/// SHA-256 over the canonical JSON of a server's structured identity — the `server_id`
/// that scopes tool-fingerprint history. Pure and deterministic: the same identity
/// always hashes to the same value, and the canonical (key-sorted) form makes it
/// independent of field order.
///
/// * stdio → `{"transport":"stdio","program":argv[0],"argv":[...]}` (`program` is Null
///   when argv is empty).
/// * http → `{"transport":"http","url":"<url verbatim>"}` — the URL is **not**
///   normalised: any normalisation rule could change over time and silently re-key an
///   established baseline, so the raw string is the stable choice.
pub fn server_identity_hash(identity: &ServerIdentity) -> String {
    let subset = match identity {
        ServerIdentity::Stdio { argv } => serde_json::json!({
            "transport": "stdio",
            "program": argv.first().cloned().map(Value::String).unwrap_or(Value::Null),
            "argv": argv,
        }),
        ServerIdentity::Http { url } => serde_json::json!({
            "transport": "http",
            "url": url,
        }),
    };
    hash_subset(&subset)
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
/// otherwise the comparison is exact. Shared with the fault-injection layer
/// ([`inject`]), which reuses the exact same wildcard semantics for its
/// `method` filter.
pub(crate) fn matches_rule(pat: &str, name: &str) -> bool {
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
    fn mask_secrets_masks_builtins_in_place_and_leaves_plain_text() {
        // An AWS key embedded in free text is masked (head/tail kept, middle starred),
        // and the surrounding text is preserved.
        let masked = mask_secrets("here is AKIAIOSFODNN7EXAMPLE in the log");
        assert!(masked.starts_with("here is AKIA"));
        assert!(masked.ends_with("in the log"));
        assert!(!masked.contains("AKIAIOSFODNN7EXAMPLE"), "raw key must not survive: {masked}");
        assert!(masked.contains('*'));

        // Multiple different secrets in one string are all masked.
        let both = mask_secrets(&format!("k1 sk-{} k2 ghp_{}", "d".repeat(24), "a".repeat(36)));
        assert!(!both.contains(&"d".repeat(24)));
        assert!(!both.contains(&"a".repeat(36)));

        // Plain text with no secret is returned unchanged.
        assert_eq!(mask_secrets("nothing secret here"), "nothing secret here");
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

    // --- v2 fingerprinting (annotations) ------------------------------------

    #[test]
    fn fingerprint_v2_folds_in_annotations_v1_ignores_them() {
        let base = json!({"name": "read", "description": "reads", "inputSchema": {}});
        let annotated = json!({
            "name": "read", "description": "reads", "inputSchema": {},
            "annotations": {"title": "Reader", "readOnlyHint": true}
        });
        let a = fingerprint_tool_versions(&base);
        let b = fingerprint_tool_versions(&annotated);
        // v1 is blind to annotations...
        assert_eq!(a.v1, b.v1);
        // ...but v2 folds them in, so adding annotations changes it.
        assert_ne!(a.v2, b.v2);
        // The public v1 helper still equals the v1 field.
        assert_eq!(b.v1, fingerprint_tool(&annotated));
    }

    #[test]
    fn fingerprint_v2_changes_when_annotations_change_v1_does_not() {
        let x = json!({"name": "t", "description": "d", "inputSchema": {}, "annotations": {"title": "A"}});
        let y = json!({"name": "t", "description": "d", "inputSchema": {}, "annotations": {"title": "B"}});
        let fx = fingerprint_tool_versions(&x);
        let fy = fingerprint_tool_versions(&y);
        assert_eq!(fx.v1, fy.v1); // v1 does not see the annotation edit
        assert_ne!(fx.v2, fy.v2); // v2 catches it
    }

    #[test]
    fn fingerprint_v2_missing_annotations_is_stable_under_reorder() {
        // Missing annotations hash as Null, so two annotation-less tools with keys
        // in a different order still agree on v2.
        let a = json!({"name": "t", "description": "d", "inputSchema": {"type": "object"}});
        let b = json!({"inputSchema": {"type": "object"}, "description": "d", "name": "t"});
        assert_eq!(
            fingerprint_tool_versions(&a).v2,
            fingerprint_tool_versions(&b).v2
        );
    }

    #[test]
    fn fingerprints_from_tools_list_versioned_extracts_both_versions() {
        let t1 = json!({"name": "read", "description": "r", "inputSchema": {}, "annotations": {"x": 1}});
        let resp = json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [t1.clone()]}});
        let fps = fingerprints_from_tools_list_versioned(&resp);
        assert_eq!(fps.len(), 1);
        assert_eq!(fps[0].0, "read");
        assert_eq!(fps[0].1, fingerprint_tool_versions(&t1));
        // Non-tools/list is empty, mirroring the v1 extractor.
        assert!(fingerprints_from_tools_list_versioned(&json!({"result": {}})).is_empty());
        assert!(
            fingerprints_from_tools_list_versioned(&json!({"result": {"tools": "nope"}})).is_empty()
        );
    }

    // --- server identity (WF5) ----------------------------------------------

    #[test]
    fn server_identity_hash_is_deterministic_and_field_sensitive() {
        // The same identity always hashes to the same value (canonical, order-free).
        let a = ServerIdentity::Stdio {
            argv: vec!["npx".to_owned(), "-y".to_owned(), "server".to_owned()],
        };
        let b = ServerIdentity::Stdio {
            argv: vec!["npx".to_owned(), "-y".to_owned(), "server".to_owned()],
        };
        assert_eq!(server_identity_hash(&a), server_identity_hash(&b));

        // Same program, different later argv (e.g. a launcher pointed at a different
        // project) is a DISTINCT identity — the whole argv participates, not just argv[0].
        let other_project = ServerIdentity::Stdio {
            argv: vec!["npx".to_owned(), "-y".to_owned(), "server-other".to_owned()],
        };
        assert_ne!(server_identity_hash(&a), server_identity_hash(&other_project));

        // The accessors expose the program and transport.
        assert_eq!(a.program(), Some("npx"));
        assert_eq!(a.transport(), "stdio");
    }

    #[test]
    fn server_identity_hash_http_is_url_stable_and_distinct_from_stdio() {
        let u1 = ServerIdentity::Http {
            url: "http://127.0.0.1:9000/u/x".to_owned(),
        };
        let u1_again = ServerIdentity::Http {
            url: "http://127.0.0.1:9000/u/x".to_owned(),
        };
        let u2 = ServerIdentity::Http {
            url: "http://127.0.0.1:9000/u/y".to_owned(),
        };
        // Same URL -> same server_id; a different URL -> a different one.
        assert_eq!(server_identity_hash(&u1), server_identity_hash(&u1_again));
        assert_ne!(server_identity_hash(&u1), server_identity_hash(&u2));
        assert_eq!(u1.transport(), "http");
        assert_eq!(u1.program(), None);

        // A stdio identity whose argv happens to render like the URL is still a
        // different hash — transport is part of the canonical subset. (This is also a
        // documentary check that `ServerIdentity` has no `env` variant field, so an
        // environment value cannot enter the hash: it is unrepresentable by type.)
        let stdio_lookalike = ServerIdentity::Stdio {
            argv: vec!["http://127.0.0.1:9000/u/x".to_owned()],
        };
        assert_ne!(
            server_identity_hash(&u1),
            server_identity_hash(&stdio_lookalike)
        );
    }

    // --- v3 fingerprinting (outputSchema) -----------------------------------

    #[test]
    fn fingerprint_v3_folds_in_output_schema_v1_v2_ignore_it() {
        let base = json!({"name": "read", "description": "reads", "inputSchema": {}});
        let with_output = json!({
            "name": "read", "description": "reads", "inputSchema": {},
            "outputSchema": {"type": "object", "properties": {"content": {"type": "string"}}}
        });
        let a = fingerprint_tool_versions(&base);
        let b = fingerprint_tool_versions(&with_output);
        // v1 and v2 are blind to outputSchema...
        assert_eq!(a.v1, b.v1);
        assert_eq!(a.v2, b.v2);
        // ...but v3 folds it in, so adding an outputSchema changes it.
        assert_ne!(a.v3, b.v3);
    }

    #[test]
    fn fingerprint_v3_changes_when_output_schema_changes_v2_does_not() {
        let x = json!({"name": "t", "description": "d", "inputSchema": {}, "outputSchema": {"type": "string"}});
        let y = json!({"name": "t", "description": "d", "inputSchema": {}, "outputSchema": {"type": "number"}});
        let fx = fingerprint_tool_versions(&x);
        let fy = fingerprint_tool_versions(&y);
        assert_eq!(fx.v2, fy.v2); // v2 does not see the outputSchema edit
        assert_ne!(fx.v3, fy.v3); // v3 catches it
    }

    #[test]
    fn fingerprint_v3_missing_output_schema_is_stable_under_reorder() {
        // Missing outputSchema hashes as Null, so two outputSchema-less tools with
        // keys in a different order still agree on v3.
        let a = json!({"name": "t", "description": "d", "inputSchema": {"type": "object"}, "annotations": {"x": 1}});
        let b = json!({"annotations": {"x": 1}, "inputSchema": {"type": "object"}, "description": "d", "name": "t"});
        assert_eq!(
            fingerprint_tool_versions(&a).v3,
            fingerprint_tool_versions(&b).v3
        );
    }

    #[test]
    fn fingerprint_v3_ignores_icons() {
        // `icons` (MCP 2025-11-25) is deliberately excluded from every version, so a
        // tool that only adds/rotates icons has an unchanged v3 fingerprint.
        let plain = json!({"name": "t", "description": "d", "inputSchema": {}, "outputSchema": {"type": "object"}});
        let iconed = json!({
            "name": "t", "description": "d", "inputSchema": {}, "outputSchema": {"type": "object"},
            "icons": [{"src": "https://cdn.example/icon-v2.png", "mimeType": "image/png", "sizes": ["48x48"]}]
        });
        assert_eq!(
            fingerprint_tool_versions(&plain).v3,
            fingerprint_tool_versions(&iconed).v3
        );
    }
}
