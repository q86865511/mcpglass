//! Fault injection: a pure, deterministic rule engine that decides whether a
//! forwarded frame should have a simulated fault applied (delay / synthesized
//! error / drop / truncate). Loaded from an independent TOML file (`--inject`),
//! never enabled by default.
//!
//! # Purity and the fail-open contract
//!
//! This module mirrors the discipline of the policy engine next door: the only
//! IO is [`InjectConfig::load`] reading the file at startup; [`Injector::decide`]
//! is a pure function of the injector's own state (its per-rule counters and RNG),
//! doing no IO and taking no locks. The caller runs `decide` off the wire the same
//! way it runs `evaluate_request`.
//!
//! Injection is **not** a fail-open violation. A fault only ever fires because the
//! user explicitly asked for it with `--inject`; like `enforce`-mode policy blocks,
//! it is a deliberate, in-protocol intervention, not a proxy bug corrupting
//! traffic. The fail-open rule still governs the *machinery*: the caller treats any
//! injector lock-poisoning or panic as "no injection" and forwards normally, and a
//! failed `inject_events` write never changes what is on the wire. With no
//! `--inject`, there is no injector at all and not a single extra byte is parsed.
//!
//! # TOML shape
//!
//! ```toml
//! seed = 42                       # optional u64; fixes the RNG for reproducible runs
//!
//! [[rules]]
//! direction = "c2s"               # "c2s" (client->server) | "s2c" (server->client)
//! method = "tools/*"              # optional; trailing `*` = prefix wildcard (as in policy deny)
//! probability = 0.5               # optional, default 1.0; must be in [0, 1]
//! max_triggers = 3                # optional; stop firing this rule after N hits
//! fault = { type = "delay", delay_ms = 200 }
//!
//! [[rules]]
//! direction = "s2c"
//! fault = { type = "error", code = -32000, message = "injected failure" }
//! # other faults: { type = "drop" } | { type = "truncate", bytes = 16 }
//! ```

use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::matches_rule;

/// Which leg a rule targets. Kept as an injection-owned type (rather than reusing
/// `proxy_core::Direction`) so the `policy` crate stays free of a `proxy-core`
/// dependency; the CLI maps it to the storage direction at the recording site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InjectDirection {
    /// client -> server.
    C2s,
    /// server -> client.
    S2c,
}

/// The fault a matched rule injects. Internally tagged on `type` so the TOML reads
/// `fault = { type = "delay", delay_ms = 200 }`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Fault {
    /// Sleep `delay_ms` before forwarding the frame unchanged.
    Delay { delay_ms: u64 },
    /// Withhold the frame and answer with a synthesized JSON-RPC error instead.
    Error { code: i64, message: String },
    /// Withhold the frame entirely (no forward, no synthesized reply).
    Drop,
    /// Forward only the first `bytes` bytes of the frame (a deliberately corrupt,
    /// truncated frame) so the peer sees a broken message.
    Truncate { bytes: usize },
}

/// A decision that a fault should be applied to the current frame: which rule fired
/// (for logging / the `inject_events` row) and what to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectHit {
    /// Stable label of the rule that fired, e.g. `rules[0]`.
    pub rule_label: String,
    pub fault: Fault,
}

/// TOML shape of the whole file. `deny_unknown_fields` catches typos, exactly as the
/// policy loader does — a mistyped key silently disabling a rule is not acceptable
/// for a testing tool whose whole job is to be predictable.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InjectToml {
    #[serde(default)]
    seed: Option<u64>,
    #[serde(default)]
    rules: Vec<RuleToml>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleToml {
    direction: InjectDirection,
    /// Optional method filter; absent means "every method on this direction". A
    /// trailing `*` is a prefix wildcard, reusing the policy deny-list semantics.
    #[serde(default)]
    method: Option<String>,
    #[serde(default = "default_probability")]
    probability: f64,
    #[serde(default)]
    max_triggers: Option<u64>,
    fault: Fault,
}

fn default_probability() -> f64 {
    1.0
}

/// A compiled rule (validated at load; `probability` is guaranteed in `[0, 1]`).
#[derive(Debug, Clone)]
struct Rule {
    label: String,
    direction: InjectDirection,
    method: Option<String>,
    probability: f64,
    max_triggers: Option<u64>,
    fault: Fault,
}

impl Rule {
    /// Whether this rule's `method` filter accepts `method` (the frame's method, if
    /// any). An absent filter matches everything; a present filter matches by the
    /// shared trailing-`*` wildcard. A rule with a method filter never matches a
    /// frame that has no method (e.g. a response or non-JSON line).
    fn method_matches(&self, method: Option<&str>) -> bool {
        match &self.method {
            None => true,
            Some(pat) => matches!(method, Some(m) if matches_rule(pat, m)),
        }
    }
}

/// A loaded, validated injection configuration. Build an [`Injector`] from it.
#[derive(Debug, Clone)]
pub struct InjectConfig {
    seed: Option<u64>,
    rules: Vec<Rule>,
}

impl InjectConfig {
    /// Parse and validate an injection config from a TOML string. A `probability`
    /// outside `[0, 1]` is a load-time error (fail loud here, never silently clamp).
    pub fn from_toml_str(s: &str) -> Result<Self> {
        let raw: InjectToml = toml::from_str(s).context("parsing inject TOML")?;
        let mut rules = Vec::with_capacity(raw.rules.len());
        for (i, r) in raw.rules.into_iter().enumerate() {
            if !(0.0..=1.0).contains(&r.probability) {
                bail!(
                    "inject rule {i}: probability {} is out of range [0, 1]",
                    r.probability
                );
            }
            rules.push(Rule {
                label: format!("rules[{i}]"),
                direction: r.direction,
                method: r.method,
                probability: r.probability,
                max_triggers: r.max_triggers,
                fault: r.fault,
            });
        }
        Ok(Self {
            seed: raw.seed,
            rules,
        })
    }

    /// Read and parse an injection file. A missing/unreadable file is an error, so
    /// the caller can abort startup before forwarding any byte.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading inject file {}", path.display()))?;
        Self::from_toml_str(&text)
    }

    /// Number of loaded rules (for callers that want to log a summary).
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

/// A running injector: the compiled rules plus the mutable state `decide` needs
/// (per-rule trigger counters and the RNG). Not `Sync`; the CLI shares one behind a
/// `Mutex` so both pumps advance the same counters and RNG.
#[derive(Debug)]
pub struct Injector {
    rules: Vec<Rule>,
    /// Per-rule trigger count, parallel to `rules`.
    counts: Vec<u64>,
    rng: XorShift64Star,
}

impl Injector {
    /// Build an injector from a loaded config. A `seed` fixes the RNG for
    /// reproducible runs; without one, the RNG is seeded from the clock so separate
    /// runs vary. Construction reads the clock at most once (only when unseeded);
    /// [`decide`](Self::decide) itself is pure.
    pub fn new(cfg: InjectConfig) -> Self {
        let seed = cfg.seed.unwrap_or_else(entropy_seed);
        let counts = vec![0u64; cfg.rules.len()];
        Self {
            rules: cfg.rules,
            counts,
            rng: XorShift64Star::new(seed),
        }
    }

    /// Decide whether to inject a fault into a frame travelling in `dir` with the
    /// given `method` (parsed by the caller; `None` for a response, a notification
    /// with no method, or a non-JSON frame).
    ///
    /// Rules are considered in file order. A rule is *eligible* when its direction
    /// matches, its method filter accepts `method`, and it is not exhausted
    /// (`max_triggers`). The first eligible rule rolls its `probability`; on a hit
    /// its counter is incremented and its fault returned, on a miss evaluation falls
    /// through to the next eligible rule. `probability = 1.0` (the default) always
    /// fires and draws no random number, so a config of only certain rules never
    /// touches the RNG and stays trivially reproducible.
    ///
    /// Pure: it mutates only `self` (counters, RNG) and performs no IO.
    pub fn decide(&mut self, dir: InjectDirection, method: Option<&str>) -> Option<InjectHit> {
        for (i, rule) in self.rules.iter().enumerate() {
            if rule.direction != dir || !rule.method_matches(method) {
                continue;
            }
            if let Some(max) = rule.max_triggers {
                if self.counts[i] >= max {
                    // Exhausted: transparent, so a later rule can still match.
                    continue;
                }
            }
            // This rule is eligible. Roll its probability (certain rules skip the RNG).
            if rule.probability < 1.0 && self.rng.next_f64() >= rule.probability {
                continue; // rolled a miss; let a later rule try.
            }
            self.counts[i] += 1;
            return Some(InjectHit {
                rule_label: rule.label.clone(),
                fault: rule.fault.clone(),
            });
        }
        None
    }
}

/// A small, dependency-free PRNG (xorshift64*). Good enough to gate probabilistic
/// injection and, crucially, exactly reproducible from a seed — the property the
/// deterministic tests rely on. Not for cryptographic use.
#[derive(Debug, Clone)]
struct XorShift64Star {
    state: u64,
}

impl XorShift64Star {
    /// Seed the generator. xorshift requires a non-zero state, so a zero seed is
    /// mapped to a fixed non-zero constant.
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// A uniform draw in `[0, 1)` using the top 53 bits (f64 mantissa width).
    fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// A clock-derived seed for the unseeded case, mixed so a coarse clock still varies.
fn entropy_seed() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    nanos ^ (nanos << 17) ^ 0x9E37_79B9_7F4A_7C15
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- TOML parsing / validation -----------------------------------------

    #[test]
    fn parses_full_config_and_all_fault_shapes() {
        let src = r#"
            seed = 7

            [[rules]]
            direction = "c2s"
            method = "tools/call"
            probability = 0.25
            max_triggers = 3
            fault = { type = "delay", delay_ms = 150 }

            [[rules]]
            direction = "s2c"
            fault = { type = "error", code = -32000, message = "boom" }

            [[rules]]
            direction = "c2s"
            fault = { type = "drop" }

            [[rules]]
            direction = "s2c"
            method = "tools/*"
            fault = { type = "truncate", bytes = 8 }
        "#;
        let cfg = InjectConfig::from_toml_str(src).unwrap();
        assert_eq!(cfg.seed, Some(7));
        assert_eq!(cfg.rules.len(), 4);

        assert_eq!(cfg.rules[0].direction, InjectDirection::C2s);
        assert_eq!(cfg.rules[0].method.as_deref(), Some("tools/call"));
        assert_eq!(cfg.rules[0].probability, 0.25);
        assert_eq!(cfg.rules[0].max_triggers, Some(3));
        assert_eq!(cfg.rules[0].fault, Fault::Delay { delay_ms: 150 });
        assert_eq!(cfg.rules[0].label, "rules[0]");

        assert_eq!(
            cfg.rules[1].fault,
            Fault::Error {
                code: -32000,
                message: "boom".to_owned()
            }
        );
        // Defaults: no method filter, probability 1.0, no cap.
        assert_eq!(cfg.rules[1].method, None);
        assert_eq!(cfg.rules[1].probability, 1.0);
        assert_eq!(cfg.rules[1].max_triggers, None);

        assert_eq!(cfg.rules[2].fault, Fault::Drop);
        assert_eq!(cfg.rules[3].fault, Fault::Truncate { bytes: 8 });
    }

    #[test]
    fn empty_config_is_valid_and_injects_nothing() {
        let cfg = InjectConfig::from_toml_str("").unwrap();
        assert_eq!(cfg.rule_count(), 0);
        let mut inj = Injector::new(cfg);
        assert_eq!(inj.decide(InjectDirection::C2s, Some("tools/call")), None);
    }

    #[test]
    fn unknown_field_is_rejected() {
        // Top-level typo.
        assert!(InjectConfig::from_toml_str("sed = 1\n").is_err());
        // Rule-level typo (probabilty vs probability).
        let src = r#"
            [[rules]]
            direction = "c2s"
            probabilty = 0.5
            fault = { type = "drop" }
        "#;
        assert!(InjectConfig::from_toml_str(src).is_err());
    }

    #[test]
    fn probability_out_of_range_is_rejected() {
        for bad in ["1.5", "-0.1"] {
            let src = format!(
                "[[rules]]\ndirection=\"c2s\"\nprobability={bad}\nfault={{ type=\"drop\" }}\n"
            );
            assert!(
                InjectConfig::from_toml_str(&src).is_err(),
                "probability {bad} must be rejected"
            );
        }
        // The boundaries are accepted.
        for ok in ["0.0", "1.0"] {
            let src =
                format!("[[rules]]\ndirection=\"c2s\"\nprobability={ok}\nfault={{ type=\"drop\" }}\n");
            assert!(InjectConfig::from_toml_str(&src).is_ok());
        }
    }

    #[test]
    fn malformed_toml_is_error() {
        assert!(InjectConfig::from_toml_str("[[rules]]\ndirection = ").is_err());
        // A rule missing its required `fault` is an error.
        assert!(InjectConfig::from_toml_str("[[rules]]\ndirection = \"c2s\"\n").is_err());
        // An unknown direction value is an error.
        assert!(
            InjectConfig::from_toml_str("[[rules]]\ndirection=\"sideways\"\nfault={type=\"drop\"}\n")
                .is_err()
        );
    }

    // --- decide: matching, direction, wildcard ------------------------------

    fn cfg(src: &str) -> InjectConfig {
        InjectConfig::from_toml_str(src).unwrap()
    }

    #[test]
    fn direction_and_method_gate_matching() {
        let mut inj = Injector::new(cfg(r#"
            [[rules]]
            direction = "c2s"
            method = "tools/call"
            fault = { type = "drop" }
        "#));
        // Right direction + method -> hit.
        assert_eq!(
            inj.decide(InjectDirection::C2s, Some("tools/call")),
            Some(InjectHit {
                rule_label: "rules[0]".to_owned(),
                fault: Fault::Drop
            })
        );
        // Wrong direction -> no hit.
        assert_eq!(inj.decide(InjectDirection::S2c, Some("tools/call")), None);
        // Wrong method -> no hit.
        assert_eq!(inj.decide(InjectDirection::C2s, Some("resources/list")), None);
        // No method at all, but the rule requires one -> no hit.
        assert_eq!(inj.decide(InjectDirection::C2s, None), None);
    }

    #[test]
    fn trailing_star_is_a_prefix_wildcard() {
        let mut inj = Injector::new(cfg(r#"
            [[rules]]
            direction = "c2s"
            method = "tools/*"
            fault = { type = "drop" }
        "#));
        assert!(inj.decide(InjectDirection::C2s, Some("tools/call")).is_some());
        assert!(inj.decide(InjectDirection::C2s, Some("tools/list")).is_some());
        assert!(inj.decide(InjectDirection::C2s, Some("resources/read")).is_none());
    }

    #[test]
    fn absent_method_filter_matches_any_method_and_none() {
        let mut inj = Injector::new(cfg(r#"
            [[rules]]
            direction = "s2c"
            fault = { type = "drop" }
        "#));
        assert!(inj.decide(InjectDirection::S2c, Some("anything")).is_some());
        // A response (no method) still matches a filter-less rule.
        assert!(inj.decide(InjectDirection::S2c, None).is_some());
    }

    // --- decide: determinism, probability, max_triggers ---------------------

    #[test]
    fn certain_rule_always_fires_without_touching_rng() {
        let mut inj = Injector::new(cfg(r#"
            [[rules]]
            direction = "c2s"
            fault = { type = "drop" }
        "#));
        for _ in 0..100 {
            assert!(inj.decide(InjectDirection::C2s, Some("m")).is_some());
        }
    }

    #[test]
    fn probability_zero_never_fires() {
        let mut inj = Injector::new(cfg(r#"
            seed = 1
            [[rules]]
            direction = "c2s"
            probability = 0.0
            fault = { type = "drop" }
        "#));
        for _ in 0..100 {
            assert!(inj.decide(InjectDirection::C2s, Some("m")).is_none());
        }
    }

    /// The decide sequence is a pure function of (seed, config): two injectors built
    /// from the same seeded config produce byte-identical hit/miss sequences.
    #[test]
    fn fixed_seed_gives_a_deterministic_sequence() {
        let src = r#"
            seed = 0xABCDEF
            [[rules]]
            direction = "c2s"
            probability = 0.5
            fault = { type = "drop" }
        "#;
        let seq = |cfg: InjectConfig| -> Vec<bool> {
            let mut inj = Injector::new(cfg);
            (0..64)
                .map(|_| inj.decide(InjectDirection::C2s, Some("m")).is_some())
                .collect()
        };
        let a = seq(cfg(src));
        let b = seq(cfg(src));
        assert_eq!(a, b, "same seed must yield the same sequence");
        // A 0.5 probability must actually gate: the sequence has both hits and misses.
        assert!(a.iter().any(|&x| x), "expected at least one hit");
        assert!(a.iter().any(|&x| !x), "expected at least one miss");
    }

    #[test]
    fn max_triggers_stops_the_rule_after_n_hits() {
        let mut inj = Injector::new(cfg(r#"
            [[rules]]
            direction = "c2s"
            max_triggers = 2
            fault = { type = "error", code = -1, message = "x" }
        "#));
        assert!(inj.decide(InjectDirection::C2s, Some("m")).is_some());
        assert!(inj.decide(InjectDirection::C2s, Some("m")).is_some());
        // Third call: the rule is exhausted.
        assert!(inj.decide(InjectDirection::C2s, Some("m")).is_none());
        assert!(inj.decide(InjectDirection::C2s, Some("m")).is_none());
    }

    #[test]
    fn first_eligible_rule_wins_and_exhausted_rules_fall_through() {
        // Two c2s rules on the same method: the first is capped at one hit, then the
        // second takes over.
        let mut inj = Injector::new(cfg(r#"
            [[rules]]
            direction = "c2s"
            max_triggers = 1
            fault = { type = "drop" }

            [[rules]]
            direction = "c2s"
            fault = { type = "error", code = -2, message = "second" }
        "#));
        // First call -> rule 0 (drop).
        assert_eq!(inj.decide(InjectDirection::C2s, Some("m")).unwrap().fault, Fault::Drop);
        // Rule 0 now exhausted -> rule 1 (error) claims subsequent frames.
        assert_eq!(
            inj.decide(InjectDirection::C2s, Some("m")).unwrap().fault,
            Fault::Error { code: -2, message: "second".to_owned() }
        );
    }
}
