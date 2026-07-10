//! Micro-benchmarks for the two pure hot paths in `policy`:
//!
//! * [`evaluate_request`] — the synchronous c2s decision made on every `tools/call`
//!   before the frame is forwarded. It is the one policy computation that sits *on*
//!   the forwarding path (the gate can block), so its cost is a wire-latency floor.
//!   Benched in monitor and enforce mode, each with a deny hit and a miss.
//! * [`fingerprints_from_tools_list_versioned`] — the triple SHA-256 (v1/v2/v3) taken
//!   per advertised tool on the s2c leg. It runs on the storage thread (off the wire),
//!   so this measures the recording-side cost of rug-pull fingerprinting.
//!
//! Run with `cargo bench -p policy`. See docs/benchmarks.md for methodology.

use criterion::{criterion_group, criterion_main, Criterion};
use policy::{
    evaluate_request, fingerprint_tool_versions, fingerprints_from_tools_list_versioned, Policy,
};
use serde_json::{json, Value};
use std::hint::black_box;

/// Build a `tools/call` request for `name` carrying a small, secret-free argument
/// object (so `secret_scan` runs to completion without matching).
fn tools_call(name: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": { "query": "quarterly revenue report", "limit": 25 }
        }
    })
}

/// A mid-sized `tools/list` response: eight tools with realistic schemas.
fn tools_list_response() -> Value {
    let tool = |name: &str, desc: &str| {
        json!({
            "name": name,
            "description": desc,
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "the search text" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 100 },
                    "cursor": { "type": "string" }
                },
                "required": ["query"]
            },
            "annotations": { "readOnlyHint": true },
            "outputSchema": {
                "type": "object",
                "properties": { "results": { "type": "array" } }
            }
        })
    };
    json!({
        "jsonrpc": "2.0",
        "id": 7,
        "result": {
            "tools": [
                tool("search", "Full-text search over the corpus"),
                tool("fetch", "Fetch a document by URL"),
                tool("list", "List available documents"),
                tool("create", "Create a new document"),
                tool("update", "Update an existing document"),
                tool("delete", "Delete a document"),
                tool("summarize", "Summarize a document"),
                tool("translate", "Translate a document")
            ]
        }
    })
}

fn bench_evaluate_request(c: &mut Criterion) {
    // A deny rule plus secret scanning, in each mode. `deny_unknown_fields` in the
    // policy loader means these strings must be exactly the supported keys.
    let monitor = Policy::from_toml_str("mode = 'monitor'\ndeny = ['dangerous_*']\nsecret_scan = true")
        .expect("monitor policy");
    let enforce = Policy::from_toml_str("mode = 'enforce'\ndeny = ['dangerous_*']\nsecret_scan = true")
        .expect("enforce policy");

    // Miss: the tool is not denied and the arguments carry no secret -> Forward, but
    // the full deny scan + secret scan still runs (the common steady-state path).
    let miss = tools_call("search");
    // Hit: the tool matches the deny rule -> an event fires (Monitor forwards it,
    // Enforce blocks on it).
    let hit = tools_call("dangerous_delete");

    let mut group = c.benchmark_group("evaluate_request");
    group.bench_function("monitor_miss", |b| {
        b.iter(|| evaluate_request(black_box(&miss), black_box(&monitor)))
    });
    group.bench_function("monitor_hit", |b| {
        b.iter(|| evaluate_request(black_box(&hit), black_box(&monitor)))
    });
    group.bench_function("enforce_miss", |b| {
        b.iter(|| evaluate_request(black_box(&miss), black_box(&enforce)))
    });
    group.bench_function("enforce_hit", |b| {
        b.iter(|| evaluate_request(black_box(&hit), black_box(&enforce)))
    });
    group.finish();
}

fn bench_fingerprint(c: &mut Criterion) {
    let resp = tools_list_response();
    let single = resp["result"]["tools"][0].clone();

    let mut group = c.benchmark_group("fingerprint");
    // One tool, all three hash versions (the per-tool unit cost).
    group.bench_function("tool_versions_single", |b| {
        b.iter(|| fingerprint_tool_versions(black_box(&single)))
    });
    // A whole mid-sized tools/list: eight tools x three hashes each.
    group.bench_function("tools_list_versioned_8", |b| {
        b.iter(|| fingerprints_from_tools_list_versioned(black_box(&resp)))
    });
    group.finish();
}

criterion_group!(benches, bench_evaluate_request, bench_fingerprint);
criterion_main!(benches);
