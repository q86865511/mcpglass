//! Micro-benchmark for [`proxy_core::parse_line`], the per-frame JSON-RPC field
//! extraction the storage thread runs on every tapped message. It is off the
//! forwarding hot path (the wire is never gated on it), but it runs once per
//! recorded frame, so its cost sets the ceiling on tap throughput.
//!
//! Run with `cargo bench -p proxy-core`. Numbers are hardware-relative; see
//! docs/benchmarks.md for the methodology and recorded figures.

use criterion::{criterion_group, criterion_main, Criterion};
use proxy_core::{parse_line, Direction};
use std::hint::black_box;

/// A representative `tools/call` request — the shape the c2s leg sees most.
const TOOLS_CALL: &[u8] = br#"{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"search","arguments":{"query":"quarterly revenue","limit":25}}}"#;

/// A representative `tools/list` response (s2c), a larger body with nested schemas.
const TOOLS_LIST_RESP: &[u8] = br#"{"jsonrpc":"2.0","id":7,"result":{"tools":[{"name":"search","description":"Full-text search","inputSchema":{"type":"object","properties":{"query":{"type":"string"},"limit":{"type":"integer"}},"required":["query"]}},{"name":"fetch","description":"Fetch a URL","inputSchema":{"type":"object","properties":{"url":{"type":"string"}},"required":["url"]}}]}}"#;

/// A non-JSON frame: exercises the invalid-body fast path (recorded verbatim).
const NON_JSON: &[u8] = b"this is not json at all, just some bytes on the wire";

fn bench_parse_line(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_line");

    group.bench_function("tools_call_c2s", |b| {
        b.iter(|| parse_line(black_box(TOOLS_CALL), black_box(Direction::C2s)))
    });
    group.bench_function("tools_list_resp_s2c", |b| {
        b.iter(|| parse_line(black_box(TOOLS_LIST_RESP), black_box(Direction::S2c)))
    });
    group.bench_function("non_json_s2c", |b| {
        b.iter(|| parse_line(black_box(NON_JSON), black_box(Direction::S2c)))
    });

    group.finish();
}

criterion_group!(benches, bench_parse_line);
criterion_main!(benches);
