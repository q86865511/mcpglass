# Benchmarks and fail-open regression tests

This document turns the fail-open promise in [security-model.md](security-model.md) —
*"while the mcpglass process is alive, no failure in its own machinery may block or
delay client↔server traffic"* — into measured, repeatable engineering figures, and
records the regression tests that keep that promise honest.

Two kinds of measurement live here:

- **Micro-benchmarks** ([criterion](https://github.com/bheisler/criterion.rs)) for the
  pure hot-path functions: JSON-RPC frame parsing, the c2s policy decision, and tool
  fingerprinting.
- **An end-to-end overhead benchmark** that drives thousands of real `tools/call`
  round-trips through `mcpglass wrap` and compares them to talking to the server
  directly.

Plus the two **fail-open regression tests** (a saturated tap channel and an unwritable
database) that run in the ordinary `cargo test` suite.

> **These numbers are hardware-relative and are never used to gate CI.** They exist to
> characterise the proxy and to catch order-of-magnitude regressions by eye, not to pass
> or fail a build. Re-run them locally; expect run-to-run variation of a few percent.

## Methodology

| | |
| --- | --- |
| CPU | 13th Gen Intel Core i5-13600K (14 cores / 20 threads) |
| RAM | 32 GB |
| OS | Windows 11 Pro (10.0.26200) |
| Toolchain | rustc 1.96.1, `cargo bench` / `--release` (workspace `release` profile: `lto = "thin"`, `codegen-units = 1`) |
| Micro-bench frame | a representative `tools/call` request and an 8-tool `tools/list` response (see the bench sources) |
| E2E frame | one `tools/call` per round-trip with a small, secret-free argument object |
| E2E sample | 5000 timed round-trips after 200 warm-up round-trips, per configuration |

The end-to-end latencies are collected in-process: each round-trip writes one frame,
reads exactly one echoed line back, and records the elapsed time; p50/p99 are order
statistics over the 5000 samples (no external measurement crate). The stand-in server is
the `echo-mcp` test fixture (echoes each line verbatim), so the figures isolate proxy
overhead, not server work.

## Micro-benchmarks

`cargo bench -p proxy-core` and `cargo bench -p policy`. Times are the criterion median.

### `proxy-core::parse_line` — per-frame field extraction (storage thread)

| Frame | Median |
| --- | --- |
| `tools/call` request (c2s) | ~0.89 µs |
| `tools/list` response, 2 tools (s2c) | ~2.53 µs |
| non-JSON line (invalid-body fast path) | ~41 ns |

Runs once per recorded frame on the storage thread — off the forwarding path, so it sets
the ceiling on tap throughput, not wire latency.

### `policy::evaluate_request` — the c2s decision (on the wire path)

| Case | Median |
| --- | --- |
| monitor, deny miss (full deny + secret scan, forwards) | ~0.24 µs |
| monitor, deny hit (event constructed) | ~0.52 µs |
| enforce, deny miss (forwards) | ~0.24 µs |
| enforce, deny hit (blocks) | ~0.50 µs |

This is the one policy computation that sits *on* the forwarding path. Sub-microsecond in
every case; enforce is indistinguishable from monitor (the mode enum flips a branch, it
does no extra work), and a deny hit costs about twice a miss purely from building the
event record.

### `policy` fingerprinting — the triple SHA-256 (storage thread)

| Work | Median |
| --- | --- |
| one tool, v1+v2+v3 hashes | ~13.6 µs |
| whole 8-tool `tools/list`, all versions | ~118 µs |

Runs on the storage thread when a correlated `tools/list` response is tapped — off the
wire. The cost is dominated by canonical-JSON serialisation + three SHA-256 passes per
tool and scales linearly with the tool count.

## End-to-end `wrap` overhead

`cargo test -p cli --release --test bench_e2e -- --ignored --nocapture`. One representative
run (5000 round-trips each):

| Mode | Throughput (req/s) | p50 (µs) | p99 (µs) |
| --- | ---: | ---: | ---: |
| baseline (direct to server, no proxy) | ~60600 | 12 | 46 |
| `wrap --record off` | ~8970 | 101 | 294 |
| `wrap --record metadata` | ~8230 | 113 | 297 |
| `wrap --record full` | ~8100 | 114 | 310 |
| `wrap --record full --enforce` | ~8280 | 111 | 296 |

Reading the deltas:

- **baseline → `--record off`** is the irreducible proxy hop: the client↔server path now
  crosses an extra process with two async pumps and a shared, frame-atomic stdout, so per
  round-trip latency rises from ~12 µs to ~100 µs. This is the cost of *being* a transparent
  proxy, independent of any recording or policy work.
- **`off` → `metadata` → `full`** is the recording cost. It is small and monotonic
  (~8970 → ~8230 → ~8100 req/s): recording is a best-effort `try_send` onto a bounded
  channel, so it barely touches the round-trip.
- **`full` → `full --enforce`** is within noise — the enforce decision is not measurably
  more expensive than monitoring (consistent with the `evaluate_request` micro-benchmark).

The absolute per-request overhead (~100 µs) is negligible next to real MCP server work
(network calls, tool execution, LLM turns), which is why the proxy is transparent in
practice.

## Fail-open regression tests

These run in the normal `cargo test` suite (`crates/cli/tests/fail_open_regression.rs`)
and are the executable proof that a stalled or failed recording path never reaches the
wire. Both rely on `cfg(debug_assertions)`-only hooks in the wrapped binary
(`MCPGLASS_TEST_CHANNEL_CAP`, `MCPGLASS_TEST_STORAGE_STALL_MS`), which compile out
entirely in release builds — the storage loop and channel pay nothing in production.

### Channel saturation — `saturated_tap_channel_never_backpressures_the_wire`

The storage thread is slowed to 3 ms/message and the tap channel shrunk to 32 slots, then
2000 `tools/call` frames are pushed through. The test asserts:

1. **the wire is byte-identical** to a direct connection — not one frame corrupted or
   delayed, despite the tap drowning;
2. **records are dropped, not buffered** — far fewer than the offered frames land in
   SQLite (the `try_send` overflow is discarded, never queued onto the wire);
3. **the drop is logged once per pump** — throttled via `log_drop_once`, never
   once-per-dropped-frame (which would itself turn a stall into blocking disk I/O).

### Recording-target failure — `storage_open_failure_disables_recording_without_touching_the_wire`

The database path is pointed at a directory, so `Store::open` fails at startup. This is the
portable stand-in for a full/unwritable disk (a true `ENOSPC` is not inducible on Windows)
and drives the same degradation path: recording disabled, forwarding intact. The test
asserts the proxied bytes match a direct connection exactly, the exit code is unchanged,
and the failure is reported to the log as a recording-disabled degradation (never to the
protocol channels).

## Reproducing

```sh
# Micro-benchmarks (criterion; release bench profile)
cargo bench -p proxy-core
cargo bench -p policy

# End-to-end wrap overhead (release; manual, #[ignore]'d out of the normal suite)
cargo test -p cli --release --test bench_e2e -- --ignored --nocapture

# Fail-open regression tests (part of the normal debug test suite)
cargo test -p cli --test fail_open_regression
```

The GitHub Actions workflow [`.github/workflows/bench.yml`](../.github/workflows/bench.yml)
runs the criterion and end-to-end benchmarks on demand (`workflow_dispatch`) and uploads
the results as an artifact. It is never part of the gating CI.
