//! End-to-end `wrap` overhead benchmark: how much latency/throughput cost the proxy
//! adds over talking to an MCP server directly, across the four `--record` / `--enforce`
//! configurations plus a no-proxy baseline.
//!
//! This is a **manual** benchmark, marked `#[ignore]` so it never runs in the normal
//! `cargo test` suite (it drives thousands of real round-trips and its numbers are
//! hardware-relative, so gating CI on them would be flaky). It lives as a test rather
//! than a separate bench/bin because it can reuse the existing integration harness
//! (`CARGO_BIN_EXE_mcpglass` / `CARGO_BIN_EXE_echo-mcp`) with zero extra build wiring.
//!
//! Run it in release for representative figures:
//!
//! ```sh
//! cargo test -p cli --release --test bench_e2e -- --ignored --nocapture
//! ```
//!
//! Each frame is a `tools/call` (so the c2s policy gate does real work) with a small,
//! secret-free argument object; the `enforce` run therefore evaluates the gate on
//! every frame and forwards (no match), preserving the round-trip. See docs/benchmarks.md.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::{Duration, Instant};

const MCPGLASS: &str = env!("CARGO_BIN_EXE_mcpglass");
const ECHO_MCP: &str = env!("CARGO_BIN_EXE_echo-mcp");

/// Timed round-trips. Kept modest so the whole sweep finishes in a few seconds.
const FRAMES: usize = 5000;
/// Untimed warm-up round-trips to reach steady state before measuring.
const WARMUP: usize = 200;

/// One `tools/call` frame (no trailing newline) for sequence number `i`.
fn frame(i: usize) -> String {
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{i},\"method\":\"tools/call\",\
         \"params\":{{\"name\":\"search\",\"arguments\":{{\"query\":\"row {i}\",\"limit\":25}}}}}}"
    )
}

struct Summary {
    label: &'static str,
    throughput_req_s: f64,
    p50_us: u128,
    p99_us: u128,
}

/// Drive `child` (which echoes one line per input line) through WARMUP + FRAMES
/// sequential round-trips, timing each measured one. Returns per-request latencies.
fn drive(mut child: Child) -> Vec<Duration> {
    let mut stdin: ChildStdin = child.stdin.take().expect("child stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("child stdout"));
    let mut line = String::new();

    // One request -> one echoed line back. Returns the round-trip elapsed time.
    let mut round_trip = |stdin: &mut ChildStdin, line: &mut String, i: usize| -> Duration {
        line.clear();
        let t0 = Instant::now();
        writeln!(stdin, "{}", frame(i)).expect("write frame");
        stdin.flush().expect("flush frame");
        let n = stdout.read_line(line).expect("read echoed line");
        assert!(n > 0, "server closed the stream early");
        t0.elapsed()
    };

    for i in 0..WARMUP {
        round_trip(&mut stdin, &mut line, i);
    }

    let mut latencies = Vec::with_capacity(FRAMES);
    for i in 0..FRAMES {
        latencies.push(round_trip(&mut stdin, &mut line, WARMUP + i));
    }

    drop(stdin); // EOF -> the server (and proxy) wind down.
    let _ = child.wait();
    latencies
}

fn summarize(label: &'static str, mut latencies: Vec<Duration>) -> Summary {
    let total: Duration = latencies.iter().sum();
    let throughput_req_s = latencies.len() as f64 / total.as_secs_f64();
    latencies.sort_unstable();
    let pct = |p: usize| latencies[(latencies.len() * p / 100).min(latencies.len() - 1)].as_micros();
    Summary {
        label,
        throughput_req_s,
        p50_us: pct(50),
        p99_us: pct(99),
    }
}

/// Spawn the echo server directly (baseline) or under `mcpglass wrap` with `args`.
fn spawn_proxied(tag: &str, extra_args: &[&str]) -> Child {
    let tmp = std::env::temp_dir().join(format!("mcpglass-bench-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let db: PathBuf = tmp.join("sessions.db");
    let log: PathBuf = tmp.join("mcpglass.log");

    let mut cmd = Command::new(MCPGLASS);
    cmd.arg("wrap")
        .args(["--db", db.to_str().unwrap()])
        .args(["--log", log.to_str().unwrap()])
        .args(extra_args)
        .args(["--", ECHO_MCP])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    cmd.spawn().expect("spawn mcpglass wrap")
}

fn spawn_baseline() -> Child {
    Command::new(ECHO_MCP)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn echo baseline")
}

#[test]
#[ignore = "manual end-to-end benchmark; run with --release --ignored --nocapture"]
fn wrap_overhead_benchmark() {
    let runs: Vec<Summary> = vec![
        summarize("baseline (direct)", drive(spawn_baseline())),
        summarize("wrap --record off", drive(spawn_proxied("off", &["--record", "off"]))),
        summarize("wrap --record metadata", drive(spawn_proxied("meta", &["--record", "metadata"]))),
        summarize("wrap --record full", drive(spawn_proxied("full", &["--record", "full"]))),
        summarize(
            "wrap --record full --enforce",
            drive(spawn_proxied("enforce", &["--record", "full", "--enforce"])),
        ),
    ];

    println!("\n=== wrap overhead: {FRAMES} tools/call round-trips ({WARMUP} warm-up) ===");
    println!("{:<32} {:>14} {:>10} {:>10}", "mode", "throughput", "p50", "p99");
    println!("{:<32} {:>14} {:>10} {:>10}", "", "(req/s)", "(us)", "(us)");
    for r in &runs {
        println!(
            "{:<32} {:>14.0} {:>10} {:>10}",
            r.label, r.throughput_req_s, r.p50_us, r.p99_us
        );
    }
    println!();

    // A guard, not a gate: the run is only meaningful if every configuration made
    // real progress. Absolute numbers are hardware-relative and never asserted.
    for r in &runs {
        assert!(r.throughput_req_s > 0.0, "{} made no progress", r.label);
    }
}
