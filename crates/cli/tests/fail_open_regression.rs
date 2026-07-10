//! Executable proof of the fail-open promise from docs/security-model.md:
//! *"while the mcpglass process is alive, no failure in its own machinery may block
//! or delay client<->server traffic."* Two failure modes are forced and the wire is
//! checked to be intact:
//!
//! 1. **A stalled/saturated tap channel.** The storage thread is slowed with a
//!    per-message stall and the channel shrunk so it overflows; the round-trip must
//!    still complete byte-for-byte, records must be *dropped* (not buffered onto the
//!    wire), and the drop must be logged exactly once.
//! 2. **An unwritable recording target.** The database cannot be opened, so recording
//!    is disabled at startup; forwarding must be unaffected and the failure logged.
//!
//! Both hooks (`MCPGLASS_TEST_CHANNEL_CAP`, `MCPGLASS_TEST_STORAGE_STALL_MS`) are
//! compiled only into debug/test builds, so these tests run under the ordinary
//! `cargo test` (debug) profile, where the wrapped binary carries them.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const MCPGLASS: &str = env!("CARGO_BIN_EXE_mcpglass");
const ECHO_MCP: &str = env!("CARGO_BIN_EXE_echo-mcp");

/// Run `cmd`, feed `input` on stdin (closing it to signal EOF), and return
/// (stdout, exit code). stderr is inherited so a panic surfaces in test output.
fn run_capture(mut cmd: Command, input: Vec<u8>) -> (Vec<u8>, i32) {
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut child = cmd.spawn().expect("spawn");
    let mut stdin = child.stdin.take().expect("stdin");
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let mut out = Vec::new();
    child
        .stdout
        .take()
        .expect("stdout")
        .read_to_end(&mut out)
        .expect("read stdout");
    writer.join().expect("writer thread");
    let status = child.wait().expect("wait");
    (out, status.code().unwrap_or(-1))
}

/// A fresh, unique temp directory for one test's db + log.
fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("mcpglass-failopen-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn recorded_message_count(db: &Path) -> i64 {
    let conn = rusqlite::Connection::open(db).expect("open db");
    conn.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
        .expect("count messages")
}

/// A stalled storage thread + an overflowing tap channel must not touch the wire:
/// every frame round-trips byte-identically, records are dropped rather than
/// buffered, and the drop is logged once (throttled).
#[test]
fn saturated_tap_channel_never_backpressures_the_wire() {
    // Enough frames to bury the tiny (32-slot) channel while the storage thread
    // crawls at 3 ms/message. try_send drops the overflow; the wire is untouched.
    const FRAMES: usize = 2000;
    let input: String = (0..FRAMES)
        .map(|i| {
            format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{i},\"method\":\"tools/call\",\
                 \"params\":{{\"name\":\"search\",\"arguments\":{{\"seq\":{i}}}}}}}\n"
            )
        })
        .collect();

    // Baseline: talk to the echo server directly, no proxy.
    let (direct_out, direct_code) = run_capture(Command::new(ECHO_MCP), input.clone().into_bytes());
    assert_eq!(direct_code, 0, "direct echo should exit 0");

    let tmp = scratch("saturation");
    let db = tmp.join("sessions.db");
    let log = tmp.join("mcpglass.log");

    let mut proxied = Command::new(MCPGLASS);
    proxied
        .env("MCPGLASS_TEST_CHANNEL_CAP", "32")
        .env("MCPGLASS_TEST_STORAGE_STALL_MS", "3")
        .args([
            "wrap",
            "--db",
            db.to_str().unwrap(),
            "--log",
            log.to_str().unwrap(),
            "--",
            ECHO_MCP,
        ]);
    let (proxied_out, proxied_code) = run_capture(proxied, input.into_bytes());

    // (a) The wire is sacred: proxied output is byte-identical to the direct echo,
    //     even though the tap was drowning.
    assert_eq!(
        proxied_out, direct_out,
        "a saturated tap must not corrupt or drop a single wire byte"
    );
    assert_eq!(proxied_code, 0, "proxy mirrors the child's exit code");

    // (b) Records were dropped, not silently buffered onto the wire: far fewer than
    //     the FRAMES c2s + FRAMES s2c that were offered to the channel.
    let recorded = recorded_message_count(&db);
    assert!(recorded > 0, "some early frames should still have been recorded");
    assert!(
        recorded < FRAMES as i64,
        "a saturated channel must drop records (recorded {recorded} of >={FRAMES} offered)"
    );

    // (c) The drop is logged, and throttled: the substring appears (once per pump at
    //     most), never once-per-dropped-frame.
    let log_text = std::fs::read_to_string(&log).expect("read log");
    let drops = log_text.matches("tap dropped (channel full/closed)").count();
    assert!(drops >= 1, "the first tap drop must be logged");
    assert!(
        drops <= 2,
        "drop logging must be throttled (<=1 per pump), got {drops} lines"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

/// If the recording database cannot even be opened, recording is disabled at startup
/// and the wire carries on untouched — the storage failure never reaches the pumps.
#[test]
fn storage_open_failure_disables_recording_without_touching_the_wire() {
    let input =
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n".to_string();

    let (direct_out, direct_code) = run_capture(Command::new(ECHO_MCP), input.clone().into_bytes());
    assert_eq!(direct_code, 0);

    let tmp = scratch("open-fail");
    // Point --db at a path that is an existing *directory*: rusqlite cannot open it as
    // a database file, so `Store::open` fails. This is the portable stand-in for an
    // unwritable/full recording target (a true ENOSPC is not inducible on Windows),
    // and it drives the same fail-open degradation: recording disabled, wire intact.
    let db_dir = tmp.join("db-is-a-directory");
    std::fs::create_dir_all(&db_dir).unwrap();
    let log = tmp.join("mcpglass.log");

    let mut proxied = Command::new(MCPGLASS);
    proxied.args([
        "wrap",
        "--db",
        db_dir.to_str().unwrap(),
        "--log",
        log.to_str().unwrap(),
        "--",
        ECHO_MCP,
    ]);
    let (proxied_out, proxied_code) = run_capture(proxied, input.into_bytes());

    // The wire is byte-identical and the proxy exits cleanly despite storage failing.
    assert_eq!(
        proxied_out, direct_out,
        "a failed db open must not affect forwarded bytes"
    );
    assert_eq!(proxied_code, 0, "storage failure must not change the exit code");

    // The failure is reported to the log (never to the protocol channels), and the
    // degradation is the documented one: recording disabled.
    let log_text = std::fs::read_to_string(&log).expect("read log");
    assert!(
        log_text.contains("db open failed") && log_text.contains("recording disabled"),
        "the open failure must be logged as a recording-disabled degradation; got: {log_text:?}"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
