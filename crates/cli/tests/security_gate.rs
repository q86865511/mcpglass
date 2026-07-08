//! End-to-end checks of the Phase-2 client->server security gate on the `wrap`
//! hot path. Uses the `echo-mcp` fixture (which echoes each c2s line back on
//! s2c), so "the server received the request" is observable as "the request was
//! echoed to our stdout".

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const MCPGLASS: &str = env!("CARGO_BIN_EXE_mcpglass");
const ECHO_MCP: &str = env!("CARGO_BIN_EXE_echo-mcp");

const INITIALIZE: &str = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n";

/// A unique token buried in a tools/call's arguments. If the server received the
/// call it echoes the whole line (token included); if the call was blocked the
/// token never appears on stdout.
const MARKER: &str = "ZZBLOCKMARKER";

/// A tools/call for `tool`, id 42, carrying `MARKER` in its arguments.
fn dangerous_call() -> String {
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":42,\"method\":\"tools/call\",\
         \"params\":{{\"name\":\"dangerous_tool\",\"arguments\":{{\"note\":\"{MARKER}\"}}}}}}\n"
    )
}

/// Run `cmd`, feed `input` on stdin (closing it), return (stdout, exit code).
fn run_capture(mut cmd: Command, input: &[u8]) -> (Vec<u8>, i32) {
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().expect("spawn");
    let mut stdin = child.stdin.take().expect("stdin");
    let input = input.to_vec();
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

/// A fresh temp dir for one test's db + policy files.
fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("mcpglass-secit-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run `wrap` through the echo server with an explicit policy file.
fn run_wrap(dir: &Path, policy_toml: &str, input: &str) -> (Vec<u8>, i32, PathBuf) {
    run_wrap_env(dir, policy_toml, input, &[])
}

/// Like [`run_wrap`], but sets extra environment variables on the `wrap`
/// subprocess (used to shrink the frame cap for the oversized-frame path).
fn run_wrap_env(
    dir: &Path,
    policy_toml: &str,
    input: &str,
    env: &[(&str, &str)],
) -> (Vec<u8>, i32, PathBuf) {
    let db = dir.join("sessions.db");
    let log = dir.join("mcpglass.log");
    let policy = dir.join("policy.toml");
    std::fs::write(&policy, policy_toml).unwrap();

    let mut cmd = Command::new(MCPGLASS);
    cmd.args([
        "wrap",
        "--db",
        db.to_str().unwrap(),
        "--log",
        log.to_str().unwrap(),
        "--policy",
        policy.to_str().unwrap(),
        "--",
        ECHO_MCP,
    ]);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let (out, code) = run_capture(cmd, input.as_bytes());
    (out, code, db)
}

/// Count security_events rows matching a rule token.
fn count_events_by_rule(db: &Path, rule: &str, action: &str) -> i64 {
    let conn = rusqlite::Connection::open(db).expect("open db");
    conn.query_row(
        "SELECT COUNT(*) FROM security_events WHERE rule = ?1 AND action_taken = ?2",
        rusqlite::params![rule, action],
        |r| r.get(0),
    )
    .expect("count")
}

/// Count security_events rows matching a kind (+ optional action_taken).
fn count_events(db: &Path, kind: &str, action: Option<&str>) -> i64 {
    let conn = rusqlite::Connection::open(db).expect("open db");
    match action {
        Some(a) => conn
            .query_row(
                "SELECT COUNT(*) FROM security_events WHERE kind = ?1 AND action_taken = ?2",
                rusqlite::params![kind, a],
                |r| r.get(0),
            )
            .expect("count"),
        None => conn
            .query_row(
                "SELECT COUNT(*) FROM security_events WHERE kind = ?1",
                rusqlite::params![kind],
                |r| r.get(0),
            )
            .expect("count"),
    }
}

#[test]
fn enforce_deny_blocks_request_and_answers_client() {
    let dir = temp_dir("enforce-deny");
    let input = format!("{INITIALIZE}{}", dangerous_call());
    let (out, code, db) = run_wrap(
        &dir,
        "mode = \"enforce\"\ndeny = [\"dangerous_tool\"]\n",
        &input,
    );
    let stdout = String::from_utf8_lossy(&out);

    // Client got the in-protocol refusal for id 42...
    assert!(stdout.contains("-32001"), "expected block error, got: {stdout}");
    assert!(stdout.contains("\"id\":42"), "error must echo the request id");
    // ...and the server NEVER saw the call (its marker was never echoed back).
    assert!(
        !stdout.contains(MARKER),
        "blocked call must not reach the echo server: {stdout}"
    );
    // The initialize before it was still forwarded and echoed.
    assert!(stdout.contains("initialize"), "initialize should pass through");
    assert_eq!(code, 0, "proxy mirrors the child's clean exit");

    assert_eq!(count_events(&db, "policy_deny", Some("blocked")), 1);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn monitor_deny_forwards_but_flags() {
    let dir = temp_dir("monitor-deny");
    let input = format!("{INITIALIZE}{}", dangerous_call());
    let (out, code, db) = run_wrap(
        &dir,
        "mode = \"monitor\"\ndeny = [\"dangerous_tool\"]\n",
        &input,
    );
    let stdout = String::from_utf8_lossy(&out);

    // Monitor forwards: the server received and echoed the call (marker present),
    // and no synthetic error was produced.
    assert!(
        stdout.contains(MARKER),
        "monitor mode must forward the call to the server: {stdout}"
    );
    assert!(!stdout.contains("-32001"), "monitor must not block: {stdout}");
    assert_eq!(code, 0);

    // The deny was still recorded, as advisory only.
    assert_eq!(count_events(&db, "policy_deny", Some("flagged")), 1);
    assert_eq!(count_events(&db, "policy_deny", Some("blocked")), 0);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn secret_in_arguments_is_flagged() {
    let dir = temp_dir("secret");
    // A fake AWS access key (AKIA + 16 uppercase/digits) in tools/call arguments.
    let secret = format!("AKIA{}", "A".repeat(16));
    let call = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\
         \"params\":{{\"name\":\"send\",\"arguments\":{{\"body\":\"{secret}\"}}}}}}\n"
    );
    let input = format!("{INITIALIZE}{call}");
    let (out, code, db) = run_wrap(&dir, "secret_scan = true\n", &input);
    let stdout = String::from_utf8_lossy(&out);

    assert_eq!(code, 0);
    // Default monitor mode forwards; the call was echoed.
    assert!(stdout.contains("send"), "call should be forwarded: {stdout}");
    // A secret_leak event was recorded (flagged, since monitor mode).
    assert_eq!(count_events(&db, "secret_leak", Some("flagged")), 1);
    // The stored detail must be masked, never the raw secret.
    let conn = rusqlite::Connection::open(&db).unwrap();
    let detail: String = conn
        .query_row(
            "SELECT detail FROM security_events WHERE kind = 'secret_leak'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(!detail.contains(&secret), "raw secret leaked into storage: {detail}");

    let _ = std::fs::remove_dir_all(&dir);
}

/// A tools/call whose padded arguments push the frame well past the pump read
/// buffer (64 KiB), carrying `MARKER` near the front so "the server received it"
/// is observable as the marker being echoed.
///
/// The frame must exceed `READ_BUF_BYTES` so it necessarily spans multiple reads
/// and overflows the (shrunk) cap *before* its terminating newline arrives — that
/// is the code path that surfaces `Chunk::Raw`. A frame delivered whole in a single
/// read is emitted as a normal `Frame` regardless of size, so a small pad would not
/// exercise the oversized path.
fn oversized_call() -> String {
    let pad = "P".repeat(100_000);
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":55,\"method\":\"tools/call\",\
         \"params\":{{\"name\":\"big\",\"arguments\":{{\"note\":\"{MARKER}{pad}\"}}}}}}\n"
    )
}

#[test]
fn enforce_blocks_oversized_frame_and_records_event() {
    let dir = temp_dir("enforce-oversized");
    // Shrink the cap far below the frame size so the overflow path triggers.
    let cap = 256usize;
    // initialize is small (forwarded); the padded call overflows the cap.
    let input = format!("{INITIALIZE}{}", oversized_call());
    let (out, code, db) = run_wrap_env(
        &dir,
        "mode = \"enforce\"\n",
        &input,
        &[("MCPGLASS_MAX_LINE_BYTES", &cap.to_string())],
    );
    let stdout = String::from_utf8_lossy(&out);

    // The oversized, uninspectable frame was dropped: the echo server never saw it.
    assert!(
        !stdout.contains(MARKER),
        "enforce must drop the oversized frame before the server: {stdout}"
    );
    // The small initialize still passed through.
    assert!(stdout.contains("initialize"), "initialize should pass through");
    assert_eq!(code, 0, "proxy mirrors the child's clean exit");

    // Exactly one blocked oversized-frame event was recorded (once per frame).
    assert_eq!(count_events_by_rule(&db, "oversized-frame", "blocked"), 1);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn monitor_forwards_oversized_frame_verbatim() {
    let dir = temp_dir("monitor-oversized");
    let cap = 256usize;
    let input = format!("{INITIALIZE}{}", oversized_call());
    let (out, code, db) = run_wrap_env(
        &dir,
        "mode = \"monitor\"\n",
        &input,
        &[("MCPGLASS_MAX_LINE_BYTES", &cap.to_string())],
    );
    let stdout = String::from_utf8_lossy(&out);

    // Monitor keeps the fail-open passthrough: the oversized frame reached the
    // server and was echoed back (marker present), and nothing was blocked.
    assert!(
        stdout.contains(MARKER),
        "monitor must forward the oversized frame verbatim: {stdout}"
    );
    assert_eq!(code, 0);
    assert_eq!(count_events_by_rule(&db, "oversized-frame", "blocked"), 0);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn broken_policy_file_aborts_before_forwarding() {
    let dir = temp_dir("broken-policy");
    // Malformed TOML: a security config that fails to parse must abort startup,
    // not fall open to "no policy".
    let (out, code, _db) = run_wrap(&dir, "mode = \"enforce\"\ndeny = [\n", INITIALIZE);

    assert_ne!(code, 0, "a broken policy must make wrap exit non-zero");
    // Nothing was forwarded: the child was never given the initialize to echo.
    assert!(out.is_empty(), "no traffic should flow on a policy abort: {out:?}");

    let _ = std::fs::remove_dir_all(&dir);
}
