//! End-to-end check of the transparent proxy: bytes through `mcp-lens wrap` must
//! be identical to talking to the server directly, and the tap must land in
//! SQLite with the right direction and method.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

const MCP_LENS: &str = env!("CARGO_BIN_EXE_mcp-lens");
const ECHO_MCP: &str = env!("CARGO_BIN_EXE_echo-mcp");

const REQUEST: &str = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n";
const NOTIFICATION: &str = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n";

/// Run `cmd`, feed `input` on stdin (closing it), and return (stdout, exit code).
fn run_capture(mut cmd: Command, input: &[u8]) -> (Vec<u8>, i32) {
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut child = cmd.spawn().expect("spawn");
    let mut stdin = child.stdin.take().expect("stdin");
    let input = input.to_vec();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
        // Dropping `stdin` closes it -> EOF, so the pipeline winds down.
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

#[test]
fn passthrough_is_byte_identical_and_recorded() {
    let mut input = String::new();
    input.push_str(REQUEST);
    input.push_str(NOTIFICATION);

    // Baseline: talk to the echo server directly.
    let direct = Command::new(ECHO_MCP);
    let (direct_out, direct_code) = run_capture(direct, input.as_bytes());
    assert_eq!(direct_code, 0, "direct echo should exit 0");

    // Through the proxy, writing the tap to a temp db.
    let tmp = std::env::temp_dir().join(format!("mcp-lens-it-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let db: PathBuf = tmp.join("sessions.db");
    let log: PathBuf = tmp.join("mcp-lens.log");

    let mut proxied = Command::new(MCP_LENS);
    proxied.args([
        "wrap",
        "--db",
        db.to_str().unwrap(),
        "--log",
        log.to_str().unwrap(),
        "--",
        ECHO_MCP,
    ]);
    let (proxied_out, proxied_code) = run_capture(proxied, input.as_bytes());

    // (a) Response bytes must match the direct connection exactly.
    assert_eq!(
        proxied_out, direct_out,
        "proxied stdout must be byte-identical to direct"
    );
    assert_eq!(proxied_code, 0, "proxy should mirror child exit code 0");

    // (b) SQLite must hold the tapped messages with method + direction.
    let conn = rusqlite::Connection::open(&db).expect("open db");

    let c2s_init: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE direction='c2s' AND method='initialize'",
            [],
            |r| r.get(0),
        )
        .expect("query c2s");
    assert!(c2s_init >= 1, "expected a c2s initialize record");

    let s2c_init: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE direction='s2c' AND method='initialize'",
            [],
            |r| r.get(0),
        )
        .expect("query s2c");
    assert!(s2c_init >= 1, "expected a s2c initialize (echoed) record");

    // Notification: valid JSON, has a method, no rpc_id.
    let notif_no_id: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM messages
             WHERE method='notifications/initialized' AND rpc_id IS NULL AND is_valid_json=1",
            [],
            |r| r.get(0),
        )
        .expect("query notification");
    assert!(notif_no_id >= 1, "expected a notification record with null id");

    let _ = std::fs::remove_dir_all(&tmp);
}
