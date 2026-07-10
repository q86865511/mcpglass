//! End-to-end check of the transparent proxy: bytes through `mcpglass wrap` must
//! be identical to talking to the server directly, and the tap must land in
//! SQLite with the right direction and method.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

const MCPGLASS: &str = env!("CARGO_BIN_EXE_mcpglass");
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
    let tmp = std::env::temp_dir().join(format!("mcpglass-it-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let db: PathBuf = tmp.join("sessions.db");
    let log: PathBuf = tmp.join("mcpglass.log");

    let mut proxied = Command::new(MCPGLASS);
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

    // Schema v1: exactly one session, and it was ended after the child exited.
    let (session_id, ended): (i64, Option<i64>) = conn
        .query_row(
            "SELECT id, ended_at_ms FROM sessions",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("query session");
    assert!(ended.is_some(), "session should have an end timestamp");

    // Every tapped message hangs off that session.
    let orphaned: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE session_id != ?1",
            [session_id],
            |r| r.get(0),
        )
        .expect("query orphaned");
    assert_eq!(orphaned, 0, "all messages must belong to the session");

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

/// The MCP 2025-11-25 wire additions (tasks, icons, sampling tools/toolChoice,
/// URL-mode elicitation, a `CreateTaskResult` with an `_meta` related-task marker)
/// are unknown to the proxy, which forwards bytes verbatim. This drives every new
/// shape through `mcpglass wrap` and asserts (a) the bytes are byte-identical to a
/// direct connection and (b) each frame is recorded with the right method/id — i.e.
/// the newer spec is pure pass-through, no frame mangled or dropped.
#[test]
fn wire_2025_11_25_shapes_pass_through_and_record() {
    // Each line is one JSON-RPC frame the newer spec introduces. echo-mcp echoes
    // each verbatim, so the recorded s2c is byte-identical to the c2s.
    let frames = [
        r#"{"jsonrpc":"2.0","id":1,"method":"tasks/get","params":{"task":{"ttl":30000}}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tasks/result","params":{"taskId":"abc"}}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tasks/list"}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"tasks/cancel","params":{"taskId":"abc"}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/tasks/status","params":{"taskId":"abc","status":"working"}}"#,
        r#"{"jsonrpc":"2.0","id":5,"result":{"task":{"taskId":"abc","ttl":30000},"_meta":{"io.modelcontextprotocol/related-task":{"taskId":"abc"}}}}"#,
        r#"{"jsonrpc":"2.0","id":6,"method":"sampling/createMessage","params":{"messages":[],"tools":[{"name":"calc"}],"toolChoice":{"type":"auto"}}}"#,
        r#"{"jsonrpc":"2.0","id":7,"method":"elicitation/create","params":{"mode":"url","url":"https://example.test/form"}}"#,
        r#"{"jsonrpc":"2.0","id":7,"result":{"action":"accept","content":{"answer":"yes"}}}"#,
        r#"{"jsonrpc":"2.0","id":8,"result":{"tools":[{"name":"read","icons":[{"src":"data:image/png;base64,AA","mimeType":"image/png","sizes":["16x16"]}]}]}}"#,
    ];
    let input: String = frames.iter().map(|f| format!("{f}\n")).collect();

    // Baseline: talk to echo directly.
    let direct = Command::new(ECHO_MCP);
    let (direct_out, direct_code) = run_capture(direct, input.as_bytes());
    assert_eq!(direct_code, 0);

    let tmp = std::env::temp_dir().join(format!("mcpglass-it-1125-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let db: PathBuf = tmp.join("sessions.db");
    let log: PathBuf = tmp.join("mcpglass.log");

    let mut proxied = Command::new(MCPGLASS);
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

    // (a) Byte-identical to the direct connection: no frame was mangled.
    assert_eq!(proxied_out, direct_out, "new wire shapes must pass through verbatim");
    assert_eq!(proxied_code, 0);

    // (b) Recording: the tasks request family and the augmented requests are indexed
    // by method; the CreateTaskResult / ElicitResult are recorded as responses (no
    // method, id present) and must not be flagged errors.
    let conn = rusqlite::Connection::open(&db).expect("open db");
    for method in ["tasks/get", "tasks/list", "sampling/createMessage", "elicitation/create"] {
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE direction='c2s' AND method=?1",
                [method],
                |r| r.get(0),
            )
            .expect("query method");
        assert!(n >= 1, "expected a c2s {method} record");
    }
    // The status notification: has a method, no id.
    let notif: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM messages
             WHERE method='notifications/tasks/status' AND rpc_id IS NULL AND is_valid_json=1",
            [],
            |r| r.get(0),
        )
        .expect("query tasks notification");
    assert!(notif >= 1, "expected a tasks/status notification with null id");
    // The CreateTaskResult (id 5) is a valid, non-error response with no method.
    let create_task_result: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM messages
             WHERE rpc_id='5' AND method IS NULL AND is_valid_json=1 AND is_error=0
               AND instr(raw, 'related-task') > 0",
            [],
            |r| r.get(0),
        )
        .expect("query CreateTaskResult");
    assert!(
        create_task_result >= 1,
        "the CreateTaskResult must record verbatim (with its _meta related-task) as a non-error response"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
