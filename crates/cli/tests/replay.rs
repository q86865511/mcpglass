//! End-to-end checks of `mcpglass replay` on both transports, plus the dashboard
//! replay endpoint driven in-process with a stub backend.
//!
//! * **stdio** reuses the `echo-mcp` fixture: a real `wrap` run records a c2s
//!   `tools/call`, then `mcpglass replay <id>` re-spawns echo-mcp and drives a fresh
//!   handshake — the echo of the replayed frame is the observable response.
//! * **HTTP** seeds a session whose command is a fake axum upstream URL (the
//!   `gateway_http.rs` technique), then `mcpglass replay` re-initializes against it.
//! * **dashboard** calls `dashboard::serve` with a stub `ReplayFn` and checks the
//!   200 / 400 / 501 mapping of `POST /api/messages/{id}/replay`.

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;

const MCPGLASS: &str = env!("CARGO_BIN_EXE_mcpglass");
const ECHO_MCP: &str = env!("CARGO_BIN_EXE_echo-mcp");

// ---------------------------------------------------------------------------
// Shared scaffolding.
// ---------------------------------------------------------------------------

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "mcpglass-replay-it-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
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

/// Like `run_capture`, but also returns captured stderr — needed to assert *which*
/// error a failing replay reported.
fn run_capture_err(mut cmd: Command, input: &[u8]) -> (Vec<u8>, String, i32) {
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
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
    let mut err = Vec::new();
    child
        .stderr
        .take()
        .expect("stderr")
        .read_to_end(&mut err)
        .expect("read stderr");
    writer.join().expect("writer thread");
    let status = child.wait().expect("wait");
    (out, String::from_utf8_lossy(&err).into_owned(), status.code().unwrap_or(-1))
}

fn query_i64(db: &Path, sql: &str) -> i64 {
    let conn = rusqlite::Connection::open(db).expect("open db");
    conn.query_row(sql, [], |r| r.get(0)).expect("query")
}

/// A tools/call frame (id 42) carrying `marker` late in its arguments, without a
/// trailing newline (the caller appends framing as needed).
fn tools_call(marker: &str) -> String {
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":42,\"method\":\"tools/call\",\
         \"params\":{{\"name\":\"do_it\",\"arguments\":{{\"note\":\"{marker}\"}}}}}}"
    )
}

// ---------------------------------------------------------------------------
// stdio.
// ---------------------------------------------------------------------------

#[test]
fn replay_stdio_reissues_request_to_a_fresh_server() {
    const MARKER: &str = "ZZREPLAYSTDIO";
    let dir = temp_dir("stdio");
    let db = dir.join("sessions.db");
    let log = dir.join("mcpglass.log");

    // 1. Record a real session: initialize, then a tools/call carrying MARKER.
    let input = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{{}}}}\n{}\n",
        tools_call(MARKER)
    );
    let mut cmd = Command::new(MCPGLASS);
    cmd.args([
        "wrap",
        "--db",
        db.to_str().unwrap(),
        "--log",
        log.to_str().unwrap(),
        "--",
        ECHO_MCP,
    ]);
    let (_out, code) = run_capture(cmd, input.as_bytes());
    assert_eq!(code, 0, "wrap should exit cleanly");

    // 2. Find the recorded c2s tools/call message.
    let msg_id = query_i64(
        &db,
        "SELECT id FROM messages WHERE direction='c2s' AND method='tools/call' ORDER BY id LIMIT 1",
    );

    // 3. Replay it: echo-mcp is re-spawned and echoes the replayed frame back.
    let mut cmd = Command::new(MCPGLASS);
    cmd.args(["replay", &msg_id.to_string(), "--db", db.to_str().unwrap()]);
    let (out, code) = run_capture(cmd, b"");
    let stdout = String::from_utf8_lossy(&out);
    assert_eq!(code, 0, "replay should succeed: {stdout}");

    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).unwrap_or_else(|e| panic!("replay must print JSON ({e}): {stdout}"));
    assert_eq!(v["transport"], serde_json::json!("stdio"));
    let resp = v["response_raw"].as_str().expect("a response_raw string");
    assert!(resp.contains("\"id\":42"), "the response must answer request id 42: {resp}");
    assert!(
        resp.contains(MARKER),
        "the echo server returns the replayed frame, marker included: {resp}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// HTTP (fake axum upstream, mirroring gateway_http.rs).
// ---------------------------------------------------------------------------

/// A fake upstream: records every POST body and answers each request with an
/// `application/json` result echoing the request id, stamping an `Mcp-Session-Id`
/// so the replay's fresh-initialize handshake can capture one. DELETE is a no-op 200.
async fn upstream_post(
    State(bodies): State<Arc<Mutex<Vec<String>>>>,
    body: axum::body::Bytes,
) -> Response {
    bodies
        .lock()
        .unwrap()
        .push(String::from_utf8_lossy(&body).into_owned());
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    let id = v.get("id").cloned().unwrap_or(serde_json::Value::Null);
    let payload = serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": { "ok": true } });
    (
        [
            ("content-type", "application/json"),
            ("mcp-session-id", "replay-sess"),
        ],
        serde_json::to_vec(&payload).unwrap(),
    )
        .into_response()
}

async fn spawn_upstream() -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route(
            "/",
            post(upstream_post).delete(|| async { StatusCode::OK }),
        )
        .with_state(bodies.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, bodies)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replay_http_reinitializes_and_reissues_request() {
    const MARKER: &str = "ZZREPLAYHTTP";
    let (up_addr, up_bodies) = spawn_upstream().await;
    let url = format!("http://{up_addr}/");

    let dir = temp_dir("http");
    let db = dir.join("sessions.db");

    // Seed a session whose command is the fake upstream URL + one c2s tools/call.
    let sid = {
        let store = storage::Store::open(&db).unwrap();
        store.begin_session("replay-http", &url).unwrap()
    };
    let raw = tools_call(MARKER);
    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute(
            "INSERT INTO messages
                (session_id, ts_ms, direction, raw, method, rpc_id, is_valid_json, is_error)
             VALUES (?1, 1, 'c2s', ?2, 'tools/call', '42', 1, 0)",
            rusqlite::params![sid, raw],
        )
        .unwrap();
    }
    let msg_id = query_i64(&db, "SELECT id FROM messages WHERE method='tools/call' ORDER BY id LIMIT 1");

    // Replay (a blocking subprocess run; the in-process upstream keeps serving on
    // other runtime threads).
    let db_arg = db.to_str().unwrap().to_owned();
    let (out, code) = tokio::task::spawn_blocking(move || {
        let mut cmd = Command::new(MCPGLASS);
        cmd.args(["replay", &msg_id.to_string(), "--db", &db_arg]);
        run_capture(cmd, b"")
    })
    .await
    .unwrap();
    let stdout = String::from_utf8_lossy(&out);
    assert_eq!(code, 0, "replay should succeed: {stdout}");

    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).unwrap_or_else(|e| panic!("replay must print JSON ({e}): {stdout}"));
    assert_eq!(v["transport"], serde_json::json!("http"));
    let resp = v["response_raw"].as_str().expect("a response_raw string");
    assert!(resp.contains("\"id\":42"), "the buffered JSON response must answer id 42: {resp}");

    // The upstream saw a fresh initialize and the replayed request body.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let bodies = up_bodies.lock().unwrap();
    assert!(
        bodies.iter().any(|b| b.contains("initialize")),
        "replay must open a fresh initialize handshake against the upstream"
    );
    assert!(
        bodies.iter().any(|b| b.contains(MARKER)),
        "the replayed request body must reach the upstream: {bodies:?}"
    );
    drop(bodies);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A fake upstream that lets the handshake through (so replay obtains a session) but
/// rejects the actual replayed request with 401, as an auth-gated upstream would. The
/// `initialize` request and the `initialized` notification both carry "initialize" as
/// a substring; the `tools/call` does not, so only it is refused.
async fn upstream_post_needs_auth(body: axum::body::Bytes) -> Response {
    let text = String::from_utf8_lossy(&body);
    if text.contains("initialize") {
        let payload = serde_json::json!({ "jsonrpc": "2.0", "id": "mcpglass-replay-init", "result": {} });
        return (
            [
                ("content-type", "application/json"),
                ("mcp-session-id", "replay-sess"),
            ],
            serde_json::to_vec(&payload).unwrap(),
        )
            .into_response();
    }
    (StatusCode::UNAUTHORIZED, "auth required").into_response()
}

async fn spawn_upstream_needs_auth() -> SocketAddr {
    let app = Router::new().route(
        "/",
        post(upstream_post_needs_auth).delete(|| async { StatusCode::OK }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replay_http_surfaces_upstream_error_status() {
    let up_addr = spawn_upstream_needs_auth().await;
    let url = format!("http://{up_addr}/");

    let dir = temp_dir("http-401");
    let db = dir.join("sessions.db");
    let sid = {
        let store = storage::Store::open(&db).unwrap();
        store.begin_session("replay-http-401", &url).unwrap()
    };
    let raw = tools_call("ZZAUTH");
    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute(
            "INSERT INTO messages
                (session_id, ts_ms, direction, raw, method, rpc_id, is_valid_json, is_error)
             VALUES (?1, 1, 'c2s', ?2, 'tools/call', '42', 1, 0)",
            rusqlite::params![sid, raw],
        )
        .unwrap();
    }
    let msg_id = query_i64(&db, "SELECT id FROM messages WHERE method='tools/call' ORDER BY id LIMIT 1");

    let db_arg = db.to_str().unwrap().to_owned();
    let (out, err, code) = tokio::task::spawn_blocking(move || {
        let mut cmd = Command::new(MCPGLASS);
        cmd.args(["replay", &msg_id.to_string(), "--db", &db_arg]);
        run_capture_err(cmd, b"")
    })
    .await
    .unwrap();

    assert_eq!(code, 1, "replay must fail (exit 1) when the upstream rejects the request");
    assert!(
        String::from_utf8_lossy(&out).trim().is_empty(),
        "a failed replay must not print a fake success on stdout"
    );
    assert!(
        err.contains("server error") && err.contains("401"),
        "the error must surface the upstream 401, not a success: {err}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// dashboard endpoint (in-process serve + stub ReplayFn).
// ---------------------------------------------------------------------------

/// Spawn `dashboard::serve` on port 0 with the given replay backend; return the
/// bound address (via the `on_ready` callback, like `mcpglass dashboard`).
async fn spawn_dashboard(db: PathBuf, replay: Option<dashboard::ReplayFn>) -> SocketAddr {
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut tx = Some(tx);
        let _ = dashboard::serve(db, 0, replay, move |addr| {
            let _ = tx.take().unwrap().send(addr);
        })
        .await;
    });
    rx.await.expect("dashboard bound to an address")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dashboard_replay_endpoint_maps_statuses() {
    // A stub backend: id 1 succeeds (200), any other id is NotReplayable (400).
    let stub: dashboard::ReplayFn = Arc::new(|id: i64| {
        Box::pin(async move {
            if id == 1 {
                Ok(dashboard::ReplayOutcome {
                    transport: "stdio".to_owned(),
                    response_raw: Some(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#.to_owned()),
                    note: "stub replay".to_owned(),
                })
            } else {
                Err(dashboard::ReplayError::NotReplayable(format!(
                    "message {id} is not a replayable request"
                )))
            }
        }) as Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<dashboard::ReplayOutcome, dashboard::ReplayError>,
                    > + Send,
            >,
        >
    });

    let dir = temp_dir("dash-ok");
    let addr = spawn_dashboard(dir.join("sessions.db"), Some(stub)).await;
    let client = reqwest::Client::new();

    // 200 + JSON body for a replayable message.
    let ok = client
        .post(format!("http://{addr}/api/messages/1/replay"))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    let body: serde_json::Value = ok.json().await.unwrap();
    assert_eq!(body["transport"], serde_json::json!("stdio"));
    assert_eq!(body["note"], serde_json::json!("stub replay"));

    // 400 for a non-replayable message.
    let bad = client
        .post(format!("http://{addr}/api/messages/2/replay"))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 400);

    // A second instance with no backend answers 501.
    let dir2 = temp_dir("dash-none");
    let addr2 = spawn_dashboard(dir2.join("sessions.db"), None).await;
    let none = client
        .post(format!("http://{addr2}/api/messages/1/replay"))
        .send()
        .await
        .unwrap();
    assert_eq!(none.status(), 501);

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
}
