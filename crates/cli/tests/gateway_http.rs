//! End-to-end checks of `mcpglass gateway`, the HTTP reverse proxy for url-type
//! (Streamable HTTP) MCP servers.
//!
//! Shape mirrors the repo's other end-to-end tests: the gateway is launched as the
//! real binary (`CARGO_BIN_EXE_mcpglass`) and driven with reqwest, while a fake
//! upstream MCP server runs in-process (axum) so "the upstream received the
//! request" is observable — the marker technique from `security_gate.rs`. The
//! session DB is read back with rusqlite to prove the tap landed.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;

const MCPGLASS: &str = env!("CARGO_BIN_EXE_mcpglass");

// ---------------------------------------------------------------------------
// Test scaffolding.
// ---------------------------------------------------------------------------

/// A private temp dir unique to this test run, cleaned on drop.
struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "mcpglass-gw-test-{}-{}-{:?}",
            tag,
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Grab an OS-assigned free port, then release it so the gateway can bind it.
/// (Small reuse race, tolerable for a loopback test.)
fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// A running `mcpglass gateway` subprocess; killed on drop.
struct Gateway {
    child: Child,
    port: u16,
    db: PathBuf,
    _dir: TempDir,
}
impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Launch `mcpglass gateway` on a free port with an explicit policy and upstream
/// map, then wait until it is accepting connections.
async fn spawn_gateway(tag: &str, policy_toml: &str, upstreams: &[(&str, String)]) -> Gateway {
    let dir = TempDir::new(tag);
    let db = dir.0.join("sessions.db");
    let log = dir.0.join("mcpglass.log");
    let policy = dir.0.join("policy.toml");
    std::fs::write(&policy, policy_toml).unwrap();
    // `--port 0` lets the OS pick the port, so concurrent tests can never race
    // each other for a number pre-picked by a bind-and-release probe. The gateway
    // prints its banner only after the listener is really bound (`on_ready` gets
    // the actual local_addr), so parsing the port out of it doubles as the
    // readiness wait.
    let mut cmd = Command::new(MCPGLASS);
    cmd.args([
        "gateway",
        "--port",
        "0",
        "--db",
        db.to_str().unwrap(),
        "--log",
        log.to_str().unwrap(),
        "--policy",
        policy.to_str().unwrap(),
    ]);
    for (name, url) in upstreams {
        cmd.arg("--upstream").arg(format!("{name}={url}"));
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = cmd.spawn().expect("spawn gateway");
    let port = read_banner_port(&mut child);

    Gateway {
        child,
        port,
        db,
        _dir: dir,
    }
}

/// Block until the gateway's "Gateway listening on http://127.0.0.1:<port> ..."
/// banner arrives on the child's piped stdout and return the OS-assigned port.
fn read_banner_port(child: &mut std::process::Child) -> u16 {
    use std::io::BufRead;
    let mut banner = String::new();
    let out = child.stdout.as_mut().expect("gateway stdout piped");
    std::io::BufReader::new(out)
        .read_line(&mut banner)
        .expect("read gateway banner");
    banner
        .split("127.0.0.1:")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|p| p.parse().ok())
        .unwrap_or_else(|| panic!("unexpected gateway banner: {banner:?}"))
}

/// Poll `f` until it returns `Some` or the budget runs out.
async fn wait_until<F: FnMut() -> Option<()>>(mut budget_ms: u64, mut f: F) -> bool {
    let step = 40;
    loop {
        if f().is_some() {
            return true;
        }
        if budget_ms == 0 {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(step)).await;
        budget_ms = budget_ms.saturating_sub(step);
    }
}

fn count_rows(db: &PathBuf, sql: &str) -> Option<i64> {
    let conn = rusqlite::Connection::open(db).ok()?;
    conn.query_row(sql, [], |r| r.get(0)).ok()
}

// ---------------------------------------------------------------------------
// Fake upstream MCP server (in-process).
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct UpstreamState {
    /// Every POST body the upstream received (to prove blocked calls never arrive).
    bodies: Arc<Mutex<Vec<String>>>,
}

/// A `tools/list` gets an SSE response carrying a `search` tool; anything else gets
/// a plain `application/json` result. Both stamp an `Mcp-Session-Id` header so we
/// can check header pass-through.
async fn upstream_post(State(st): State<UpstreamState>, body: axum::body::Bytes) -> Response {
    st.bodies
        .lock()
        .unwrap()
        .push(String::from_utf8_lossy(&body).into_owned());

    let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    let method = v.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let id = v.get("id").cloned().unwrap_or(serde_json::Value::Null);

    if method == "tools/list" {
        let payload = serde_json::json!({
            "jsonrpc": "2.0", "id": id,
            "result": { "tools": [ { "name": "search", "description": "find things" } ] }
        });
        let sse = format!("event: message\ndata: {payload}\n\n");
        (
            [
                ("content-type", "text/event-stream"),
                ("mcp-session-id", "sess-abc"),
            ],
            sse,
        )
            .into_response()
    } else {
        let payload = serde_json::json!({
            "jsonrpc": "2.0", "id": id, "result": { "ok": true, "echo": method }
        });
        (
            [
                ("content-type", "application/json"),
                ("mcp-session-id", "sess-abc"),
            ],
            serde_json::to_vec(&payload).unwrap(),
        )
            .into_response()
    }
}

async fn upstream_get() -> Response {
    let sse = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tick\"}\n\n";
    ([("content-type", "text/event-stream")], sse).into_response()
}

/// A `/json` route that answers *every* request — including `tools/list` — with a
/// buffered `application/json` body (advertising a `jsontool`). This is the path
/// that would break fingerprint correlation if the c2s request were tapped after
/// the s2c response instead of before it.
async fn upstream_post_json(State(st): State<UpstreamState>, body: axum::body::Bytes) -> Response {
    st.bodies
        .lock()
        .unwrap()
        .push(String::from_utf8_lossy(&body).into_owned());
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    let id = v.get("id").cloned().unwrap_or(serde_json::Value::Null);
    let payload = serde_json::json!({
        "jsonrpc": "2.0", "id": id,
        "result": { "tools": [ { "name": "jsontool", "description": "buffered" } ] }
    });
    (
        [("content-type", "application/json")],
        serde_json::to_vec(&payload).unwrap(),
    )
        .into_response()
}

/// Start the fake upstream on a loopback port; return (address, received-bodies handle).
async fn spawn_upstream() -> (std::net::SocketAddr, Arc<Mutex<Vec<String>>>) {
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let state = UpstreamState {
        bodies: bodies.clone(),
    };
    let app = Router::new()
        .route(
            "/",
            post(upstream_post).get(upstream_get).delete(|| async { axum::http::StatusCode::OK }),
        )
        .route("/json", post(upstream_post_json))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, bodies)
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

/// Monitor mode: JSON + SSE pass-through with header fidelity, the tap landing in
/// SQLite (including a fingerprint for an SSE `tools/list`), an unreachable upstream
/// yielding 502, and a foreign Origin rejected with 403.
#[tokio::test]
async fn monitor_passthrough_tap_and_edges() {
    let (up_addr, up_bodies) = spawn_upstream().await;
    let dead = free_port(); // nothing will listen here
    let gw = spawn_gateway(
        "monitor",
        "mode = \"monitor\"\n",
        &[
            ("echo", format!("http://{up_addr}/")),
            ("echojson", format!("http://{up_addr}/json")),
            ("dead", format!("http://127.0.0.1:{dead}/")),
        ],
    )
    .await;
    let base = format!("http://127.0.0.1:{}", gw.port);
    let client = reqwest::Client::new();

    // (1) JSON response body + Mcp-Session-Id pass straight through.
    let resp = client
        .post(format!("{base}/u/echo"))
        .header("content-type", "application/json")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("mcp-session-id").unwrap(), "sess-abc");
    let ct = resp.headers().get("content-type").unwrap().to_str().unwrap().to_owned();
    assert!(ct.starts_with("application/json"), "content-type was {ct}");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["id"], serde_json::json!(1));
    assert_eq!(body["result"]["ok"], serde_json::json!(true));

    // (2)+(7) tools/list over SSE: streamed through to the client verbatim.
    let resp = client
        .post(format!("{base}/u/echo"))
        .header("content-type", "application/json")
        .body(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let ct = resp.headers().get("content-type").unwrap().to_str().unwrap().to_owned();
    assert!(ct.starts_with("text/event-stream"), "content-type was {ct}");
    let sse = resp.text().await.unwrap();
    assert!(sse.contains("\"search\""), "SSE body must carry the tools payload: {sse}");

    // (7b) a tools/list returned as a *buffered* application/json body must also be
    // fingerprinted — the c2s request has to be recorded before the s2c response.
    let resp = client
        .post(format!("{base}/u/echojson"))
        .header("content-type", "application/json")
        .body(r#"{"jsonrpc":"2.0","id":5,"method":"tools/list"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["result"]["tools"][0]["name"], serde_json::json!("jsontool"));

    // (5) an upstream that refuses the connection -> honest 502.
    let resp = client
        .post(format!("{base}/u/dead"))
        .body(r#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 502);

    // (6) a non-localhost Origin -> 403 (DNS-rebinding guard).
    let resp = client
        .post(format!("{base}/u/echo"))
        .header("origin", "http://evil.example")
        .body(r#"{"jsonrpc":"2.0","id":4,"method":"ping"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // (2) the SSE event was tapped into the messages table (s2c).
    let db = gw.db.clone();
    assert!(
        wait_until(3000, || {
            count_rows(
                &db,
                "SELECT COUNT(*) FROM messages WHERE direction='s2c' AND raw LIKE '%search%'",
            )
            .filter(|&n| n >= 1)
            .map(|_| ())
        })
        .await,
        "the SSE tools/list response must be recorded as an s2c message"
    );

    // (7) and fingerprinted (correlated to the c2s tools/list request).
    let db = gw.db.clone();
    assert!(
        wait_until(3000, || {
            count_rows(
                &db,
                "SELECT COUNT(*) FROM tool_fingerprints WHERE tool_name='search'",
            )
            .filter(|&n| n >= 1)
            .map(|_| ())
        })
        .await,
        "an SSE tools/list must be fingerprinted"
    );

    // (7b) the buffered application/json tools/list was also fingerprinted, proving
    // the c2s-before-s2c recording order holds on the non-streamed path too.
    let db = gw.db.clone();
    assert!(
        wait_until(3000, || {
            count_rows(
                &db,
                "SELECT COUNT(*) FROM tool_fingerprints WHERE tool_name='jsontool'",
            )
            .filter(|&n| n >= 1)
            .map(|_| ())
        })
        .await,
        "a buffered application/json tools/list must be fingerprinted"
    );

    // Sanity: the upstream really did receive the forwarded requests.
    assert!(up_bodies.lock().unwrap().iter().any(|b| b.contains("tools/list")));
}

/// The gateway passively records the `MCP-Protocol-Version` header a client sends on
/// its requests: with no `initialize` handshake observed (the fake upstream answers a
/// plain result, not an `initialize` response), the header hint is what pins the
/// session's protocol version — recorded once, source `header`.
#[tokio::test]
async fn protocol_version_header_is_recorded_as_hint() {
    let (up_addr, _up_bodies) = spawn_upstream().await;
    let gw = spawn_gateway(
        "proto-hint",
        "mode = \"monitor\"\n",
        &[("echo", format!("http://{up_addr}/"))],
    )
    .await;
    let base = format!("http://127.0.0.1:{}", gw.port);
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base}/u/echo"))
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2025-11-25")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let db = gw.db.clone();
    assert!(
        wait_until(3000, || {
            count_rows(
                &db,
                "SELECT COUNT(*) FROM sessions
                 WHERE protocol_version='2025-11-25' AND protocol_version_source='header'",
            )
            .filter(|&n| n >= 1)
            .map(|_| ())
        })
        .await,
        "the MCP-Protocol-Version header must be recorded as a header-source hint"
    );
}

/// A DNS-rebound browser sends a same-origin `GET` with *no* `Origin` header at
/// all (per the Fetch spec) but still carries a `Host` naming the attacker's
/// domain — the gap `Origin`-only checking misses. A forged `Host` must be
/// rejected even with no `Origin` present; a loopback `Host` still works.
#[tokio::test]
async fn foreign_host_is_rejected() {
    let (up_addr, _up_bodies) = spawn_upstream().await;
    let gw = spawn_gateway(
        "host-gate",
        "mode = \"monitor\"\n",
        &[("echo", format!("http://{up_addr}/"))],
    )
    .await;
    let base = format!("http://127.0.0.1:{}", gw.port);
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{base}/u/echo"))
        .header("host", "evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "a forged Host must be rejected even with no Origin header");

    let resp = client
        .get(format!("{base}/u/echo"))
        .header("host", "127.0.0.1")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "a loopback Host must still be allowed");
}

/// Enforce mode: a denied `tools/call` with an id is answered in-protocol
/// (200 / -32001) and never reaches the upstream; a denied notification (no id)
/// is acknowledged with 202. The marker proves neither reaches the upstream.
#[tokio::test]
async fn enforce_blocks_deny_and_notification() {
    const MARKER: &str = "ZZBLOCKMARKER";
    let (up_addr, up_bodies) = spawn_upstream().await;
    let gw = spawn_gateway(
        "enforce",
        "mode = \"enforce\"\ndeny = [\"dangerous_tool\"]\n",
        &[("echo", format!("http://{up_addr}/"))],
    )
    .await;
    let base = format!("http://127.0.0.1:{}", gw.port);
    let client = reqwest::Client::new();

    // (3) denied request (has id) -> 200 application/json with a -32001 error echoing the id.
    let call = format!(
        r#"{{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{{"name":"dangerous_tool","arguments":{{"note":"{MARKER}"}}}}}}"#
    );
    let resp = client.post(format!("{base}/u/echo")).body(call).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let ct = resp.headers().get("content-type").unwrap().to_str().unwrap().to_owned();
    assert!(ct.starts_with("application/json"), "content-type was {ct}");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["id"], serde_json::json!(42), "the error must echo the request id");
    assert_eq!(body["error"]["code"], serde_json::json!(-32001));

    // (4) denied notification (no id) -> 202 Accepted, no body.
    let notif =
        r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"dangerous_tool","arguments":{}}}"#;
    let resp = client.post(format!("{base}/u/echo")).body(notif).send().await.unwrap();
    assert_eq!(resp.status(), 202);
    assert!(resp.text().await.unwrap().is_empty(), "a 202 acknowledgement carries no body");

    // Neither blocked message reached the upstream.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let seen = up_bodies.lock().unwrap();
    assert!(
        !seen.iter().any(|b| b.contains(MARKER)),
        "the blocked request must never reach the upstream"
    );
    assert!(
        !seen.iter().any(|b| b.contains("dangerous_tool")),
        "no denied call should reach the upstream"
    );
}
