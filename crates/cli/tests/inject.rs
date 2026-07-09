//! End-to-end checks of Phase-3 fault injection (`--inject`), on both transports.
//!
//! The stdio (`wrap`) tests reuse the `echo-mcp` fixture and the marker technique
//! from `security_gate.rs`: because the echo server reflects every c2s line back on
//! s2c, "the server received the frame" is observable as "the frame was echoed to
//! our stdout". The gateway tests reuse the in-process fake upstream from
//! `gateway_http.rs`. All configs use `probability = 1.0` (the default) so every
//! matched frame is injected deterministically, with no RNG involved.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;

const MCPGLASS: &str = env!("CARGO_BIN_EXE_mcpglass");
const ECHO_MCP: &str = env!("CARGO_BIN_EXE_echo-mcp");

const INITIALIZE: &str = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n";

/// A token buried deep in a tools/call's arguments. It is echoed back only if the
/// server actually received the (whole) frame.
const MARKER: &str = "ZZINJECTMARKER";

/// A tools/call for `dangerous`, id 42, carrying `MARKER` late in its arguments.
fn tools_call() -> String {
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":42,\"method\":\"tools/call\",\
         \"params\":{{\"name\":\"do_it\",\"arguments\":{{\"note\":\"{MARKER}\"}}}}}}\n"
    )
}

// ---------------------------------------------------------------------------
// stdio (`wrap`) scaffolding.
// ---------------------------------------------------------------------------

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

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("mcpglass-injit-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run `wrap` through the echo server with a monitor policy and an inject config.
fn run_wrap_inject(dir: &Path, inject_toml: &str, input: &str) -> (Vec<u8>, i32, PathBuf) {
    let db = dir.join("sessions.db");
    let log = dir.join("mcpglass.log");
    let policy = dir.join("policy.toml");
    let inject = dir.join("inject.toml");
    std::fs::write(&policy, "mode = \"monitor\"\n").unwrap();
    std::fs::write(&inject, inject_toml).unwrap();

    let mut cmd = Command::new(MCPGLASS);
    cmd.args([
        "wrap",
        "--db",
        db.to_str().unwrap(),
        "--log",
        log.to_str().unwrap(),
        "--policy",
        policy.to_str().unwrap(),
        "--inject",
        inject.to_str().unwrap(),
        "--",
        ECHO_MCP,
    ]);
    let (out, code) = run_capture(cmd, input.as_bytes());
    (out, code, db)
}

/// Count `inject_events` rows for a fault token.
fn count_inject(db: &Path, fault: &str) -> i64 {
    let conn = rusqlite::Connection::open(db).expect("open db");
    conn.query_row(
        "SELECT COUNT(*) FROM inject_events WHERE fault = ?1",
        rusqlite::params![fault],
        |r| r.get(0),
    )
    .expect("count")
}

/// The single detail string recorded for a fault (asserts exactly one such row).
fn inject_detail(db: &Path, fault: &str) -> String {
    let conn = rusqlite::Connection::open(db).expect("open db");
    conn.query_row(
        "SELECT detail FROM inject_events WHERE fault = ?1",
        rusqlite::params![fault],
        |r| r.get(0),
    )
    .expect("detail")
}

// ---------------------------------------------------------------------------
// stdio tests.
// ---------------------------------------------------------------------------

#[test]
fn wrap_error_answers_client_and_withholds_from_server() {
    let dir = temp_dir("error");
    let inject = "[[rules]]\n\
         direction = \"c2s\"\n\
         method = \"tools/call\"\n\
         fault = { type = \"error\", code = -32000, message = \"injected boom\" }\n";
    let input = format!("{INITIALIZE}{}", tools_call());
    let (out, code, db) = run_wrap_inject(&dir, inject, &input);
    let stdout = String::from_utf8_lossy(&out);

    // The client got the injected error for id 42...
    assert!(stdout.contains("-32000"), "expected injected error code: {stdout}");
    assert!(stdout.contains("injected boom"), "expected injected message: {stdout}");
    assert!(stdout.contains("\"id\":42"), "the error must echo the request id: {stdout}");
    // ...and the server never saw the call (marker never echoed back).
    assert!(
        !stdout.contains(MARKER),
        "an errored c2s frame must not reach the server: {stdout}"
    );
    // The unmatched initialize still passed through and was echoed.
    assert!(stdout.contains("initialize"), "initialize should pass through: {stdout}");
    assert_eq!(code, 0);

    // Exactly one error inject event landed, tagged c2s.
    assert_eq!(count_inject(&db, "error"), 1);
    let conn = rusqlite::Connection::open(&db).unwrap();
    let dir_tok: String = conn
        .query_row(
            "SELECT direction FROM inject_events WHERE fault = 'error'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(dir_tok, "c2s");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn wrap_drop_yields_no_response() {
    let dir = temp_dir("drop");
    let inject = "[[rules]]\n\
         direction = \"c2s\"\n\
         method = \"tools/call\"\n\
         fault = { type = \"drop\" }\n";
    let input = format!("{INITIALIZE}{}", tools_call());
    let (out, code, db) = run_wrap_inject(&dir, inject, &input);
    let stdout = String::from_utf8_lossy(&out);

    // A dropped c2s frame is neither forwarded nor answered: no marker, no error.
    assert!(!stdout.contains(MARKER), "dropped frame must not reach the server: {stdout}");
    assert!(!stdout.contains("error"), "drop must not synthesize a response: {stdout}");
    // initialize (unmatched) still echoed.
    assert!(stdout.contains("initialize"), "initialize should pass through: {stdout}");
    assert_eq!(code, 0);
    assert_eq!(count_inject(&db, "drop"), 1);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn wrap_truncate_forwards_only_a_prefix() {
    let dir = temp_dir("truncate");
    // Craft the frame so an early token sits within the first 20 bytes and a late
    // token sits past them; truncation must keep the former and cut the latter.
    // (Hand-written JSON so the byte layout is exact; `method` still parses as
    // tools/call for the rule to match on the *whole* frame.)
    const EARLY: &str = "EARLYKEEP";
    const LATE: &str = "LATECUTZZ";
    let frame = format!(
        "{{\"note\":\"{EARLY}\",\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\
         \"params\":{{\"name\":\"t\",\"arguments\":{{\"x\":\"{LATE}\"}}}}}}\n"
    );
    let inject = "[[rules]]\n\
         direction = \"c2s\"\n\
         method = \"tools/call\"\n\
         fault = { type = \"truncate\", bytes = 20 }\n";
    let (out, code, db) = run_wrap_inject(&dir, inject, &frame);
    let stdout = String::from_utf8_lossy(&out);

    // The server received (and echoed) the truncated prefix, so the early token is
    // present but the late token — beyond the cut — is not.
    assert!(stdout.contains(EARLY), "truncated prefix should reach the server: {stdout}");
    assert!(
        !stdout.contains(LATE),
        "bytes past the truncation point must be cut: {stdout}"
    );
    assert_eq!(code, 0);
    assert_eq!(count_inject(&db, "truncate"), 1);
    // The detail records the truncation size (20 of the full length).
    assert!(inject_detail(&db, "truncate").contains("to 20 of"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn wrap_delay_defers_forwarding() {
    let dir = temp_dir("delay");
    let delay_ms = 600u64;
    let inject = format!(
        "[[rules]]\n\
         direction = \"c2s\"\n\
         method = \"tools/call\"\n\
         fault = {{ type = \"delay\", delay_ms = {delay_ms} }}\n"
    );
    let input = format!("{INITIALIZE}{}", tools_call());

    let start = Instant::now();
    let (out, code, db) = run_wrap_inject(&dir, &inject, &input);
    let elapsed = start.elapsed();
    let stdout = String::from_utf8_lossy(&out);

    // A delayed frame is still forwarded (marker echoed), just late: the whole run
    // cannot finish before the injected sleep elapses.
    assert!(stdout.contains(MARKER), "delay must still forward the frame: {stdout}");
    assert!(
        elapsed >= Duration::from_millis(delay_ms - 150),
        "run finished in {elapsed:?}, expected at least ~{delay_ms}ms from the injected delay"
    );
    assert_eq!(code, 0);
    assert_eq!(count_inject(&db, "delay"), 1);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn wrap_broken_inject_aborts_before_forwarding() {
    let dir = temp_dir("broken");
    // A probability out of range must abort startup, not fall open to "no injection".
    let inject = "[[rules]]\ndirection=\"c2s\"\nprobability=2.0\nfault={type=\"drop\"}\n";
    let (out, code, _db) = run_wrap_inject(&dir, inject, INITIALIZE);

    assert_ne!(code, 0, "a broken inject config must make wrap exit non-zero");
    assert!(out.is_empty(), "no traffic should flow on an inject-config abort: {out:?}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn wrap_s2c_error_replaces_server_response() {
    let dir = temp_dir("s2c-error");
    // Inject on the server->client leg: the echo of our tools/call (a response the
    // echo server sends back) is replaced by an injected error carrying its id.
    let inject = "[[rules]]\n\
         direction = \"s2c\"\n\
         method = \"tools/call\"\n\
         fault = { type = \"error\", code = -32050, message = \"s2c boom\" }\n";
    let input = format!("{INITIALIZE}{}", tools_call());
    let (out, code, _db) = run_wrap_inject(&dir, inject, &input);
    let stdout = String::from_utf8_lossy(&out);

    // The echoed tools/call (s2c, method tools/call) is replaced by the error, so the
    // original marker never reaches the client but the injected error does (id 42).
    assert!(stdout.contains("-32050"), "expected the injected s2c error: {stdout}");
    assert!(stdout.contains("\"id\":42"), "the error must carry the frame id: {stdout}");
    assert!(
        !stdout.contains(MARKER),
        "the replaced s2c frame must not reach the client: {stdout}"
    );
    // initialize's echo (method initialize, unmatched) still arrives intact.
    assert!(stdout.contains("initialize"), "initialize echo should pass through: {stdout}");
    assert_eq!(code, 0);

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// gateway scaffolding (fake upstream + spawned binary), mirroring gateway_http.rs.
// ---------------------------------------------------------------------------

struct TempDirG(PathBuf);
impl TempDirG {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "mcpglass-inj-gw-{}-{}-{:?}",
            tag,
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        TempDirG(dir)
    }
}
impl Drop for TempDirG {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

struct Gateway {
    child: std::process::Child,
    port: u16,
    db: PathBuf,
    _dir: TempDirG,
}
impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Launch `mcpglass gateway` with a monitor policy, an inject config, and an
/// upstream map, then wait until it accepts connections.
async fn spawn_gateway_inject(tag: &str, inject_toml: &str, upstreams: &[(&str, String)]) -> Gateway {
    let dir = TempDirG::new(tag);
    let db = dir.0.join("sessions.db");
    let log = dir.0.join("mcpglass.log");
    let policy = dir.0.join("policy.toml");
    let inject = dir.0.join("inject.toml");
    std::fs::write(&policy, "mode = \"monitor\"\n").unwrap();
    std::fs::write(&inject, inject_toml).unwrap();
    // free_port() releases its socket before the gateway re-binds the number, so a
    // concurrently starting test can be handed the same ephemeral port (Linux reuses
    // them eagerly). The loser exits at bind time while a bare TCP probe happily
    // connects to the *other* test's gateway — so retry on a fresh port whenever our
    // child died, and only accept a port once our child is both alive and accepting.
    let mut launched = None;
    for _ in 0..5 {
        let port = free_port();
        let mut cmd = Command::new(MCPGLASS);
        cmd.args([
            "gateway",
            "--port",
            &port.to_string(),
            "--db",
            db.to_str().unwrap(),
            "--log",
            log.to_str().unwrap(),
            "--policy",
            policy.to_str().unwrap(),
            "--inject",
            inject.to_str().unwrap(),
        ]);
        for (name, url) in upstreams {
            cmd.arg("--upstream").arg(format!("{name}={url}"));
        }
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        let mut child = cmd.spawn().expect("spawn gateway");

        let mut up = false;
        for _ in 0..100 {
            if child.try_wait().expect("poll gateway child").is_some() {
                break;
            }
            if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                up = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        if up && child.try_wait().expect("poll gateway child").is_none() {
            launched = Some((child, port));
            break;
        }
        let _ = child.kill();
        let _ = child.wait();
    }
    let (child, port) = launched.expect("gateway did not come up after 5 port attempts");

    Gateway {
        child,
        port,
        db,
        _dir: dir,
    }
}

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

#[derive(Clone)]
struct UpstreamState {
    bodies: Arc<Mutex<Vec<String>>>,
}

async fn upstream_post(State(st): State<UpstreamState>, body: axum::body::Bytes) -> Response {
    st.bodies
        .lock()
        .unwrap()
        .push(String::from_utf8_lossy(&body).into_owned());
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    let id = v.get("id").cloned().unwrap_or(serde_json::Value::Null);
    let payload = serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": { "ok": true } });
    (
        [("content-type", "application/json")],
        serde_json::to_vec(&payload).unwrap(),
    )
        .into_response()
}

async fn spawn_upstream() -> (std::net::SocketAddr, Arc<Mutex<Vec<String>>>) {
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/", post(upstream_post))
        .with_state(UpstreamState {
            bodies: bodies.clone(),
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, bodies)
}

// ---------------------------------------------------------------------------
// gateway tests.
// ---------------------------------------------------------------------------

/// A c2s `drop` on the gateway acknowledges with 202 and never contacts the upstream.
#[tokio::test]
async fn gateway_drop_returns_202_and_skips_upstream() {
    const CALLMARK: &str = "ZZGWDROP";
    let (up_addr, up_bodies) = spawn_upstream().await;
    let gw = spawn_gateway_inject(
        "gw-drop",
        "[[rules]]\ndirection=\"c2s\"\nmethod=\"tools/call\"\nfault={type=\"drop\"}\n",
        &[("echo", format!("http://{up_addr}/"))],
    )
    .await;
    let base = format!("http://127.0.0.1:{}", gw.port);
    let client = reqwest::Client::new();

    let call = format!(
        r#"{{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{{"name":"t","arguments":{{"n":"{CALLMARK}"}}}}}}"#
    );
    let resp = client.post(format!("{base}/u/echo")).body(call).send().await.unwrap();
    assert_eq!(resp.status(), 202, "a dropped request is acknowledged with 202");
    assert!(resp.text().await.unwrap().is_empty(), "202 carries no body");

    // The upstream was never contacted.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !up_bodies.lock().unwrap().iter().any(|b| b.contains(CALLMARK)),
        "a dropped request must not reach the upstream"
    );

    // The drop inject event landed.
    let db = gw.db.clone();
    assert!(
        wait_until(3000, || count_rows(
            &db,
            "SELECT COUNT(*) FROM inject_events WHERE fault='drop' AND direction='c2s'"
        )
        .filter(|&n| n >= 1)
        .map(|_| ()))
        .await,
        "a c2s drop must be recorded in inject_events"
    );
}

/// A c2s `error` on the gateway answers 200 application/json with the injected
/// error body and never contacts the upstream.
#[tokio::test]
async fn gateway_error_returns_synth_body_and_skips_upstream() {
    const CALLMARK: &str = "ZZGWERR";
    let (up_addr, up_bodies) = spawn_upstream().await;
    let gw = spawn_gateway_inject(
        "gw-error",
        "[[rules]]\ndirection=\"c2s\"\nmethod=\"tools/call\"\n\
         fault={type=\"error\",code=-32070,message=\"gw boom\"}\n",
        &[("echo", format!("http://{up_addr}/"))],
    )
    .await;
    let base = format!("http://127.0.0.1:{}", gw.port);
    let client = reqwest::Client::new();

    let call = format!(
        r#"{{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{{"name":"t","arguments":{{"n":"{CALLMARK}"}}}}}}"#
    );
    let resp = client.post(format!("{base}/u/echo")).body(call).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let ct = resp.headers().get("content-type").unwrap().to_str().unwrap().to_owned();
    assert!(ct.starts_with("application/json"), "content-type was {ct}");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["id"], serde_json::json!(8), "the error must echo the request id");
    assert_eq!(body["error"]["code"], serde_json::json!(-32070));
    assert!(body["error"]["message"].as_str().unwrap().contains("gw boom"));

    // The upstream was never contacted.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !up_bodies.lock().unwrap().iter().any(|b| b.contains(CALLMARK)),
        "an errored request must not reach the upstream"
    );

    let db = gw.db.clone();
    assert!(
        wait_until(3000, || count_rows(
            &db,
            "SELECT COUNT(*) FROM inject_events WHERE fault='error' AND direction='c2s'"
        )
        .filter(|&n| n >= 1)
        .map(|_| ()))
        .await,
        "a c2s error must be recorded in inject_events"
    );
}
