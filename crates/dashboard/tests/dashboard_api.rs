//! End-to-end test of the dashboard HTTP API: builds a real SQLite fixture via
//! the `storage` crate, serves it on a loopback port, and hits every endpoint
//! with real HTTP requests.

use std::path::PathBuf;
use std::time::Duration;

use proxy_core::{parse_line, Direction};
use storage::{Record, Store};

/// A private temp dir unique to this test run, cleaned on drop.
struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "mcpglass-dashboard-test-{}-{}-{:?}",
            tag,
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
    fn db(&self) -> PathBuf {
        self.0.join("sessions.db")
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn rec(direction: Direction, ts_ms: i64, raw: &str) -> Record {
    let p = parse_line(raw.as_bytes(), direction);
    Record {
        ts_ms,
        direction,
        raw: raw.to_owned(),
        method: p.method,
        rpc_id: p.rpc_id,
        is_valid_json: p.is_valid_json,
        is_error: p.is_error,
    }
}

/// Build a fixture DB with one session and 122 messages: alternating
/// ping request/response pairs, a batch of notifications, and one error
/// response, so pagination (>100), method/direction filters, and stats all
/// have something to chew on.
fn build_fixture() -> (TempDir, i64) {
    let tmp = TempDir::new("api");
    let store = Store::open(&tmp.db()).unwrap();
    let sid = store.begin_session("fixture", "echo fixture").unwrap();

    let mut ts = 1i64;
    // 60 ping request/response pairs -> 120 messages.
    for i in 0..60 {
        store
            .insert(
                sid,
                &rec(
                    Direction::C2s,
                    ts,
                    &format!(r#"{{"id":{i},"method":"ping"}}"#),
                ),
            )
            .unwrap();
        ts += 1;
        store
            .insert(
                sid,
                &rec(Direction::S2c, ts, &format!(r#"{{"id":{i},"result":{{}}}}"#)),
            )
            .unwrap();
        ts += 1;
    }
    // A notification (c2s, no rpc_id).
    store
        .insert(
            sid,
            &rec(Direction::C2s, ts, r#"{"method":"notifications/x"}"#),
        )
        .unwrap();
    ts += 1;
    // An error response.
    store
        .insert(
            sid,
            &rec(
                Direction::S2c,
                ts,
                r#"{"id":999,"error":{"code":-32601,"message":"no"}}"#,
            ),
        )
        .unwrap();
    store.end_session(sid).unwrap();

    (tmp, sid)
}

async fn wait_for_server(base: &str) {
    let client = reqwest::Client::new();
    for _ in 0..50 {
        if client
            .get(format!("{base}/api/health"))
            .send()
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("dashboard server did not come up at {base}");
}

/// Spawn `dashboard::serve` on port 0 (OS-assigned) and return the actual
/// bound address, obtained via the `on_ready` callback rather than a
/// pre-bound throwaway listener — this is the same readiness signal
/// `mcpglass dashboard` uses to know when it's safe to print the URL / open
/// a browser tab.
async fn spawn_server(db_path: PathBuf) -> std::net::SocketAddr {
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut tx = Some(tx);
        dashboard::serve(db_path, 0, move |addr| {
            let _ = tx.take().unwrap().send(addr);
        })
        .await
    });
    rx.await.expect("on_ready fired with the bound address")
}

#[tokio::test]
async fn full_api_surface() {
    let (tmp, sid) = build_fixture();
    let db_path = tmp.db();
    let addr = spawn_server(db_path).await;

    let base = format!("http://{addr}");
    wait_for_server(&base).await;
    let client = reqwest::Client::new();

    // --- /api/health ---
    let health: serde_json::Value = client
        .get(format!("{base}/api/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(health["version"].is_string());

    // --- /api/sessions ---
    let sessions: serde_json::Value = client
        .get(format!("{base}/api/sessions"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let list = sessions["sessions"].as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["id"].as_i64().unwrap(), sid);
    assert_eq!(list[0]["label"], "fixture");
    assert_eq!(list[0]["message_count"].as_u64().unwrap(), 122);
    assert!(list[0]["ended_at_ms"].is_number());

    // --- /api/sessions/{id}/messages: default page ---
    let page1: serde_json::Value = client
        .get(format!("{base}/api/sessions/{sid}/messages?limit=100"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(page1["total"].as_u64().unwrap(), 122);
    let msgs1 = page1["messages"].as_array().unwrap();
    assert_eq!(msgs1.len(), 100);
    // Chronological (ascending id) order.
    let first_id = msgs1[0]["id"].as_i64().unwrap();
    let last_id = msgs1[99]["id"].as_i64().unwrap();
    assert!(first_id < last_id);

    // --- pagination: offset=100 gets the remaining 22 ---
    let page2: serde_json::Value = client
        .get(format!(
            "{base}/api/sessions/{sid}/messages?limit=100&offset=100"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(page2["total"].as_u64().unwrap(), 122);
    assert_eq!(page2["messages"].as_array().unwrap().len(), 22);

    // --- direction filter ---
    let c2s: serde_json::Value = client
        .get(format!(
            "{base}/api/sessions/{sid}/messages?limit=1000&direction=c2s"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // 60 pings + 1 notification.
    assert_eq!(c2s["total"].as_u64().unwrap(), 61);
    for m in c2s["messages"].as_array().unwrap() {
        assert_eq!(m["direction"], "c2s");
    }

    // --- method filter ---
    let pings: serde_json::Value = client
        .get(format!(
            "{base}/api/sessions/{sid}/messages?limit=1000&method=ping"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(pings["total"].as_u64().unwrap(), 60);

    // --- limit above the 1000 cap: server clamps rather than erroring ---
    let clamped: serde_json::Value = client
        .get(format!("{base}/api/sessions/{sid}/messages?limit=5000"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(clamped["messages"].as_array().unwrap().len(), 122);

    // --- /api/messages/{id} ---
    let some_id = msgs1[0]["id"].as_i64().unwrap();
    let detail: serde_json::Value = client
        .get(format!("{base}/api/messages/{some_id}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail["id"].as_i64().unwrap(), some_id);
    assert_eq!(detail["session_id"].as_i64().unwrap(), sid);
    assert!(detail["raw"].as_str().unwrap().contains("ping"));

    // --- /api/messages/{id}: unknown id is 404 ---
    let missing = client
        .get(format!("{base}/api/messages/99999999"))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), reqwest::StatusCode::NOT_FOUND);

    // --- /api/sessions/{id}/stats ---
    let stats: serde_json::Value = client
        .get(format!("{base}/api/sessions/{sid}/stats"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let per_method = stats["per_method"].as_array().unwrap();
    let ping_stat = per_method
        .iter()
        .find(|m| m["method"] == "ping")
        .expect("ping stat present");
    assert_eq!(ping_stat["count"].as_u64().unwrap(), 60);
    assert!(ping_stat["avg_latency_ms"].is_number());
    assert_eq!(stats["totals"]["messages"].as_u64().unwrap(), 122);
    assert_eq!(stats["totals"]["errors"].as_u64().unwrap(), 1);

    // --- static frontend: SPA index at / ---
    let root = client.get(&base).send().await.unwrap();
    assert!(root
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("text/html"));
    let body = root.text().await.unwrap();
    assert!(body.contains("<div id=\"root\">"));

    // --- unknown client-side route also falls back to index.html ---
    let spa_route = client
        .get(format!("{base}/sessions/42"))
        .send()
        .await
        .unwrap();
    assert!(spa_route
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("text/html"));
}

#[tokio::test]
async fn empty_db_yields_empty_lists_not_errors() {
    let tmp = TempDir::new("empty");
    // Note: db file does not exist yet; `Store::open` inside the handler
    // creates it on first request.
    let addr = spawn_server(tmp.db()).await;

    let base = format!("http://{addr}");
    wait_for_server(&base).await;
    let client = reqwest::Client::new();

    let sessions: serde_json::Value = client
        .get(format!("{base}/api/sessions"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(sessions["sessions"].as_array().unwrap().len(), 0);
}

/// `on_ready` must fire with an address the listener actually bound to a real
/// OS-assigned port (0 in, non-zero out), and that address must already be
/// connectable by the time the callback runs.
#[tokio::test]
async fn on_ready_reports_bound_and_connectable_address() {
    let tmp = TempDir::new("on-ready");
    let addr = spawn_server(tmp.db()).await;

    assert_ne!(addr.port(), 0);
    tokio::net::TcpStream::connect(addr)
        .await
        .expect("address from on_ready should be immediately connectable");
}
