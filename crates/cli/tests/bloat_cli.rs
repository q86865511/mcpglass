//! End-to-end check of `mcpglass bloat`: seed a session with a captured
//! `tools/list` round-trip via the `storage` crate, run the subcommand as a
//! subprocess, and check its stdout reports the tool names and labels the
//! estimate approximate (the zero-dependency chars/4 heuristic, never a real
//! tokenizer count).

use std::path::PathBuf;
use std::process::{Command, Stdio};

use proxy_core::{parse_line, Direction};
use storage::{Record, Store};

const MCPGLASS: &str = env!("CARGO_BIN_EXE_mcpglass");

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "mcpglass-bloat-cli-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
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

fn run_capture(mut cmd: Command) -> (String, i32) {
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let output = cmd.output().expect("spawn mcpglass bloat");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    (stdout, output.status.code().unwrap_or(-1))
}

#[test]
fn bloat_reports_tool_names_and_marks_the_estimate_approximate() {
    let dir = temp_dir("basic");
    let db = dir.join("sessions.db");

    let sid = {
        let store = Store::open(&db).unwrap();
        let sid = store.begin_session("bloat-fixture", "echo").unwrap();
        store
            .insert(sid, &rec(Direction::C2s, 1, r#"{"id":1,"method":"tools/list"}"#))
            .unwrap();
        let resp = r#"{"id":1,"result":{"tools":[
            {"name":"search_web","description":"Searches the web for a query."},
            {"name":"fetch_url","description":"Fetches a URL."}
        ]}}"#;
        store.insert(sid, &rec(Direction::S2c, 2, resp)).unwrap();
        store.end_session(sid).unwrap();
        sid
    };

    let mut cmd = Command::new(MCPGLASS);
    cmd.args(["bloat", "--db", db.to_str().unwrap(), "--session", &sid.to_string()]);
    let (stdout, code) = run_capture(cmd);
    assert_eq!(code, 0, "bloat should exit cleanly: {stdout}");
    assert!(stdout.contains("search_web"), "stdout should list tool names: {stdout}");
    assert!(stdout.contains("fetch_url"), "stdout should list tool names: {stdout}");
    assert!(
        stdout.to_lowercase().contains("approximate"),
        "stdout must label the estimate approximate: {stdout}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bloat_defaults_to_the_most_recently_started_session_when_none_given() {
    let dir = temp_dir("default-session");
    let db = dir.join("sessions.db");

    {
        let store = Store::open(&db).unwrap();
        // Older session: no tools/list captured.
        let old_sid = store.begin_session("older", "echo").unwrap();
        store.end_session(old_sid).unwrap();
        // Newest session: has a tools/list round-trip.
        let sid = store.begin_session("newest", "echo").unwrap();
        store
            .insert(sid, &rec(Direction::C2s, 1, r#"{"id":1,"method":"tools/list"}"#))
            .unwrap();
        store
            .insert(
                sid,
                &rec(
                    Direction::S2c,
                    2,
                    r#"{"id":1,"result":{"tools":[{"name":"only_tool","description":"d"}]}}"#,
                ),
            )
            .unwrap();
        store.end_session(sid).unwrap();
    }

    let mut cmd = Command::new(MCPGLASS);
    cmd.args(["bloat", "--db", db.to_str().unwrap()]);
    let (stdout, code) = run_capture(cmd);
    assert_eq!(code, 0, "bloat should exit cleanly: {stdout}");
    assert!(
        stdout.contains("only_tool"),
        "with no --session, bloat should default to the most recently started session: {stdout}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bloat_reports_no_tools_list_when_session_never_captured_one() {
    let dir = temp_dir("no-tools-list");
    let db = dir.join("sessions.db");

    let sid = {
        let store = Store::open(&db).unwrap();
        let sid = store.begin_session("no-catalog", "echo").unwrap();
        store
            .insert(sid, &rec(Direction::C2s, 1, r#"{"id":1,"method":"ping"}"#))
            .unwrap();
        store.end_session(sid).unwrap();
        sid
    };

    let mut cmd = Command::new(MCPGLASS);
    cmd.args(["bloat", "--db", db.to_str().unwrap(), "--session", &sid.to_string()]);
    let (stdout, code) = run_capture(cmd);
    assert_eq!(code, 0, "a session with no tools/list is not an error: {stdout}");
    assert!(
        stdout.contains("no tools/list captured"),
        "stdout should say nothing was captured: {stdout}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
