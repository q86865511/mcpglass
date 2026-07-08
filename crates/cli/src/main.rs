//! `mcpglass` — a transparent MCP stdio proxy.
//!
//! It spawns an MCP server as a child, wires our stdio to the child's stdio
//! byte-for-byte, and taps each direction into SQLite out of band. The tap is
//! strictly best-effort: forwarding always happens first and never waits on the
//! tap, so no proxy-side failure can alter or stall client<->server traffic
//! (fail-open is the whole point of Phase 0).

use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};

use clap::{Parser, Subcommand};
use proxy_core::{parse_line, Direction, LineSplitter};
use storage::{Record, Store};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;

/// Memory guard for a single un-terminated frame on the tap path. Well above any
/// realistic JSON-RPC message (the spike must handle >=10 MB payloads), yet still
/// bounded so a runaway stream can't exhaust memory. Forwarding ignores this.
const MAX_LINE_BYTES: usize = 64 * 1024 * 1024;

/// Read buffer size for each pump.
const READ_BUF_BYTES: usize = 64 * 1024;

#[derive(Parser)]
#[command(name = "mcpglass", about = "Transparent proxy for MCP stdio traffic")]
struct Cli {
    #[command(subcommand)]
    command: SubCmd,
}

#[derive(Subcommand)]
enum SubCmd {
    /// Wrap an MCP server: `mcpglass wrap [--db P] [--log P] -- <cmd> [args...]`.
    Wrap {
        /// SQLite session file. Defaults to <data_local>/mcpglass/sessions.db.
        #[arg(long)]
        db: Option<PathBuf>,
        /// Proxy diagnostics log. Defaults to <data_local>/mcpglass/mcpglass.log.
        /// Never written to stdout/stderr — those are the protocol channels.
        #[arg(long)]
        log: Option<PathBuf>,
        /// The server command and its args, after `--`.
        #[arg(last = true, required = true, num_args = 1.., allow_hyphen_values = true)]
        command: Vec<String>,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        SubCmd::Wrap { db, log, command } => {
            let code = run_wrap(db, log, command).await;
            std::process::exit(code);
        }
    }
}

/// One tapped frame handed to the storage thread. Off the hot path by design.
struct TapEvent {
    direction: Direction,
    ts_ms: i64,
    raw: Vec<u8>,
}

async fn run_wrap(db: Option<PathBuf>, log: Option<PathBuf>, command: Vec<String>) -> i32 {
    let program = command[0].clone();
    let args: Vec<String> = command[1..].to_vec();

    let data_dir = default_data_dir();
    let log_path = log.or_else(|| data_dir.as_ref().map(|d| d.join("mcpglass.log")));
    let db_path = db
        .or_else(|| data_dir.as_ref().map(|d| d.join("sessions.db")))
        .unwrap_or_else(|| std::env::temp_dir().join("mcpglass").join("sessions.db"));

    let logger = Logger::open(log_path.as_deref());
    logger.info(format!("wrap start: program={program} args={args:?} db={db_path:?}"));

    let mut child = match spawn_child(&program, &args, &logger).await {
        Ok(c) => c,
        Err(e) => {
            // Nothing to proxy if the server won't start. Report via the log only.
            logger.error(format!("failed to spawn `{program}`: {e:#}"));
            return 127;
        }
    };

    let child_stdin = child.stdin.take().expect("child stdin was piped");
    let child_stdout = child.stdout.take().expect("child stdout was piped");
    let mut child_stderr = child.stderr.take().expect("child stderr was piped");

    let (tx, rx) = mpsc::channel::<TapEvent>(8192);

    // Storage owns a sync rusqlite connection on a dedicated blocking thread.
    let storage = tokio::task::spawn_blocking({
        let logger = logger.clone();
        move || storage_loop(rx, db_path, logger)
    });

    // client -> server, tapped as c2s.
    let t_in = tokio::spawn(pump(
        tokio::io::stdin(),
        child_stdin,
        Direction::C2s,
        tx.clone(),
        logger.clone(),
        "c2s",
    ));
    // server -> client, tapped as s2c.
    let t_out = tokio::spawn(pump(
        child_stdout,
        tokio::io::stdout(),
        Direction::S2c,
        tx.clone(),
        logger.clone(),
        "s2c",
    ));
    // server stderr is the server's own diagnostic channel: raw passthrough, no tap.
    let t_err = tokio::spawn(async move {
        let mut our_err = tokio::io::stderr();
        let _ = tokio::io::copy(&mut child_stderr, &mut our_err).await;
    });

    drop(tx); // storage's channel now closes once both pumps drop their senders.

    let status = child.wait().await;

    // The server has exited. Drain its remaining stdout/stderr, then tear down the
    // client-side pump (its stdin read can block forever) and flush storage.
    let _ = t_out.await;
    let _ = t_err.await;
    t_in.abort();
    let _ = t_in.await;
    let _ = storage.await;

    match status {
        Ok(s) => {
            logger.info(format!("child exited: {s:?}"));
            // Mirror the child's exit code; fall back to 0 if signalled with none.
            s.code().unwrap_or(0)
        }
        Err(e) => {
            logger.error(format!("failed to wait on child: {e}"));
            1
        }
    }
}

/// Copy `reader` -> `writer` verbatim, tapping completed frames to `tx`.
///
/// Invariant: bytes are forwarded and flushed *before* the tap runs, and the tap
/// uses a non-blocking send. Neither a slow nor a broken storage side can ever
/// delay or drop the forwarded bytes.
async fn pump<R, W>(
    mut reader: R,
    mut writer: W,
    direction: Direction,
    tx: mpsc::Sender<TapEvent>,
    logger: Logger,
    ctx: &'static str,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut splitter = LineSplitter::new(MAX_LINE_BYTES);
    let mut buf = vec![0u8; READ_BUF_BYTES];
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) => break, // EOF
            Ok(n) => n,
            Err(e) => {
                logger.error(format!("{ctx}: read error: {e}"));
                break;
            }
        };

        // 1) Forward first — the wire is sacred.
        if let Err(e) = writer.write_all(&buf[..n]).await {
            logger.error(format!("{ctx}: write error: {e}"));
            break;
        }
        if let Err(e) = writer.flush().await {
            logger.error(format!("{ctx}: flush error: {e}"));
            break;
        }

        // 2) Tap second — best effort, never applies backpressure to the wire.
        for line in splitter.push(&buf[..n]) {
            let ev = TapEvent {
                direction,
                ts_ms: now_ms(),
                raw: line,
            };
            if tx.try_send(ev).is_err() {
                logger.error(format!("{ctx}: tap dropped (channel full/closed)"));
            }
        }
    }
    // Dropping `writer` here closes the child's stdin on EOF, letting it exit.
}

/// Drain the tap channel into SQLite. Runs on a blocking thread; a DB failure is
/// logged and the record dropped — recording stops, forwarding does not.
fn storage_loop(mut rx: mpsc::Receiver<TapEvent>, db_path: PathBuf, logger: Logger) {
    let store = match Store::open(&db_path) {
        Ok(s) => s,
        Err(e) => {
            logger.error(format!("db open failed ({e:#}); recording disabled"));
            // Keep draining so pumps' try_send never blocks/errors on a full queue.
            while rx.blocking_recv().is_some() {}
            return;
        }
    };
    while let Some(ev) = rx.blocking_recv() {
        let parsed = parse_line(&ev.raw);
        let rec = Record {
            ts_ms: ev.ts_ms,
            direction: ev.direction,
            raw: String::from_utf8_lossy(&ev.raw).into_owned(),
            method: parsed.method,
            rpc_id: parsed.rpc_id,
            is_valid_json: parsed.is_valid_json,
        };
        if let Err(e) = store.insert(&rec) {
            logger.error(format!("insert failed (record dropped): {e:#}"));
        }
    }
}

/// Spawn the server with all three stdio streams piped.
///
/// On Windows, tools like `npx`/`npm` are `.cmd` shims that `CreateProcess`
/// cannot launch directly; if the direct spawn reports NotFound we retry through
/// `cmd /c`.
async fn spawn_child(program: &str, args: &[String], logger: &Logger) -> anyhow::Result<Child> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    match cmd.spawn() {
        Ok(child) => Ok(child),
        Err(e) if e.kind() == ErrorKind::NotFound && cfg!(windows) => {
            logger.info(format!(
                "`{program}` not directly executable; retrying via `cmd /c`"
            ));
            let mut shell = Command::new("cmd");
            shell
                .arg("/c")
                .arg(program)
                .args(args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            Ok(shell.spawn()?)
        }
        Err(e) => Err(e.into()),
    }
}

fn default_data_dir() -> Option<PathBuf> {
    directories::BaseDirs::new().map(|b| b.data_local_dir().join("mcpglass"))
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Append-only diagnostics sink. Silently no-ops if the file can't be opened —
/// logging must never be a reason to fail proxying. Never touches stdout/stderr.
#[derive(Clone)]
struct Logger {
    inner: Arc<Mutex<Option<std::fs::File>>>,
}

impl Logger {
    fn open(path: Option<&Path>) -> Self {
        let file = path.and_then(|p| {
            if let Some(parent) = p.parent() {
                if !parent.as_os_str().is_empty() {
                    let _ = std::fs::create_dir_all(parent);
                }
            }
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
                .ok()
        });
        Self {
            inner: Arc::new(Mutex::new(file)),
        }
    }

    fn write(&self, level: &str, msg: &str) {
        if let Ok(mut guard) = self.inner.lock() {
            if let Some(file) = guard.as_mut() {
                use std::io::Write;
                let _ = writeln!(file, "{} [{}] {}", now_ms(), level, msg);
                let _ = file.flush();
            }
        }
    }

    fn info(&self, msg: impl AsRef<str>) {
        self.write("INFO", msg.as_ref());
    }

    fn error(&self, msg: impl AsRef<str>) {
        self.write("ERROR", msg.as_ref());
    }
}
