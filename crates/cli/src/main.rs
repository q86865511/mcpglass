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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use clap::{Parser, Subcommand};
use policy::{Fault, InjectConfig, InjectDirection, InjectHit, Injector, Mode, Policy};
use proxy_core::Direction;
use serde_json::Value;
use storage::{ActionTaken, InjectEvent, InjectFault, SecurityEvent, SecurityEventKind};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{mpsc, Mutex as AsyncMutex};

use security::{Chunk, Decision, FrameAction, FramedStream};
use tap::{now_ms, storage_loop, Logger, StorageMsg, TapEvent};

mod bloat;
mod clients;
mod dash;
mod gateway;
mod gateway_config;
mod replay;
mod security;
mod tap;

/// Memory guard for a single un-terminated frame on the tap path. Well above any
/// realistic JSON-RPC message (the spike must handle >=10 MB payloads), yet still
/// bounded so a runaway stream can't exhaust memory. Forwarding ignores this.
const MAX_LINE_BYTES: usize = 64 * 1024 * 1024;

/// Test-only override (`MCPGLASS_MAX_LINE_BYTES`) for the frame cap, so integration
/// tests can exercise the oversized-frame path without building a real 64 MB frame.
/// Falls back to [`MAX_LINE_BYTES`]; ignored (falls back) if unset, unpar. or zero.
pub(crate) fn max_line_bytes() -> usize {
    std::env::var("MCPGLASS_MAX_LINE_BYTES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(MAX_LINE_BYTES)
}

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
    /// Wrap an MCP server: `mcpglass wrap [--db P] [--log P] [--name L]
    /// [--policy P] [--enforce] -- <cmd> [args...]`.
    Wrap {
        /// SQLite session file. Defaults to <data_local>/mcpglass/sessions.db.
        #[arg(long)]
        db: Option<PathBuf>,
        /// Proxy diagnostics log. Defaults to <data_local>/mcpglass/mcpglass.log.
        /// Never written to stdout/stderr — those are the protocol channels.
        #[arg(long)]
        log: Option<PathBuf>,
        /// Human-friendly session label. Defaults to the wrapped program's name.
        #[arg(long)]
        name: Option<String>,
        /// Security policy file. Defaults to <data_local>/mcpglass/policy.toml if
        /// present, else a built-in monitor-only policy. A file that exists but
        /// fails to parse aborts startup (a security config must not fail open).
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Force enforce mode regardless of the policy file's `mode` (the only
        /// mode that can block a request). Handy for testing/temporary lockdown.
        #[arg(long)]
        enforce: bool,
        /// Fault-injection config (TOML). When set, matched frames get simulated
        /// faults (delay/error/drop/truncate) applied to either direction — a
        /// resilience-testing tool, off by default. A file that fails to load aborts
        /// startup (before any byte is forwarded, so aborting is safe).
        #[arg(long)]
        inject: Option<PathBuf>,
        /// The server command and its args, after `--`.
        #[arg(last = true, required = true, num_args = 1.., allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Route a client's stdio MCP servers through mcpglass:
    /// `mcpglass attach [claude-code|claude-desktop|cursor|all] [--project D] [--dry-run]`.
    Attach {
        /// Which client(s) to rewrite. Defaults to `all` (only touches ones found).
        #[arg(default_value = "all")]
        target: String,
        /// For claude-code, rewrite `<dir>/.mcp.json` instead of the user config.
        #[arg(long)]
        project: Option<PathBuf>,
        /// Print the intended changes without writing or backing up.
        #[arg(long)]
        dry_run: bool,
        /// Port the `mcpglass gateway` listens on; url-type servers are repointed
        /// at `http://127.0.0.1:<port>/u/<name>`. Must match the port you run
        /// `mcpglass gateway` with.
        #[arg(long, default_value_t = 7412)]
        gateway_port: u16,
    },
    /// Reverse `attach`, restoring each wrapped server's original command/args.
    Detach {
        /// Which client(s) to restore. Defaults to `all`.
        #[arg(default_value = "all")]
        target: String,
        /// For claude-code, restore `<dir>/.mcp.json` instead of the user config.
        #[arg(long)]
        project: Option<PathBuf>,
        /// Print the intended changes without writing or backing up.
        #[arg(long)]
        dry_run: bool,
    },
    /// Serve the local HTTP dashboard: `mcpglass dashboard [--db P] [--port N] [--no-open]`.
    Dashboard {
        /// SQLite session file. Defaults to <data_local>/mcpglass/sessions.db.
        #[arg(long)]
        db: Option<PathBuf>,
        /// Port to listen on.
        #[arg(long, default_value_t = 7411)]
        port: u16,
        /// Skip opening a browser tab automatically.
        #[arg(long)]
        no_open: bool,
    },
    /// Run the reverse proxy for url-type (Streamable HTTP) MCP servers:
    /// `mcpglass gateway [--port N] [--db P] [--log P] [--policy P] [--enforce]
    /// [--upstream name=url ...]`. Long-running; `attach` repoints clients at it.
    Gateway {
        /// Port to listen on (must match `attach --gateway-port`).
        #[arg(long, default_value_t = 7412)]
        port: u16,
        /// SQLite session file. Defaults to <data_local>/mcpglass/sessions.db.
        #[arg(long)]
        db: Option<PathBuf>,
        /// Proxy diagnostics log. Defaults to <data_local>/mcpglass/mcpglass.log.
        #[arg(long)]
        log: Option<PathBuf>,
        /// Security policy file. Same resolution as `wrap`; a file that exists but
        /// fails to parse aborts startup.
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Force enforce mode regardless of the policy file's `mode`.
        #[arg(long)]
        enforce: bool,
        /// Fault-injection config (TOML), same format and semantics as `wrap
        /// --inject`. Off by default; a file that fails to load aborts startup
        /// (before binding, so no traffic is affected).
        #[arg(long)]
        inject: Option<PathBuf>,
        /// Upstream route `name=url` (repeatable). If omitted, routes are read from
        /// `<data_local>/mcpglass/gateway.toml` (written by `attach`).
        #[arg(long = "upstream", value_parser = parse_upstream)]
        upstream: Vec<(String, String)>,
    },
    /// Re-send a recorded client->server request back to its server, out of band:
    /// `mcpglass replay <message-id> [--db P] [--timeout-secs N]`. A debugging probe,
    /// not a wire path: it reconstructs the server from the recorded session, drives a
    /// fresh `initialize` handshake, and prints the response. stdio replay restarts
    /// the server process (side effects possible); the replay is never recorded.
    Replay {
        /// The id of the client->server request message to replay (from the dashboard
        /// or the sessions db). Responses, notifications, and s2c frames are rejected.
        message_id: i64,
        /// SQLite session file. Defaults to <data_local>/mcpglass/sessions.db.
        #[arg(long)]
        db: Option<PathBuf>,
        /// Overall time budget for the whole replay exchange, in seconds.
        #[arg(long, default_value_t = 30)]
        timeout_secs: u64,
    },
    /// Context-bloat analysis: estimate how many context tokens a session's
    /// advertised tool catalog costs, and flag tools worth trimming:
    /// `mcpglass bloat [--db P] [--session N] [--top N]`. A zero-dependency
    /// heuristic (~4 chars/token); always labelled approximate, never a real
    /// tokenizer count.
    Bloat {
        /// SQLite session file. Defaults to <data_local>/mcpglass/sessions.db.
        #[arg(long)]
        db: Option<PathBuf>,
        /// Which session to analyze. Defaults to the most recently started one.
        #[arg(long)]
        session: Option<i64>,
        /// How many of the heaviest tools to list in the report.
        #[arg(long, default_value_t = 10)]
        top: usize,
    },
}

/// Parse a `--upstream name=url` argument into its (name, url) pair.
fn parse_upstream(s: &str) -> Result<(String, String), String> {
    match s.split_once('=') {
        Some((name, url)) if !name.is_empty() && !url.is_empty() => {
            Ok((name.to_owned(), url.to_owned()))
        }
        _ => Err(format!("expected `name=url`, got {s:?}")),
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        SubCmd::Wrap {
            db,
            log,
            name,
            policy,
            enforce,
            inject,
            command,
        } => {
            let code = run_wrap(db, log, name, policy, enforce, inject, command).await;
            std::process::exit(code);
        }
        SubCmd::Attach {
            target,
            project,
            dry_run,
            gateway_port,
        } => {
            std::process::exit(clients::run_attach(&target, project, dry_run, gateway_port));
        }
        SubCmd::Detach {
            target,
            project,
            dry_run,
        } => {
            std::process::exit(clients::run_detach(&target, project, dry_run));
        }
        SubCmd::Dashboard { db, port, no_open } => {
            let code = dash::run(db, port, no_open).await;
            std::process::exit(code);
        }
        SubCmd::Gateway {
            port,
            db,
            log,
            policy,
            enforce,
            inject,
            upstream,
        } => {
            let code = gateway::run(port, db, log, policy, enforce, inject, upstream).await;
            std::process::exit(code);
        }
        SubCmd::Replay {
            message_id,
            db,
            timeout_secs,
        } => {
            let code = replay::run(db, message_id, timeout_secs).await;
            std::process::exit(code);
        }
        SubCmd::Bloat { db, session, top } => {
            let code = bloat::run(db, session, top).await;
            std::process::exit(code);
        }
    }
}

/// Exit code for a bad/missing security policy at startup. Distinct from the
/// spawn failure (127); mirrors sysexits `EX_CONFIG`. Safe to abort here because
/// no byte has been forwarded yet.
pub(crate) const EXIT_POLICY_CONFIG: i32 = 78;

/// Shared handle to our stdout. The server->client pump and the client->server
/// gate both write here (real server frames and synthesized block responses), so
/// writes are serialized and kept frame-atomic — an injected error can never land
/// in the middle of a real frame.
type SharedStdout = Arc<AsyncMutex<tokio::io::Stdout>>;

/// Shared fault injector. One [`Injector`] is shared by both pumps behind a plain
/// `std::sync::Mutex` so its per-rule counters and RNG advance in lock-step across
/// directions. `None` when `--inject` was not given (the common case): the pumps
/// then skip injection entirely, parsing not a single extra byte. The mutex is only
/// ever held for the duration of a pure [`Injector::decide`] call — never across an
/// `.await` — so it cannot stall the wire.
type SharedInjector = Option<Arc<Mutex<Injector>>>;

async fn run_wrap(
    db: Option<PathBuf>,
    log: Option<PathBuf>,
    name: Option<String>,
    policy_path: Option<PathBuf>,
    enforce: bool,
    inject_path: Option<PathBuf>,
    command: Vec<String>,
) -> i32 {
    let program = command[0].clone();
    let args: Vec<String> = command[1..].to_vec();

    // A session groups this whole run; label falls back to the program's basename.
    let label = name.unwrap_or_else(|| program_label(&program, &args));
    let command_line = command.join(" ");

    let data_dir = default_data_dir();
    let log_path = log.or_else(|| data_dir.as_ref().map(|d| d.join("mcpglass.log")));
    let db_path = db
        .or_else(|| data_dir.as_ref().map(|d| d.join("sessions.db")))
        .unwrap_or_else(|| std::env::temp_dir().join("mcpglass").join("sessions.db"));

    let logger = Logger::open(log_path.as_deref());
    logger.info(format!("wrap start: program={program} args={args:?} db={db_path:?}"));

    // Resolve the security policy BEFORE spawning/forwarding. A malformed security
    // config must fail loud (stderr + non-zero exit), never silently fall open —
    // this is the one point where aborting is safe because no traffic flows yet.
    let default_policy_path = data_dir.as_ref().map(|d| d.join("policy.toml"));
    let policy = match security::resolve_policy(policy_path.as_deref(), default_policy_path, enforce)
    {
        Ok(p) => Arc::new(p),
        Err(e) => {
            // Pre-forwarding: stderr is not yet a protocol channel, so reporting
            // here cannot corrupt an MCP session.
            eprintln!("mcpglass: {e}");
            logger.error(format!("policy load failed; aborting before any forward: {e}"));
            return EXIT_POLICY_CONFIG;
        }
    };
    logger.info(format!("policy mode={:?}", policy.mode));

    // Fault injection is opt-in. Like the policy file, a broken config must abort
    // *before* any byte is forwarded — safe here, and the only place aborting is.
    // With no `--inject` the injector is `None` and the pumps do zero extra work.
    let injector = match resolve_injector(inject_path.as_deref(), &logger) {
        Ok(i) => i,
        Err(code) => return code,
    };

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

    let (tx, rx) = mpsc::channel::<StorageMsg>(8192);

    // Storage owns a sync rusqlite connection on a dedicated blocking thread.
    let storage = tokio::task::spawn_blocking({
        let logger = logger.clone();
        move || storage_loop(rx, db_path, logger, label, command_line)
    });

    // Both write legs share this stdout so their writes stay frame-atomic.
    let shared_stdout: SharedStdout = Arc::new(AsyncMutex::new(tokio::io::stdout()));

    // Resolved once here (not per-frame) so both legs frame on the same cap.
    let frame_cap = max_line_bytes();

    // client -> server: framed and policy-gated (may block per message), tapped as c2s.
    let t_in = tokio::spawn(pump_c2s(
        tokio::io::stdin(),
        child_stdin,
        shared_stdout.clone(),
        policy.clone(),
        tx.clone(),
        logger.clone(),
        frame_cap,
        injector.clone(),
    ));
    // server -> client: frame-atomic passthrough, tapped as s2c (fingerprinting
    // runs on the storage thread, so this leg makes no synchronous decision).
    let t_out = tokio::spawn(pump_s2c(
        child_stdout,
        shared_stdout.clone(),
        tx.clone(),
        logger.clone(),
        frame_cap,
        injector.clone(),
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

/// Write all of `bytes` and flush. Small helper shared by both legs.
async fn write_all_flush<W: AsyncWrite + Unpin>(w: &mut W, bytes: &[u8]) -> std::io::Result<()> {
    w.write_all(bytes).await?;
    w.flush().await
}

/// Forward one frame (the newline the splitter stripped is re-appended, so the
/// bytes on the wire are byte-identical to the source) and flush.
async fn forward_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &[u8]) -> std::io::Result<()> {
    w.write_all(frame).await?;
    w.write_all(b"\n").await?;
    w.flush().await
}

/// Record a "channel full/closed" drop at most once per pump (`flag` is that pump's
/// latch). This is a fail-open safeguard: [`Logger::write`] is a *synchronous*
/// `writeln!`+`flush`, so if the storage thread stalls and the tap channel stays
/// full, logging every dropped frame would turn each frame into blocking disk IO on
/// the pump. A slow log disk would then throttle the pump and back-pressure the
/// wire — the exact failure this whole path is built to avoid. So we log the first
/// drop and silently discard the rest; steady-state traffic never fills the channel
/// and so never reaches this latch.
pub(crate) fn log_drop_once(flag: &AtomicBool, logger: &Logger, msg: &str) {
    if !flag.swap(true, Ordering::Relaxed) {
        logger.error(msg);
    }
}

/// Resolve the optional fault injector at startup. `None` path -> `Ok(None)` (the
/// pumps do no injection). A present-but-broken config returns `Err(exit_code)` so
/// the caller aborts before forwarding — reusing [`EXIT_POLICY_CONFIG`] since it is
/// the same class of "startup config failed, abort while it is still safe" event.
pub(crate) fn resolve_injector(
    inject_path: Option<&Path>,
    logger: &Logger,
) -> Result<SharedInjector, i32> {
    let Some(path) = inject_path else {
        return Ok(None);
    };
    match InjectConfig::load(path) {
        Ok(cfg) => {
            logger.info(format!(
                "inject enabled: {} rule(s) from {}",
                cfg.rule_count(),
                path.display()
            ));
            Ok(Some(Arc::new(Mutex::new(Injector::new(cfg)))))
        }
        Err(e) => {
            // Pre-forwarding, so stderr is not yet a protocol channel.
            eprintln!("mcpglass: failed to load inject config {}: {e:#}", path.display());
            logger.error(format!("inject load failed; aborting before any forward: {e:#}"));
            Err(EXIT_POLICY_CONFIG)
        }
    }
}

/// Consult the shared injector for one forwarded frame. Fail-open by construction:
/// a `None` injector, a poisoned lock, or a (pure, but defensively guarded)
/// `decide` panic all yield `None`, i.e. "inject nothing, forward normally" — the
/// injection machinery can never itself be a reason to disturb the wire.
pub(crate) fn inject_decide(
    injector: &SharedInjector,
    dir: InjectDirection,
    method: Option<&str>,
) -> Option<InjectHit> {
    let inj = injector.as_ref()?;
    let mut guard = inj.lock().ok()?; // poisoned -> forward normally
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| guard.decide(dir, method)))
        .unwrap_or(None)
}

/// Map a [`Fault`] to its storage token for the `inject_events` row.
pub(crate) fn fault_kind(fault: &Fault) -> InjectFault {
    match fault {
        Fault::Delay { .. } => InjectFault::Delay,
        Fault::Error { .. } => InjectFault::Error,
        Fault::Drop => InjectFault::Drop,
        Fault::Truncate { .. } => InjectFault::Truncate,
    }
}

/// Apply an injected fault to a client->server frame that policy already cleared to
/// forward. Performs the wire action for the fault and returns the [`InjectEvent`]
/// to record; the original frame is still tapped into `messages` by the caller (it
/// genuinely was sent by the client). `Err` means a write to the server failed and
/// the pump should tear down, mirroring the normal forward path.
#[allow(clippy::too_many_arguments)]
async fn apply_c2s_injection(
    server: &mut ChildStdin,
    stdout: &SharedStdout,
    frame: &[u8],
    id_value: Option<Value>,
    hit: InjectHit,
    method: Option<String>,
    rpc_id: Option<String>,
    ts_ms: i64,
    logger: &Logger,
) -> std::io::Result<InjectEvent> {
    let kind = fault_kind(&hit.fault);
    let detail = match hit.fault {
        Fault::Delay { delay_ms } => {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            forward_frame(server, frame).await?;
            format!("delayed c2s frame by {delay_ms}ms then forwarded")
        }
        Fault::Truncate { bytes } => {
            // Forward only a prefix, then a '\n': a deliberately corrupt frame.
            let end = bytes.min(frame.len());
            let mut corrupt = frame[..end].to_vec();
            corrupt.push(b'\n');
            write_all_flush(server, &corrupt).await?;
            format!("truncated c2s frame to {end} of {} bytes then forwarded", frame.len())
        }
        Fault::Drop => {
            // Withheld from the server, and no reply to the client.
            "dropped c2s frame (not forwarded)".to_owned()
        }
        Fault::Error { code, message } => {
            // Withhold from the server; answer the client in-protocol instead. A
            // stdout failure here can never affect server traffic (mirrors a policy
            // block response), so it is logged, not fatal. A frame with no id (a
            // notification) has nothing legal to synthesize, so nothing is sent.
            if let Some(id) = id_value.filter(|v| !v.is_null()) {
                let mut resp = security::synthesize_error_custom(&id, code, &message);
                resp.push(b'\n');
                let mut out = stdout.lock().await;
                if let Err(e) = write_all_flush(&mut *out, &resp).await {
                    logger.error(format!("c2s: inject error-response write error: {e}"));
                }
            }
            format!("synthesized error code={code} message={message:?} for c2s frame (server not sent)")
        }
    };
    Ok(InjectEvent {
        ts_ms,
        direction: Direction::C2s,
        rule: hit.rule_label,
        fault: kind,
        detail,
        method,
        rpc_id,
    })
}

/// Apply an injected fault to a server->client frame. Like [`apply_c2s_injection`]
/// but writes to the shared stdout (there is no server stdin on this leg); the
/// original server frame is still tapped by the caller so the recording faithfully
/// reflects what the server emitted. An `error` replaces the frame with a
/// synthesized error carrying the frame's own id.
#[allow(clippy::too_many_arguments)]
async fn apply_s2c_injection(
    stdout: &SharedStdout,
    frame: &[u8],
    id_value: Option<Value>,
    hit: InjectHit,
    method: Option<String>,
    rpc_id: Option<String>,
    ts_ms: i64,
) -> std::io::Result<InjectEvent> {
    let kind = fault_kind(&hit.fault);
    let detail = match hit.fault {
        Fault::Delay { delay_ms } => {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            let mut out = stdout.lock().await;
            forward_frame(&mut *out, frame).await?;
            format!("delayed s2c frame by {delay_ms}ms then delivered")
        }
        Fault::Truncate { bytes } => {
            let end = bytes.min(frame.len());
            let mut corrupt = frame[..end].to_vec();
            corrupt.push(b'\n');
            let mut out = stdout.lock().await;
            write_all_flush(&mut *out, &corrupt).await?;
            format!("truncated s2c frame to {end} of {} bytes then delivered", frame.len())
        }
        Fault::Drop => "dropped s2c frame (not delivered to client)".to_owned(),
        Fault::Error { code, message } => {
            // Replace the frame with an error carrying its id. A frame with no id has
            // no legal response to synthesize, so nothing is delivered.
            if let Some(id) = id_value.filter(|v| !v.is_null()) {
                let mut resp = security::synthesize_error_custom(&id, code, &message);
                resp.push(b'\n');
                let mut out = stdout.lock().await;
                write_all_flush(&mut *out, &resp).await?;
            }
            format!("replaced s2c frame with error code={code} message={message:?}")
        }
    };
    Ok(InjectEvent {
        ts_ms,
        direction: Direction::S2c,
        rule: hit.rule_label,
        fault: kind,
        detail,
        method,
        rpc_id,
    })
}

/// Parse just enough of a frame for the injection layer: its `method` (for rule
/// matching), its raw `id` (to echo in a synthesized error), and the normalized
/// `rpc_id` text (for the event row). Done once per forwarded frame, and only when
/// an injector is active — so a run without `--inject` never pays for it.
pub(crate) fn parse_for_injection(
    frame: &[u8],
) -> (Option<String>, Option<Value>, Option<String>) {
    let value = serde_json::from_slice::<Value>(frame).ok();
    let method = value
        .as_ref()
        .and_then(|v| v.get("method"))
        .and_then(|m| m.as_str())
        .map(str::to_owned);
    let id_value = value.as_ref().and_then(|v| v.get("id").cloned());
    let rpc_id = id_value.as_ref().and_then(security::normalize_id);
    (method, id_value, rpc_id)
}

/// client -> server pump. Unlike a raw copy, this frames the stream and makes a
/// synchronous policy decision per complete message, so a blocked request is
/// never forwarded to the server.
///
/// Fail-open layering, in order of precedence:
/// 1. An oversized/overflowing frame ([`Chunk::Raw`]) is uninspectable. In
///    `Monitor` it is forwarded verbatim (we would rather leak an un-inspectable
///    64 MB frame than stall or drop the wire). In `Enforce` it is instead
///    **dropped** — an uninspectable frame that skipped the gate would otherwise
///    defeat deny/secret rules, so an Enforce user's explicit "security first"
///    choice blocks it. This is the *only* Enforce-only drop; it affects nothing
///    but pathological >cap frames and is analogous to [`FrameAction::BlockSilent`]
///    (no id to answer, so the client receives nothing).
/// 2. A non-JSON or non-`tools/call` frame forwards (see [`security::decide_c2s_frame`]).
/// 3. Only an explicit policy block withholds a frame from the server; recording
///    and event persistence happen *after* the wire action and are best-effort.
#[allow(clippy::too_many_arguments)]
async fn pump_c2s<R>(
    mut reader: R,
    mut server: ChildStdin,
    stdout: SharedStdout,
    policy: Arc<Policy>,
    tx: mpsc::Sender<StorageMsg>,
    logger: Logger,
    max_line_bytes: usize,
    injector: SharedInjector,
) where
    R: AsyncRead + Unpin,
{
    let mut framer = FramedStream::new(max_line_bytes);
    let mut buf = vec![0u8; READ_BUF_BYTES];
    // Latch so a stalled tap channel logs its first drop only (see `log_drop_once`).
    let drop_logged = AtomicBool::new(false);
    // True while dropping the segments of one oversized frame under Enforce. An
    // oversized frame spans one-or-more consecutive `Chunk::Raw` segments; per the
    // `FramedStream` contract ONLY the terminating segment carries the trailing
    // '\n'. We latch on the first segment (record one event, drop all segments) and
    // release on the '\n'-terminated segment, so the event fires exactly once per
    // frame and two back-to-back oversized frames are still counted separately.
    let mut enforce_dropping_oversized = false;
    'outer: loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) => break, // EOF
            Ok(n) => n,
            Err(e) => {
                logger.error(format!("c2s: read error: {e}"));
                break;
            }
        };
        for chunk in framer.push(&buf[..n]) {
            match chunk {
                Chunk::Raw(bytes) => {
                    let terminates_frame = bytes.last() == Some(&b'\n');
                    if policy.mode == Mode::Enforce {
                        // Enforce: an uninspectable oversized frame must not reach
                        // the server. Drop every segment; record one blocked event
                        // on the first segment of the frame only.
                        if !enforce_dropping_oversized {
                            enforce_dropping_oversized = true;
                            let ev = SecurityEvent {
                                ts_ms: now_ms(),
                                kind: SecurityEventKind::PolicyDeny,
                                rule: "oversized-frame".to_owned(),
                                detail: format!(
                                    "client->server frame exceeded {max_line_bytes} bytes; \
                                     blocked in enforce mode (uninspectable, gate bypass)"
                                ),
                                // No parseable body, hence no tool_name/rpc_id.
                                tool_name: None,
                                rpc_id: None,
                                action_taken: ActionTaken::Blocked,
                            };
                            if tx.try_send(StorageMsg::Security(ev)).is_err() {
                                log_drop_once(
                                    &drop_logged,
                                    &logger,
                                    "c2s: security event dropped (channel full/closed)",
                                );
                            }
                        }
                        if terminates_frame {
                            enforce_dropping_oversized = false;
                        }
                        // Intentionally NOT forwarded: the bytes are discarded.
                    } else {
                        // Monitor (fail-open): forward the oversized frame verbatim,
                        // byte-for-byte. Never decided, never recorded.
                        if let Err(e) = write_all_flush(&mut server, &bytes).await {
                            logger.error(format!("c2s: write error: {e}"));
                            break 'outer;
                        }
                    }
                }
                Chunk::Frame(frame) => {
                    let ts = now_ms();
                    // `decide_c2s_frame` is pure and infallible today, but this is a
                    // security-critical hot path: a future panic there must not kill
                    // the c2s task and permanently stall forwarding. Catch it and
                    // fail open (forward, no event). Inputs are immutable borrows, so
                    // asserting unwind-safety is sound.
                    let decision = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                        || security::decide_c2s_frame(&frame, &policy, ts),
                    )) {
                        Ok(d) => d,
                        Err(_) => {
                            logger.error("c2s: decision panicked; forwarding frame (fail-open)");
                            Decision {
                                action: FrameAction::Forward,
                                events: Vec::new(),
                            }
                        }
                    };
                    // Wire action first; recording/events come after and never
                    // gate forwarding.
                    match decision.action {
                        FrameAction::Forward => {
                            // Injection layer: only policy-cleared (Forward) frames
                            // are eligible. Enabled solely by `--inject`; otherwise
                            // this whole block is skipped and the frame is parsed
                            // exactly zero extra times.
                            let injection = if injector.is_some() {
                                let (method, id_value, rpc_id) = parse_for_injection(&frame);
                                inject_decide(&injector, InjectDirection::C2s, method.as_deref())
                                    .map(|hit| (hit, method, id_value, rpc_id))
                            } else {
                                None
                            };
                            match injection {
                                None => {
                                    if let Err(e) = forward_frame(&mut server, &frame).await {
                                        logger.error(format!("c2s: write error: {e}"));
                                        break 'outer;
                                    }
                                }
                                Some((hit, method, id_value, rpc_id)) => {
                                    match apply_c2s_injection(
                                        &mut server, &stdout, &frame, id_value, hit, method,
                                        rpc_id, ts, &logger,
                                    )
                                    .await
                                    {
                                        Ok(ev) => {
                                            logger.info(format!(
                                                "inject c2s [{}]: {}",
                                                ev.fault.as_str(),
                                                ev.detail
                                            ));
                                            if tx.try_send(StorageMsg::Inject(ev)).is_err() {
                                                log_drop_once(
                                                    &drop_logged,
                                                    &logger,
                                                    "c2s: inject event dropped (channel full/closed)",
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            logger.error(format!("c2s: inject write error: {e}"));
                                            break 'outer;
                                        }
                                    }
                                }
                            }
                        }
                        FrameAction::BlockWithResponse(resp) => {
                            // Withheld from the server; answer the client in-protocol.
                            // A stdout failure here cannot affect server traffic.
                            let mut out = stdout.lock().await;
                            if let Err(e) = write_all_flush(&mut *out, &resp).await {
                                logger.error(format!("c2s: block-response write error: {e}"));
                            }
                        }
                        // No id to answer: the request is simply dropped.
                        FrameAction::BlockSilent => {}
                    }
                    // Record the message (even when blocked: it did occur) + persist
                    // every event. Best-effort; a full/closed channel just drops them
                    // (logged once, to avoid per-frame synchronous IO on a stall).
                    if tx
                        .try_send(StorageMsg::Tap(TapEvent {
                            direction: Direction::C2s,
                            ts_ms: ts,
                            raw: frame,
                        }))
                        .is_err()
                    {
                        log_drop_once(
                            &drop_logged,
                            &logger,
                            "c2s: tap dropped (channel full/closed)",
                        );
                    }
                    for ev in decision.events {
                        if tx.try_send(StorageMsg::Security(ev)).is_err() {
                            log_drop_once(
                                &drop_logged,
                                &logger,
                                "c2s: security event dropped (channel full/closed)",
                            );
                        }
                    }
                }
            }
        }
    }
    // EOF: forward any unterminated trailing bytes verbatim (fail-open — an
    // incomplete frame is not a decidable message). Dropping `server` after this
    // closes the child's stdin, letting it exit.
    if let Some(rem) = framer.finish() {
        if let Err(e) = write_all_flush(&mut server, &rem).await {
            logger.error(format!("c2s: trailing write error: {e}"));
        }
    }
}

/// server -> client pump: a frame-atomic transparent tap. It never decides, but
/// it writes only complete frames under the shared stdout lock so a client-facing
/// block response (from the c2s gate) can never be injected mid-frame. Forwarding
/// still happens before the tap, and the tap is best-effort.
async fn pump_s2c<R>(
    mut reader: R,
    stdout: SharedStdout,
    tx: mpsc::Sender<StorageMsg>,
    logger: Logger,
    max_line_bytes: usize,
    injector: SharedInjector,
) where
    R: AsyncRead + Unpin,
{
    let mut framer = FramedStream::new(max_line_bytes);
    let mut buf = vec![0u8; READ_BUF_BYTES];
    // Latch so a stalled tap channel logs its first drop only (see `log_drop_once`).
    let drop_logged = AtomicBool::new(false);
    'outer: loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) => break, // EOF
            Ok(n) => n,
            Err(e) => {
                logger.error(format!("s2c: read error: {e}"));
                break;
            }
        };
        for chunk in framer.push(&buf[..n]) {
            match chunk {
                // Oversized frame: forwarded verbatim, not tapped (parity with the
                // old LineSplitter, which dropped overflow from the tap). This is
                // the one case that momentarily leaves stdout mid-frame; a 64 MB
                // single-line server response is pathological and we choose to keep
                // the wire whole over frame-atomicity here.
                Chunk::Raw(bytes) => {
                    let mut out = stdout.lock().await;
                    if let Err(e) = write_all_flush(&mut *out, &bytes).await {
                        logger.error(format!("s2c: write error: {e}"));
                        break 'outer;
                    }
                }
                Chunk::Frame(frame) => {
                    let ts = now_ms();
                    // Injection layer (enabled only by `--inject`). The server frame
                    // is always tapped below regardless — the recording reflects what
                    // the server actually emitted; injection only changes what the
                    // *client* receives.
                    let injection = if injector.is_some() {
                        let (method, id_value, rpc_id) = parse_for_injection(&frame);
                        inject_decide(&injector, InjectDirection::S2c, method.as_deref())
                            .map(|hit| (hit, method, id_value, rpc_id))
                    } else {
                        None
                    };
                    match injection {
                        None => {
                            // Forward first — the wire is sacred — as one atomic locked write.
                            let mut out = stdout.lock().await;
                            if let Err(e) = forward_frame(&mut *out, &frame).await {
                                logger.error(format!("s2c: write error: {e}"));
                                break 'outer;
                            }
                        }
                        Some((hit, method, id_value, rpc_id)) => {
                            match apply_s2c_injection(
                                &stdout, &frame, id_value, hit, method, rpc_id, ts,
                            )
                            .await
                            {
                                Ok(ev) => {
                                    logger.info(format!(
                                        "inject s2c [{}]: {}",
                                        ev.fault.as_str(),
                                        ev.detail
                                    ));
                                    if tx.try_send(StorageMsg::Inject(ev)).is_err() {
                                        log_drop_once(
                                            &drop_logged,
                                            &logger,
                                            "s2c: inject event dropped (channel full/closed)",
                                        );
                                    }
                                }
                                Err(e) => {
                                    logger.error(format!("s2c: inject write error: {e}"));
                                    break 'outer;
                                }
                            }
                        }
                    }
                    // Tap second — best effort. tools/list fingerprinting is done
                    // on the storage thread from this same raw frame.
                    if tx
                        .try_send(StorageMsg::Tap(TapEvent {
                            direction: Direction::S2c,
                            ts_ms: ts,
                            raw: frame,
                        }))
                        .is_err()
                    {
                        log_drop_once(
                            &drop_logged,
                            &logger,
                            "s2c: tap dropped (channel full/closed)",
                        );
                    }
                }
            }
        }
    }
    // EOF: flush any unterminated trailing bytes verbatim.
    if let Some(rem) = framer.finish() {
        let mut out = stdout.lock().await;
        if let Err(e) = write_all_flush(&mut *out, &rem).await {
            logger.error(format!("s2c: trailing write error: {e}"));
        }
    }
}

/// Launchers whose own basename says nothing about which server is actually
/// running — the useful label is the package/script they're invoking instead.
const LAUNCHER_PROGRAMS: [&str; 7] = ["npx", "uvx", "bunx", "pnpm", "deno", "node", "python"];

/// Default session label for the wrapped program. For launcher programs
/// (`npx`, `uvx`, `bunx`, `pnpm`, `deno`, `node`, `python`) this is the
/// basename of the first non-flag argument — e.g. `npx -y
/// @modelcontextprotocol/server-git` labels as `server-git`, not `npx` —
/// since the launcher's own name is the same for every server it runs.
/// Anything else, or a launcher with no such argument, falls back to the
/// program's own basename. (`attach` always passes `--name` explicitly, so
/// this fallback only matters for a manually-invoked `mcpglass wrap`.)
fn program_label(program: &str, args: &[String]) -> String {
    let program_basename = basename(program);
    let is_launcher = LAUNCHER_PROGRAMS
        .iter()
        .any(|p| p.eq_ignore_ascii_case(&program_basename));
    if is_launcher {
        if let Some(first_arg) = args.iter().find(|a| !a.starts_with('-')) {
            return basename(first_arg);
        }
    }
    program_basename
}

/// Basename (without extension) of a path-like string. Falls back to the raw
/// string if there is nothing to strip.
fn basename(s: &str) -> String {
    Path::new(s)
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(s)
        .to_owned()
}

/// Extensions Windows executables can carry, tried in this order when a bare
/// `program` (e.g. `npx`) isn't directly launchable. `.bat`/`.cmd` are the
/// shim case (`npx`, `npm`, ...) that `CreateProcess` can't launch without an
/// extension.
const WINDOWS_EXTENSIONS: [&str; 4] = ["com", "exe", "bat", "cmd"];

/// Resolve `program` to a concrete file the way Windows would search for it:
/// if it already contains a path separator, only try appending extensions to
/// it directly; otherwise search each directory in `path_env` (a `;`-joined
/// `PATH` value). Pure aside from the injected `exists` check, so tests can
/// probe it without touching the real filesystem or environment.
fn resolve_windows_executable(
    program: &str,
    path_env: &str,
    mut exists: impl FnMut(&Path) -> bool,
) -> Option<PathBuf> {
    let has_path_component = program.contains('/') || program.contains('\\');
    let dirs: Vec<&str> = if has_path_component { vec![""] } else { path_env.split(';').collect() };

    for dir in dirs {
        let base = if dir.is_empty() {
            PathBuf::from(program)
        } else {
            Path::new(dir).join(program)
        };
        for ext in WINDOWS_EXTENSIONS {
            let candidate = base.with_extension(ext);
            if exists(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

/// Spawn the server with all three stdio streams piped.
///
/// On Windows, tools like `npx`/`npm` are `.cmd` shims that `CreateProcess`
/// cannot launch directly; if the direct spawn reports NotFound we resolve the
/// shim's real path ourselves (searching `PATH` like Windows would) and spawn
/// that path directly. We deliberately do NOT hand-build a `cmd /c <program>
/// <args>` string: std's own argument quoting for `.bat`/`.cmd` targets is
/// what protects against `&`/`|`/etc. in args being reinterpreted as shell
/// operators (the class of bug fixed by CVE-2024-24576) — reintroducing a
/// manual `cmd` invocation here would defeat that.
// `pub(crate)` so the out-of-band `replay` path can reuse the exact same spawn logic
// (Windows `.cmd`/`.bat` shim resolution included) when it reconstructs a server.
pub(crate) async fn spawn_child(program: &str, args: &[String], logger: &Logger) -> anyhow::Result<Child> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    match cmd.spawn() {
        Ok(child) => Ok(child),
        Err(e) if e.kind() == ErrorKind::NotFound && cfg!(windows) => {
            let path_env = std::env::var("PATH").unwrap_or_default();
            match resolve_windows_executable(program, &path_env, |p| p.exists()) {
                Some(resolved) => {
                    logger.info(format!(
                        "`{program}` not directly executable; resolved to `{}`",
                        resolved.display()
                    ));
                    let mut retry = Command::new(&resolved);
                    retry
                        .args(args)
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped());
                    Ok(retry.spawn()?)
                }
                None => Err(e.into()),
            }
        }
        Err(e) => Err(e.into()),
    }
}

pub(crate) fn default_data_dir() -> Option<PathBuf> {
    directories::BaseDirs::new().map(|b| b.data_local_dir().join("mcpglass"))
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mcpglass-main-{tag}-{}-{}",
            std::process::id(),
            now_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn resolve_windows_executable_finds_shim_via_path_search() {
        let dir = temp_dir("resolve-shim");
        let cmd_path = dir.join("foo.cmd");
        std::fs::write(&cmd_path, "@echo off\r\n").unwrap();

        let resolved = resolve_windows_executable("foo", dir.to_str().unwrap(), |p| p.exists());
        assert_eq!(resolved, Some(cmd_path));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolve_windows_executable_tries_extensions_in_order() {
        let dir = temp_dir("resolve-order");
        // Only the .bat form exists; .com/.exe must be tried and missed first.
        let bat_path = dir.join("tool.bat");
        std::fs::write(&bat_path, "@echo off\r\n").unwrap();

        let resolved = resolve_windows_executable("tool", dir.to_str().unwrap(), |p| p.exists());
        assert_eq!(resolved, Some(bat_path));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolve_windows_executable_handles_path_component_without_path_search() {
        let dir = temp_dir("resolve-path-component");
        let cmd_path = dir.join("nested.cmd");
        std::fs::write(&cmd_path, "@echo off\r\n").unwrap();

        // Program already has a path separator: PATH must not be consulted,
        // only extensions appended to the given path itself.
        let program = dir.join("nested").to_string_lossy().into_owned();
        let resolved = resolve_windows_executable(&program, "", |p| p.exists());
        assert_eq!(resolved, Some(cmd_path));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolve_windows_executable_returns_none_when_nothing_matches() {
        let resolved = resolve_windows_executable("does-not-exist-xyz", "", |_| false);
        assert!(resolved.is_none());
    }

    #[test]
    fn program_label_takes_first_non_flag_arg_for_launchers() {
        let args = vec!["-y".to_string(), "@modelcontextprotocol/server-git".to_string()];
        assert_eq!(program_label("npx", &args), "server-git");
    }

    #[test]
    fn program_label_falls_back_when_launcher_has_no_non_flag_arg() {
        let args = vec!["-y".to_string(), "--verbose".to_string()];
        assert_eq!(program_label("npx", &args), "npx");
    }

    #[test]
    fn program_label_falls_back_when_launcher_has_no_args() {
        assert_eq!(program_label("uvx", &[]), "uvx");
    }

    #[test]
    fn program_label_recognizes_launcher_regardless_of_extension_or_case() {
        let args = vec!["mcp-server-git".to_string()];
        assert_eq!(program_label("NPX.CMD", &args), "mcp-server-git");
    }

    #[test]
    fn program_label_uses_program_basename_for_non_launchers() {
        let args = vec!["--stdio".to_string()];
        assert_eq!(program_label("/usr/local/bin/my-server", &args), "my-server");
    }

    #[test]
    fn log_drop_once_records_only_the_first_drop() {
        let dir = temp_dir("log-throttle");
        let log = dir.join("proxy.log");
        let logger = Logger::open(Some(&log));
        let flag = AtomicBool::new(false);

        // Simulate a stalled channel dropping many frames in a row.
        for _ in 0..5 {
            log_drop_once(&flag, &logger, "tap dropped (channel full/closed)");
        }

        let contents = std::fs::read_to_string(&log).unwrap();
        let hits = contents.matches("tap dropped (channel full/closed)").count();
        assert_eq!(hits, 1, "only the first drop should be logged, got: {contents:?}");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Drive `storage_loop` synchronously over a pre-filled channel and return the
    /// tool names that ended up fingerprinted, in row order. `tag` must be unique
    /// per caller: `temp_dir` keys on millisecond time, so two tests sharing a tag
    /// could otherwise collide on the same db under parallel execution.
    fn fingerprinted_tools(tag: &str, msgs: Vec<StorageMsg>) -> (PathBuf, Vec<String>) {
        let dir = temp_dir(tag);
        let db = dir.join("sessions.db");
        let (tx, rx) = mpsc::channel::<StorageMsg>(64);
        for m in msgs {
            tx.try_send(m).expect("prefill channel");
        }
        drop(tx); // closes the channel so storage_loop returns at drain end.
        storage_loop(
            rx,
            db.clone(),
            Logger::open(None),
            "t".to_owned(),
            "echo cmd".to_owned(),
        );
        let conn = rusqlite::Connection::open(&db).unwrap();
        let names: Vec<String> = conn
            .prepare("SELECT tool_name FROM tool_fingerprints ORDER BY id")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        (dir, names)
    }

    fn tap(direction: Direction, ts_ms: i64, raw: &str) -> StorageMsg {
        StorageMsg::Tap(TapEvent {
            direction,
            ts_ms,
            raw: raw.as_bytes().to_vec(),
        })
    }

    #[test]
    fn only_correlated_tools_list_responses_are_fingerprinted() {
        // A response is fingerprinted only if its id matches a tools/list request we
        // saw. An unrequested `result.tools[]` (id 99) must be ignored; the genuine
        // tools/list response (id 5) must be recorded.
        let msgs = vec![
            tap(Direction::C2s, 1, r#"{"jsonrpc":"2.0","id":5,"method":"tools/list"}"#),
            // Business response that coincidentally carries a tools[] shape: ignored.
            tap(
                Direction::S2c,
                2,
                r#"{"jsonrpc":"2.0","id":99,"result":{"tools":[{"name":"evil","description":"x"}]}}"#,
            ),
            // The real tools/list answer: fingerprinted.
            tap(
                Direction::S2c,
                3,
                r#"{"jsonrpc":"2.0","id":5,"result":{"tools":[{"name":"search","description":"y"}]}}"#,
            ),
        ];
        let (dir, names) = fingerprinted_tools("fp-correlated", msgs);
        assert_eq!(names, vec!["search".to_string()]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cross_session_rug_pull_raises_fingerprint_change_event() {
        // Two `wrap` runs against the same server command (same server_key) sharing
        // one db: the tool's definition changes on the SECOND run. The change must
        // be caught across sessions and recorded as a fingerprint_change event, even
        // though the second session sees the tool for the first time.
        let dir = temp_dir("cross-session-rugpull");
        let db = dir.join("sessions.db");
        let cmd = "npx some-server".to_owned();

        let run = |raw_resp: &'static str| {
            let (tx, rx) = mpsc::channel::<StorageMsg>(64);
            tx.try_send(tap(
                Direction::C2s,
                1,
                r#"{"jsonrpc":"2.0","id":5,"method":"tools/list"}"#,
            ))
            .unwrap();
            tx.try_send(tap(Direction::S2c, 2, raw_resp)).unwrap();
            drop(tx);
            storage_loop(rx, db.clone(), Logger::open(None), "run".to_owned(), cmd.clone());
        };

        // First run: tool `search` advertised with description "A" -> New, no event.
        run(r#"{"jsonrpc":"2.0","id":5,"result":{"tools":[{"name":"search","description":"A"}]}}"#);
        // Second run (new session): same tool, description mutated to "B" -> Changed.
        run(r#"{"jsonrpc":"2.0","id":5,"result":{"tools":[{"name":"search","description":"B"}]}}"#);

        let conn = rusqlite::Connection::open(&db).unwrap();
        let changes: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM security_events WHERE kind = 'fingerprint_change'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(changes, 1, "a cross-session rug-pull must raise one fingerprint_change");
        // Two distinct sessions were created (one per run).
        let sessions: i64 = conn
            .query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(sessions, 2);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tools_list_response_without_a_request_is_not_fingerprinted() {
        // No tools/list request precedes this response -> nothing is fingerprinted.
        let msgs = vec![tap(
            Direction::S2c,
            1,
            r#"{"jsonrpc":"2.0","id":5,"result":{"tools":[{"name":"search","description":"y"}]}}"#,
        )];
        let (dir, names) = fingerprinted_tools("fp-unsolicited", msgs);
        assert!(names.is_empty(), "unsolicited tools[] must not be fingerprinted");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Regression test for the CVE-2024-24576 class of bug: the removed
    /// `cmd /c <program> <args>` fallback hand-built a command line, so a
    /// `&` inside an arg could be reinterpreted by `cmd.exe` as a command
    /// separator. Spawning a resolved `.cmd` path directly instead relies on
    /// std's own quoting for batch-file targets, which must keep `&`
    /// literal.
    #[cfg(windows)]
    #[tokio::test]
    async fn ampersand_in_arg_survives_direct_cmd_spawn() {
        let dir = temp_dir("ampersand");
        let cmd_path = dir.join("probe.cmd");
        std::fs::write(&cmd_path, "@echo off\r\necho arg=%1\r\n").unwrap();

        let mut cmd = Command::new(&cmd_path);
        cmd.arg("arg&value")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = cmd.spawn().expect("spawn probe.cmd");
        let output = child.wait_with_output().await.expect("wait for probe.cmd");
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert!(
            stdout.contains("arg&value"),
            "expected the literal `&` to survive intact, got: {stdout:?}"
        );
        // If `&` had been reinterpreted as a command separator, `value`
        // would have run as a separate, nonexistent command.
        assert!(!stdout.contains("is not recognized"));

        std::fs::remove_dir_all(&dir).ok();
    }
}
