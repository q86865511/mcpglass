//! `attach`/`detach`: import each AI client's configured MCP servers into the
//! mcpglass proxy — and precisely restore them.
//!
//! Config files are user assets. The rules here are conservative by design:
//! parse the whole file first and touch nothing we can't parse, back up before
//! every write, and reverse `attach` entry-by-entry (never by pasting a backup
//! over changes the user may have made since). JSON is round-tripped through
//! serde_json with the `preserve_order` feature so untouched keys keep both
//! their value and their position.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use directories::BaseDirs;
use serde_json::{Map, Value};

use crate::gateway_config::{self, GatewayConfig};

/// The clients we know how to rewrite, and where their configs live.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Client {
    ClaudeCode,
    ClaudeDesktop,
    Cursor,
}

impl Client {
    const ALL: [Client; 3] = [Client::ClaudeCode, Client::ClaudeDesktop, Client::Cursor];

    fn slug(self) -> &'static str {
        match self {
            Client::ClaudeCode => "claude-code",
            Client::ClaudeDesktop => "claude-desktop",
            Client::Cursor => "cursor",
        }
    }
}

/// Attach vs. detach — the only thing that differs between the two commands is
/// the per-entry transform and the words used in the report.
#[derive(Clone, Copy)]
enum Op {
    Attach,
    Detach,
}

// ---------------------------------------------------------------------------
// Public entry points (called from main's subcommand dispatch).
// ---------------------------------------------------------------------------

pub fn run_attach(target: &str, project: Option<PathBuf>, dry_run: bool, gateway_port: u16) -> i32 {
    run(Op::Attach, target, project, dry_run, gateway_port)
}

pub fn run_detach(target: &str, project: Option<PathBuf>, dry_run: bool) -> i32 {
    // Detach reads the recorded upstreams from gateway.toml; the port is unused.
    run(Op::Detach, target, project, dry_run, 0)
}

fn run(op: Op, target: &str, project: Option<PathBuf>, dry_run: bool, gateway_port: u16) -> i32 {
    let clients = match parse_target(target) {
        Some(c) => c,
        None => {
            eprintln!(
                "unknown target `{target}` (expected claude-code|claude-desktop|cursor|all)"
            );
            return 2;
        }
    };

    // The wrapped command points at this binary's absolute path. Failing to
    // resolve it means we'd write a broken command — abort before touching any
    // file. (Detach doesn't need it, but resolving early keeps the flow simple.)
    let exe = match std::env::current_exe() {
        Ok(p) => p.to_string_lossy().into_owned(),
        Err(e) => {
            eprintln!("cannot resolve the mcpglass executable path: {e}");
            return 1;
        }
    };

    let roots = match Roots::detect() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{e:#}");
            return 1;
        }
    };
    let backup_dir = default_backup_dir();

    // gateway.toml is the shared `name -> upstream URL` table. Attach records new
    // url-type servers into it; detach reads it back to restore them. It is loaded
    // once and (for attach) written once, before any client file is touched.
    let gateway_path = gateway_config::default_config_path();
    let mut gateway = gateway_path
        .as_ref()
        .map(|p| GatewayConfig::load_or_default(p))
        .unwrap_or_default();
    let gateway_before = gateway.clone();

    // For an explicit single target we report a missing file; for `all` we
    // quietly skip clients that aren't installed.
    let explicit = target != "all";

    // Phase 1 — transform every target file in memory, updating the shared gateway
    // table as we go. Nothing is written yet, so a later failure leaves the disk
    // exactly as it was.
    let mut plans = Vec::new();
    for client in clients {
        let path = config_path(client, &roots, project.as_deref());
        if !explicit && !path.exists() {
            continue;
        }
        let plan = transform_file(op, &path, &exe, gateway_port, &mut gateway);
        plans.push((client, path, plan));
    }

    // Phase 2 — persist the gateway table BEFORE touching any client file. The
    // mapping is what detach needs to restore; if we can't record it, an attach
    // that repointed clients at the gateway would be unrestorable. So a save
    // failure aborts here with the client configs still pristine. (Only attach
    // mutates the table; detach and dry-run never reach the save.)
    if !dry_run && gateway != gateway_before {
        let saved = match gateway_path.as_ref() {
            Some(path) => gateway.save(path).map_err(|e| format!("{e:#}")),
            None => Err("cannot locate a data dir for gateway.toml".to_owned()),
        };
        if let Err(e) = saved {
            eprintln!("mcpglass: error: could not write gateway config: {e}");
            eprintln!("mcpglass: aborting; no client config files were modified");
            return 1;
        }
    }

    // Phase 3 — the gateway state is safely recorded, so it is now safe to write
    // the client files.
    let mut reports = Vec::new();
    for (client, path, plan) in plans {
        reports.push(commit_file(plan, client, &path, &backup_dir, dry_run));
    }

    print_report(op, &reports, dry_run);
    exit_code(&reports)
}

/// A write failure must surface in the exit code: the gateway table was already
/// saved by then, so a client file left unwritten is an inconsistent state the
/// caller (or a script) has to notice and retry — a printed report alone is
/// invisible to automation.
fn exit_code(reports: &[FileReport]) -> i32 {
    let any_write_failed = reports
        .iter()
        .any(|r| matches!(r.status, FileStatus::WriteError(_)));
    if any_write_failed {
        1
    } else {
        0
    }
}

fn parse_target(target: &str) -> Option<Vec<Client>> {
    match target {
        "all" => Some(Client::ALL.to_vec()),
        "claude-code" => Some(vec![Client::ClaudeCode]),
        "claude-desktop" => Some(vec![Client::ClaudeDesktop]),
        "cursor" => Some(vec![Client::Cursor]),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Path resolution — centralised so tests can inject roots instead of touching
// real user files.
// ---------------------------------------------------------------------------

/// Filesystem roots used to locate client configs.
#[derive(Clone)]
struct Roots {
    /// User home (`%USERPROFILE%` / `$HOME`).
    home: PathBuf,
    /// Roaming/config dir: `%APPDATA%` on Windows, `~/Library/Application
    /// Support` on macOS, `~/.config` on Linux — exactly what Claude Desktop
    /// uses for its config across platforms.
    config: PathBuf,
}

impl Roots {
    fn detect() -> Result<Self> {
        let base = BaseDirs::new().context("cannot determine the user's home directory")?;
        Ok(Self {
            home: base.home_dir().to_path_buf(),
            config: base.config_dir().to_path_buf(),
        })
    }
}

fn config_path(client: Client, roots: &Roots, project: Option<&Path>) -> PathBuf {
    match client {
        // `--project` only makes sense for claude-code (project-scoped .mcp.json).
        Client::ClaudeCode => match project {
            Some(dir) => dir.join(".mcp.json"),
            None => roots.home.join(".claude.json"),
        },
        Client::ClaudeDesktop => roots
            .config
            .join("Claude")
            .join("claude_desktop_config.json"),
        Client::Cursor => roots.home.join(".cursor").join("mcp.json"),
    }
}

fn default_backup_dir() -> PathBuf {
    BaseDirs::new()
        .map(|b| b.data_local_dir().join("mcpglass").join("backups"))
        .unwrap_or_else(|| std::env::temp_dir().join("mcpglass").join("backups"))
}

// ---------------------------------------------------------------------------
// Per-file processing (I/O layer).
// ---------------------------------------------------------------------------

struct FileReport {
    client: Client,
    path: PathBuf,
    status: FileStatus,
}

enum FileStatus {
    NotFound,
    /// Read or parse failure — the file is left untouched.
    Unreadable(String),
    /// No `mcpServers` object to act on.
    NoServers,
    WriteError(String),
    Processed {
        servers: Vec<ServerReport>,
        wrote: Wrote,
    },
}

enum Wrote {
    Changed(PathBuf), // backup path
    DryRun,
    NoChange,
}

struct ServerReport {
    name: String,
    /// `Some(project_path)` when this entry came from `projects.<path>.mcpServers`
    /// in `~/.claude.json` rather than the file's top-level `mcpServers`.
    scope: Option<String>,
    outcome: Outcome,
}

enum Outcome {
    /// Wrapped (attach) or restored (detach).
    Changed,
    /// Already in the desired state — nothing to do.
    Unchanged,
    /// Deliberately left alone, with a reason for the report.
    Skipped(String),
}

/// The in-memory result of transforming one client file, before any write.
/// Split from the write step so `run` can transform every file first, persist
/// the gateway table, and only then commit the client files (see `run`'s phases).
enum FilePlan {
    /// A terminal status with nothing to write (not found / unreadable / no servers).
    Terminal(FileStatus),
    /// Transformed content ready to commit — or to skip when unchanged/dry-run.
    Ready {
        doc: Value,
        servers: Vec<ServerReport>,
        changed: bool,
    },
}

/// Read, parse, and transform one client file entirely in memory. Records any new
/// url upstreams into `gateway` but writes nothing to disk — the caller commits
/// (or discards) the returned plan once the gateway table is safely persisted.
fn transform_file(
    op: Op,
    path: &Path,
    exe: &str,
    gateway_port: u16,
    gateway: &mut GatewayConfig,
) -> FilePlan {
    if !path.exists() {
        return FilePlan::Terminal(FileStatus::NotFound);
    }
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => return FilePlan::Terminal(FileStatus::Unreadable(format!("read failed: {e}"))),
    };
    // Unparseable file: report and touch nothing.
    let mut doc: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => return FilePlan::Terminal(FileStatus::Unreadable(format!("invalid JSON: {e}"))),
    };
    if !has_any_servers(&doc) {
        return FilePlan::Terminal(FileStatus::NoServers);
    }

    let servers = match op {
        Op::Attach => transform_attach(&mut doc, exe, gateway_port, gateway),
        Op::Detach => transform_detach(&mut doc, &*gateway),
    };
    let changed = servers.iter().any(|s| matches!(s.outcome, Outcome::Changed));
    FilePlan::Ready { doc, servers, changed }
}

/// Write a transformed plan to disk (backup + atomic write), or skip when there's
/// nothing to write. Turns a [`FilePlan`] into the [`FileReport`] shown to the user.
fn commit_file(
    plan: FilePlan,
    client: Client,
    path: &Path,
    backup_dir: &Path,
    dry_run: bool,
) -> FileReport {
    let report = |status| FileReport {
        client,
        path: path.to_path_buf(),
        status,
    };

    let (doc, servers, changed) = match plan {
        FilePlan::Terminal(status) => return report(status),
        FilePlan::Ready { doc, servers, changed } => (doc, servers, changed),
    };

    let wrote = if !changed {
        Wrote::NoChange
    } else if dry_run {
        Wrote::DryRun
    } else {
        match backup_and_write(path, &doc, client, backup_dir) {
            Ok(backup) => Wrote::Changed(backup),
            Err(e) => return report(FileStatus::WriteError(format!("{e:#}"))),
        }
    };

    report(FileStatus::Processed { servers, wrote })
}

/// Copy the original aside, then write the transformed doc as 2-space pretty
/// JSON. The backup is the safety net; detach reverses in place rather than
/// restoring it, so a user's later edits to other entries survive.
fn backup_and_write(path: &Path, doc: &Value, client: Client, backup_dir: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(backup_dir)
        .with_context(|| format!("creating backup dir {}", backup_dir.display()))?;
    let file_name = path
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("config.json");
    let backup = backup_dir.join(format!("{}-{}-{}.json", client.slug(), file_name, now_ms()));
    std::fs::copy(path, &backup)
        .with_context(|| format!("backing up {} to {}", path.display(), backup.display()))?;
    write_json_file(path, doc)?;
    Ok(backup)
}

/// Write via a same-directory temp file + rename, so a mid-write failure
/// (disk full, process killed) never leaves a half-written config on disk —
/// the user always sees either the old file or the fully-written new one.
/// `rename` on Windows replaces an existing destination, same as POSIX.
fn write_json_file(path: &Path, doc: &Value) -> Result<()> {
    let mut text = serde_json::to_string_pretty(doc)?;
    text.push('\n');

    let file_name = path
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("config.json");
    let tmp_path = path.with_file_name(format!("{file_name}.tmp-{}", std::process::id()));

    std::fs::write(&tmp_path, &text)
        .with_context(|| format!("writing temp file {}", tmp_path.display()))?;
    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e).with_context(|| {
            format!("renaming {} into place at {}", tmp_path.display(), path.display())
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Pure transforms (no I/O) — the load-bearing, unit-tested core.
// ---------------------------------------------------------------------------

/// Every `mcpServers` map worth acting on in the document: the file's
/// top-level one (scope `None`), plus each `projects.<path>.mcpServers` map
/// (scope `Some(path)`) — `~/.claude.json` nests a project-local server list
/// under `projects` alongside per-project settings we must leave untouched.
fn for_each_servers_map(doc: &mut Value, mut f: impl FnMut(Option<&str>, &mut Map<String, Value>)) {
    if let Some(servers) = doc.get_mut("mcpServers").and_then(Value::as_object_mut) {
        f(None, servers);
    }
    if let Some(projects) = doc.get_mut("projects").and_then(Value::as_object_mut) {
        for (project_path, project_value) in projects.iter_mut() {
            if let Some(servers) = project_value.get_mut("mcpServers").and_then(Value::as_object_mut) {
                f(Some(project_path), servers);
            }
        }
    }
}

/// True if the document has a top-level `mcpServers` object or at least one
/// `projects.*.mcpServers` object — mirrors [`for_each_servers_map`]'s reach
/// so "nothing to do" is judged the same way as "what did we act on".
fn has_any_servers(doc: &Value) -> bool {
    if doc.get("mcpServers").and_then(Value::as_object).is_some() {
        return true;
    }
    doc.get("projects")
        .and_then(Value::as_object)
        .is_some_and(|projects| {
            projects
                .values()
                .any(|p| p.get("mcpServers").and_then(Value::as_object).is_some())
        })
}

fn transform_attach(
    doc: &mut Value,
    exe: &str,
    gateway_port: u16,
    gateway: &mut GatewayConfig,
) -> Vec<ServerReport> {
    let mut reports = Vec::new();
    for_each_servers_map(doc, |scope, servers| {
        for (name, entry) in servers.iter_mut() {
            reports.push(ServerReport {
                name: name.clone(),
                scope: scope.map(str::to_owned),
                outcome: attach_entry(name, entry, exe, gateway_port, gateway),
            });
        }
    });
    reports
}

fn transform_detach(doc: &mut Value, gateway: &GatewayConfig) -> Vec<ServerReport> {
    let mut reports = Vec::new();
    for_each_servers_map(doc, |scope, servers| {
        for (name, entry) in servers.iter_mut() {
            reports.push(ServerReport {
                name: name.clone(),
                scope: scope.map(str::to_owned),
                outcome: detach_entry(entry, gateway),
            });
        }
    });
    reports
}

fn attach_entry(
    name: &str,
    entry: &mut Value,
    exe: &str,
    gateway_port: u16,
    gateway: &mut GatewayConfig,
) -> Outcome {
    let Some(obj) = entry.as_object_mut() else {
        return Outcome::Skipped("not an object".into());
    };
    // stdio entry: rewrite its `command` to invoke `mcpglass wrap`.
    if let Some(command) = obj.get("command").and_then(Value::as_str).map(str::to_owned) {
        return attach_stdio_entry(name, obj, exe, command);
    }
    // url (Streamable HTTP) entry: record the original endpoint in gateway.toml and
    // point the client at the local gateway (`/u/<route>`). Other keys are untouched.
    if let Some(url) = obj.get("url").and_then(Value::as_str).map(str::to_owned) {
        // Idempotent: a url already pointing at our gateway is ours — leave it
        // (regardless of port, so a re-attach never clobbers the recorded upstream).
        if gateway_route(&url).is_some() {
            return Outcome::Unchanged;
        }
        // The `/u/<route>` segment must be path-safe and unique across servers that
        // share a name but not an upstream (top-level vs. projects.*, or different
        // client files), so the route is not always the raw name.
        let route = allocate_route(gateway, name, &url);
        gateway.servers.insert(route.clone(), url);
        obj.insert(
            "url".into(),
            Value::String(format!("http://127.0.0.1:{gateway_port}/u/{route}")),
        );
        return Outcome::Changed;
    }
    Outcome::Skipped("no command or url".into())
}

/// Rewrite one stdio entry to `mcpglass wrap --name <name> -- <command> <args...>`.
fn attach_stdio_entry(name: &str, obj: &mut Map<String, Value>, exe: &str, command: String) -> Outcome {
    // Idempotent: a command already pointing at mcpglass is ours — leave it.
    if is_mcpglass(&command) {
        return Outcome::Unchanged;
    }

    // `args` is optional (defaults to none), but if present it must be an
    // array — a non-array value (e.g. a bare string) is a shape we don't
    // understand well enough to rewrite safely, so leave the entry alone
    // rather than silently discarding whatever was in it.
    let orig_args = match obj.get("args") {
        None => Vec::new(),
        Some(Value::Array(a)) => a.clone(),
        Some(_) => return Outcome::Skipped("args is not an array".into()),
    };
    let mut new_args = vec![
        Value::String("wrap".into()),
        Value::String("--name".into()),
        Value::String(name.to_owned()),
        Value::String("--".into()),
        Value::String(command),
    ];
    new_args.extend(orig_args);

    // Insert on existing keys keeps their position (preserve_order); `env` and
    // any unknown keys are left exactly as they were.
    obj.insert("command".into(), Value::String(exe.to_owned()));
    obj.insert("args".into(), Value::Array(new_args));
    Outcome::Changed
}

fn detach_entry(entry: &mut Value, gateway: &GatewayConfig) -> Outcome {
    let Some(obj) = entry.as_object_mut() else {
        return Outcome::Skipped("not an object".into());
    };
    // stdio entry wrapped as `mcpglass wrap -- ...`.
    if let Some(command) = obj.get("command").and_then(Value::as_str).map(str::to_owned) {
        return detach_stdio_entry(obj, command);
    }
    // url entry pointing at our gateway: restore the original endpoint from
    // gateway.toml. The route is read out of the gateway url itself (attach may
    // have disambiguated it, so it isn't necessarily the server's name). Without a
    // recorded mapping for that route there is nothing to restore.
    if let Some(url) = obj.get("url").and_then(Value::as_str).map(str::to_owned) {
        let Some(route) = gateway_route(&url) else {
            return Outcome::Unchanged; // not routed through our gateway
        };
        return match gateway.get(&route) {
            Some(orig) => {
                obj.insert("url".into(), Value::String(orig.to_owned()));
                Outcome::Changed
            }
            None => Outcome::Skipped("no gateway.toml mapping to restore url".into()),
        };
    }
    Outcome::Unchanged
}

/// Reverse [`attach_stdio_entry`] for one entry, restoring the original command/args.
fn detach_stdio_entry(obj: &mut Map<String, Value>, command: String) -> Outcome {
    // Not routed through mcpglass — already detached.
    if !is_mcpglass(&command) {
        return Outcome::Unchanged;
    }

    let args = obj.get("args").and_then(Value::as_array).cloned();
    let Some(args) = args else {
        return Outcome::Skipped("mcpglass command without args".into());
    };
    if args.first().and_then(Value::as_str) != Some("wrap") {
        return Outcome::Skipped("not a wrap invocation".into());
    }
    let Some(sep) = args.iter().position(|v| v.as_str() == Some("--")) else {
        return Outcome::Skipped("no `--` separator".into());
    };
    let after = &args[sep + 1..];
    let Some(orig_command) = after.first().and_then(Value::as_str) else {
        return Outcome::Skipped("nothing after `--`".into());
    };
    let orig_command = orig_command.to_owned();
    let orig_args: Vec<Value> = after[1..].to_vec();

    obj.insert("command".into(), Value::String(orig_command));
    // Restore original shape: a server with no extra args had no `args` key.
    if orig_args.is_empty() {
        obj.remove("args");
    } else {
        obj.insert("args".into(), Value::Array(orig_args));
    }
    Outcome::Changed
}

/// If `url` points at our local gateway — `http://{127.0.0.1|localhost}:<port>/u/<route>`
/// — return the `<route>` segment; otherwise `None`. The port is intentionally
/// not matched: any loopback `/u/...` url counts as "already ours", so a re-attach
/// (even after a port change) never mistakes the gateway url for a fresh upstream
/// and clobbers the real endpoint in gateway.toml. Routes are path-safe (see
/// [`sanitize_route`]), so the segment is taken literally with no percent-decoding.
fn gateway_route(url: &str) -> Option<String> {
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = rest.split_once('/')?;
    let host = authority.split(':').next().unwrap_or("");
    if host != "127.0.0.1" && host != "localhost" {
        return None;
    }
    let route = path.strip_prefix("u/")?;
    Some(route.to_owned())
}

/// Make a server name safe to drop into a `/u/<route>` path: every character
/// outside `[A-Za-z0-9._-]` becomes `-`. `axum`'s path extractor percent-decodes,
/// and `/`, `?`, `#`, and spaces would otherwise break the route or its round-trip.
fn sanitize_route(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// Pick the `/u/<route>` name to record `url` under. Starts from the sanitized
/// server name; if that route is free or already holds this exact `url`, use it.
/// Otherwise a different upstream already owns it (two servers sharing a name, or
/// two names sanitizing to the same string), so probe `<base>~2`, `<base>~3`, …
/// until a free route or one already holding this `url` is found — keeping attach
/// idempotent within a single run.
fn allocate_route(gateway: &GatewayConfig, name: &str, url: &str) -> String {
    let base = sanitize_route(name);
    let free_or_same = |route: &str| match gateway.get(route) {
        None => true,
        Some(existing) => existing == url,
    };
    if free_or_same(&base) {
        return base;
    }
    let mut n = 2u32;
    loop {
        let candidate = format!("{base}~{n}");
        if free_or_same(&candidate) {
            return candidate;
        }
        n += 1;
    }
}

/// True when `command`'s file stem is `mcpglass` (e.g. `mcpglass`,
/// `mcpglass.exe`, or an absolute path to either).
fn is_mcpglass(command: &str) -> bool {
    Path::new(command)
        .file_stem()
        .and_then(OsStr::to_str)
        .map(|stem| stem.eq_ignore_ascii_case("mcpglass"))
        .unwrap_or(false)
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Reporting.
// ---------------------------------------------------------------------------

fn print_report(op: Op, reports: &[FileReport], dry_run: bool) {
    let verb = match op {
        Op::Attach => "attach",
        Op::Detach => "detach",
    };
    if dry_run {
        println!("mcpglass {verb} (dry-run: no files written)\n");
    } else {
        println!("mcpglass {verb}\n");
    }
    if reports.is_empty() {
        println!("  no client config files detected");
        return;
    }
    for fr in reports {
        println!("{}  {}", fr.client.slug(), fr.path.display());
        match &fr.status {
            FileStatus::NotFound => println!("  (config not found)"),
            FileStatus::Unreadable(e) => println!("  ! skipped: {e}"),
            FileStatus::WriteError(e) => println!("  ! write failed: {e}"),
            FileStatus::NoServers => println!("  (no mcpServers)"),
            FileStatus::Processed { servers, wrote } => {
                for s in servers {
                    println!(
                        "    {:<28} {}",
                        server_display_name(s),
                        outcome_label(op, &s.outcome)
                    );
                }
                match wrote {
                    Wrote::Changed(backup) => {
                        println!("  -> written; backup {}", backup.display())
                    }
                    Wrote::DryRun => println!("  -> would write (dry-run)"),
                    Wrote::NoChange => println!("  -> no changes"),
                }
            }
        }
        println!();
    }
}

/// e.g. `fs` for a top-level entry, `fs (project: E:\foo)` for one nested
/// under `projects.<path>.mcpServers`.
fn server_display_name(s: &ServerReport) -> String {
    match &s.scope {
        Some(scope) => format!("{} (project: {scope})", s.name),
        None => s.name.clone(),
    }
}

fn outcome_label(op: Op, outcome: &Outcome) -> String {
    match outcome {
        Outcome::Changed => match op {
            Op::Attach => "wrapped".into(),
            Op::Detach => "restored".into(),
        },
        Outcome::Unchanged => match op {
            Op::Attach => "already wrapped".into(),
            Op::Detach => "not wrapped".into(),
        },
        Outcome::Skipped(reason) => format!("skipped ({reason})"),
    }
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const EXE: &str = "/opt/tools/mcpglass";
    const GW_PORT: u16 = 7412;

    /// Single-file transform + commit, mirroring one iteration of `run`'s phases.
    /// A test convenience so the I/O tests can drive one file end-to-end.
    #[allow(clippy::too_many_arguments)]
    fn process_file(
        op: Op,
        client: Client,
        path: &Path,
        exe: &str,
        backup_dir: &Path,
        dry_run: bool,
        gateway_port: u16,
        gateway: &mut GatewayConfig,
    ) -> FileReport {
        let plan = transform_file(op, path, exe, gateway_port, gateway);
        commit_file(plan, client, path, backup_dir, dry_run)
    }

    /// Attach with a throwaway gateway table — for the stdio-only tests that don't
    /// exercise url rewriting.
    fn t_attach(doc: &mut Value) -> Vec<ServerReport> {
        transform_attach(doc, EXE, GW_PORT, &mut GatewayConfig::default())
    }

    /// Detach with an empty gateway table — stdio entries don't consult it.
    fn t_detach(doc: &mut Value) -> Vec<ServerReport> {
        transform_detach(doc, &GatewayConfig::default())
    }

    #[test]
    fn write_failure_yields_nonzero_exit_code() {
        let ok = FileReport {
            client: Client::ClaudeCode,
            path: PathBuf::from("a.json"),
            status: FileStatus::NoServers,
        };
        let failed = FileReport {
            client: Client::Cursor,
            path: PathBuf::from("b.json"),
            status: FileStatus::WriteError("disk full".into()),
        };
        assert_eq!(exit_code(&[ok]), 0);
        let ok = FileReport {
            client: Client::ClaudeCode,
            path: PathBuf::from("a.json"),
            status: FileStatus::NoServers,
        };
        assert_eq!(exit_code(&[ok, failed]), 1);
    }

    fn stdio_doc() -> Value {
        json!({
            "mcpServers": {
                "fs": {
                    "command": "node",
                    "args": ["server.js", "--flag"],
                    "env": { "TOKEN": "abc" }
                }
            }
        })
    }

    #[test]
    fn attach_wraps_and_preserves_env_and_order() {
        let mut doc = stdio_doc();
        let reports = t_attach(&mut doc);
        assert!(matches!(reports[0].outcome, Outcome::Changed));

        let fs = &doc["mcpServers"]["fs"];
        assert_eq!(fs["command"], json!(EXE));
        assert_eq!(
            fs["args"],
            json!(["wrap", "--name", "fs", "--", "node", "server.js", "--flag"])
        );
        // env untouched.
        assert_eq!(fs["env"], json!({ "TOKEN": "abc" }));
        // Key order unchanged: command, args, env.
        let keys: Vec<&String> = fs.as_object().unwrap().keys().collect();
        assert_eq!(keys, vec!["command", "args", "env"]);
    }

    #[test]
    fn attach_detach_round_trips_with_unknown_fields() {
        let original = json!({
            "mcpServers": {
                "fs": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": { "TOKEN": "abc" },
                    "customField": { "nested": [1, 2, 3] }
                }
            }
        });
        let mut doc = original.clone();
        t_attach(&mut doc);
        assert_ne!(doc, original, "attach must change something");
        t_detach(&mut doc);
        assert_eq!(doc, original, "detach must exactly reverse attach");
    }

    #[test]
    fn attach_detach_round_trips_project_local_servers() {
        // Mirrors ~/.claude.json's shape: a top-level mcpServers plus each
        // project's own mcpServers nested under projects.<path>.
        let original = json!({
            "mcpServers": {
                "fs": { "command": "node", "args": ["server.js"] }
            },
            "projects": {
                "E:\\repo\\foo": {
                    "mcpServers": {
                        "proj-tool": { "command": "python", "args": ["tool.py"] }
                    },
                    "otherSetting": true
                },
                "E:\\repo\\bar": {
                    "allowedTools": ["Bash"]
                }
            }
        });
        let mut doc = original.clone();
        let reports = t_attach(&mut doc);
        assert_eq!(reports.len(), 2, "one top-level + one project-scoped server");

        let proj = reports.iter().find(|r| r.name == "proj-tool").unwrap();
        assert_eq!(proj.scope.as_deref(), Some("E:\\repo\\foo"));
        assert!(matches!(proj.outcome, Outcome::Changed));
        let top = reports.iter().find(|r| r.name == "fs").unwrap();
        assert_eq!(top.scope, None);

        assert_eq!(
            doc["projects"]["E:\\repo\\foo"]["mcpServers"]["proj-tool"]["command"],
            json!(EXE)
        );
        // Sibling keys outside mcpServers are left exactly as they were.
        assert_eq!(doc["projects"]["E:\\repo\\foo"]["otherSetting"], json!(true));
        assert_eq!(doc["projects"]["E:\\repo\\bar"]["allowedTools"], json!(["Bash"]));

        t_detach(&mut doc);
        assert_eq!(doc, original, "detach must restore project-local servers too");
    }

    #[test]
    fn attach_is_idempotent() {
        let mut doc = stdio_doc();
        t_attach(&mut doc);
        let once = doc.clone();
        let reports = t_attach(&mut doc);
        assert!(matches!(reports[0].outcome, Outcome::Unchanged));
        assert_eq!(doc, once, "second attach must be a no-op");
    }

    #[test]
    fn attach_rewrites_url_entry_and_records_mapping() {
        let mut doc = json!({
            "mcpServers": {
                "remote": { "url": "https://example.com/mcp", "type": "http" }
            }
        });
        let mut gw = GatewayConfig::default();
        let reports = transform_attach(&mut doc, EXE, GW_PORT, &mut gw);
        assert!(matches!(reports[0].outcome, Outcome::Changed));
        // The client now points at the local gateway; sibling keys are untouched.
        assert_eq!(
            doc["mcpServers"]["remote"]["url"],
            json!("http://127.0.0.1:7412/u/remote")
        );
        assert_eq!(doc["mcpServers"]["remote"]["type"], json!("http"));
        // The original endpoint is recorded so detach can restore it.
        assert_eq!(gw.get("remote"), Some("https://example.com/mcp"));
    }

    #[test]
    fn attach_detach_round_trips_url_entry() {
        let original = json!({
            "mcpServers": { "remote": { "url": "https://example.com/mcp", "type": "http" } }
        });
        let mut doc = original.clone();
        let mut gw = GatewayConfig::default();
        transform_attach(&mut doc, EXE, GW_PORT, &mut gw);
        assert_ne!(doc, original, "attach must rewrite the url");
        transform_detach(&mut doc, &gw);
        assert_eq!(doc, original, "detach must restore the original url exactly");
    }

    #[test]
    fn attach_url_is_idempotent() {
        let mut doc = json!({
            "mcpServers": { "remote": { "url": "https://example.com/mcp" } }
        });
        let mut gw = GatewayConfig::default();
        transform_attach(&mut doc, EXE, GW_PORT, &mut gw);
        let once = doc.clone();
        // A second attach sees the gateway url and leaves it (Unchanged), even on a
        // different port — so the recorded upstream is never clobbered.
        let reports = transform_attach(&mut doc, EXE, 9999, &mut gw);
        assert!(matches!(reports[0].outcome, Outcome::Unchanged));
        assert_eq!(doc, once, "second attach on a gateway url must be a no-op");
    }

    #[test]
    fn detach_url_without_mapping_is_skipped() {
        // A gateway-pointing url whose original endpoint isn't in gateway.toml can't
        // be restored: report it skipped rather than silently mangle it.
        let mut doc = json!({
            "mcpServers": { "remote": { "url": "http://127.0.0.1:7412/u/remote", "type": "http" } }
        });
        let before = doc.clone();
        let reports = transform_detach(&mut doc, &GatewayConfig::default());
        assert!(matches!(reports[0].outcome, Outcome::Skipped(_)));
        assert_eq!(doc, before, "an unrestorable gateway url must be left untouched");
    }

    #[test]
    fn attach_disambiguates_same_name_different_upstreams() {
        // Two servers named `svc` — one top-level, one project-scoped — pointing at
        // different upstreams. They must get distinct routes so neither the gateway
        // mapping nor the restore clobbers the other.
        let mut doc = json!({
            "mcpServers": { "svc": { "url": "https://a.example.com/mcp", "type": "http" } },
            "projects": {
                "E:\\repo": {
                    "mcpServers": { "svc": { "url": "https://b.example.com/mcp", "type": "http" } }
                }
            }
        });
        let mut gw = GatewayConfig::default();
        transform_attach(&mut doc, EXE, GW_PORT, &mut gw);

        let top_url = doc["mcpServers"]["svc"]["url"].as_str().unwrap().to_owned();
        let proj_url = doc["projects"]["E:\\repo"]["mcpServers"]["svc"]["url"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_ne!(top_url, proj_url, "same-name servers must get distinct routes");
        assert_eq!(gw.servers.len(), 2, "two distinct upstreams recorded");

        // Each route resolves to its own upstream.
        let top_route = gateway_route(&top_url).unwrap();
        let proj_route = gateway_route(&proj_url).unwrap();
        assert_eq!(gw.get(&top_route), Some("https://a.example.com/mcp"));
        assert_eq!(gw.get(&proj_route), Some("https://b.example.com/mcp"));

        // Detach restores each entry to its own original upstream.
        transform_detach(&mut doc, &gw);
        assert_eq!(
            doc["mcpServers"]["svc"]["url"],
            json!("https://a.example.com/mcp")
        );
        assert_eq!(
            doc["projects"]["E:\\repo"]["mcpServers"]["svc"]["url"],
            json!("https://b.example.com/mcp")
        );
    }

    #[test]
    fn attach_sanitizes_unsafe_route_chars_and_round_trips() {
        // A name with a `/` would break the `/u/<name>` route; it must be sanitized.
        let original = json!({
            "mcpServers": { "my/tool": { "url": "https://example.com/mcp", "type": "http" } }
        });
        let mut doc = original.clone();
        let mut gw = GatewayConfig::default();
        transform_attach(&mut doc, EXE, GW_PORT, &mut gw);

        assert_eq!(
            doc["mcpServers"]["my/tool"]["url"],
            json!("http://127.0.0.1:7412/u/my-tool"),
            "the route segment must be path-safe"
        );
        assert_eq!(gw.get("my-tool"), Some("https://example.com/mcp"));

        transform_detach(&mut doc, &gw);
        assert_eq!(doc, original, "detach must restore the original url under the original name");
    }

    #[test]
    fn attach_sanitize_collision_gets_suffix() {
        // `my/tool` and `my-tool` both sanitize to `my-tool`; the second must get a
        // distinct route rather than overwrite the first's mapping.
        let mut doc = json!({
            "mcpServers": {
                "my/tool": { "url": "https://a.example.com/mcp" },
                "my-tool": { "url": "https://b.example.com/mcp" }
            }
        });
        let mut gw = GatewayConfig::default();
        transform_attach(&mut doc, EXE, GW_PORT, &mut gw);

        assert_eq!(gw.servers.len(), 2, "colliding routes must both be recorded");
        let u1 = doc["mcpServers"]["my/tool"]["url"].as_str().unwrap().to_owned();
        let u2 = doc["mcpServers"]["my-tool"]["url"].as_str().unwrap().to_owned();
        assert_ne!(u1, u2, "sanitize collision must resolve to distinct routes");

        transform_detach(&mut doc, &gw);
        assert_eq!(doc["mcpServers"]["my/tool"]["url"], json!("https://a.example.com/mcp"));
        assert_eq!(doc["mcpServers"]["my-tool"]["url"], json!("https://b.example.com/mcp"));
    }

    #[test]
    fn entry_without_command_or_url_is_skipped() {
        let mut doc = json!({
            "mcpServers": { "weird": { "type": "sse" } }
        });
        let before = doc.clone();
        let reports = t_attach(&mut doc);
        assert!(matches!(reports[0].outcome, Outcome::Skipped(_)));
        assert_eq!(doc, before, "an entry with neither command nor url is untouched");
    }

    #[test]
    fn non_array_args_is_skipped_and_untouched() {
        let mut doc = json!({
            "mcpServers": {
                "fs": { "command": "node", "args": "server.js" }
            }
        });
        let before = doc.clone();
        let reports = t_attach(&mut doc);
        assert!(matches!(reports[0].outcome, Outcome::Skipped(_)));
        assert_eq!(doc, before, "entry with non-array args must not be modified");
    }

    #[test]
    fn write_json_file_leaves_no_tmp_file_behind() {
        let dir = temp_dir("atomic-write");
        let path = dir.join("config.json");
        write_json_file(&path, &json!({"a": 1})).unwrap();

        let entries: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("config.json")]);

        let written: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(written, json!({"a": 1}));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_json_file_replaces_existing_file() {
        let dir = temp_dir("atomic-overwrite");
        let path = dir.join("config.json");
        write_json_file(&path, &json!({"a": 1})).unwrap();
        write_json_file(&path, &json!({"a": 2})).unwrap();

        let written: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(written, json!({"a": 2}), "rename must replace the old file");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn bad_json_file_is_left_untouched() {
        let dir = temp_dir("badjson");
        let path = dir.join("config.json");
        let raw = b"{ this is not valid json ";
        std::fs::write(&path, raw).unwrap();

        let report = process_file(
            Op::Attach,
            Client::Cursor,
            &path,
            EXE,
            &dir,
            false,
            GW_PORT,
            &mut GatewayConfig::default(),
        );
        assert!(matches!(report.status, FileStatus::Unreadable(_)));
        assert_eq!(std::fs::read(&path).unwrap(), raw, "file must be byte-identical");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn special_chars_after_separator_round_trip() {
        let original = json!({
            "mcpServers": {
                "weird": {
                    "command": "python",
                    "args": ["-c", "print('hello world')", "arg with spaces", "unicode-café-✓", "--"]
                }
            }
        });
        let mut doc = original.clone();
        t_attach(&mut doc);
        // The wrapped command must itself point at mcpglass now.
        assert_eq!(doc["mcpServers"]["weird"]["command"], json!(EXE));
        t_detach(&mut doc);
        assert_eq!(doc, original, "special-char args must survive round-trip");
    }

    #[test]
    fn no_args_server_round_trips_without_adding_args_key() {
        let original = json!({
            "mcpServers": { "bare": { "command": "myserver" } }
        });
        let mut doc = original.clone();
        t_attach(&mut doc);
        assert!(doc["mcpServers"]["bare"]["args"].is_array());
        t_detach(&mut doc);
        // detach must drop the synthetic args key to match the original shape.
        assert_eq!(doc, original);
        assert!(doc["mcpServers"]["bare"].as_object().unwrap().get("args").is_none());
    }

    #[test]
    fn smoke_attach_backup_then_detach_restores_bytes() {
        let dir = temp_dir("smoke");
        let cfg = dir.join("claude_desktop_config.json");
        let backups = dir.join("backups");

        // Fake claude-desktop config: 2 stdio servers + 1 url (streamable HTTP).
        let original = json!({
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                    "env": { "LOG": "1" }
                },
                "git": { "command": "uvx", "args": ["mcp-server-git"] },
                "web": { "url": "https://example.com/mcp", "type": "http" }
            }
        });
        write_json_file(&cfg, &original).unwrap();
        let original_bytes = std::fs::read(&cfg).unwrap();

        // Shared gateway table: attach records the url upstream, detach restores it.
        let mut gw = GatewayConfig::default();

        // Attach.
        let r = process_file(
            Op::Attach,
            Client::ClaudeDesktop,
            &cfg,
            EXE,
            &backups,
            false,
            GW_PORT,
            &mut gw,
        );
        let FileStatus::Processed { servers, wrote } = &r.status else {
            panic!("expected processed, got other status");
        };
        // All three changed: two stdio wrapped, one url routed through the gateway.
        let changed = servers.iter().filter(|s| matches!(s.outcome, Outcome::Changed)).count();
        let skipped = servers.iter().filter(|s| matches!(s.outcome, Outcome::Skipped(_))).count();
        assert_eq!(changed, 3);
        assert_eq!(skipped, 0);
        // The url upstream was recorded for restoration.
        assert_eq!(gw.get("web"), Some("https://example.com/mcp"));
        let Wrote::Changed(backup) = wrote else {
            panic!("expected a backup to be written");
        };
        assert!(backup.exists(), "backup file must exist");
        assert_eq!(
            std::fs::read(backup).unwrap(),
            original_bytes,
            "backup must be the pristine original"
        );

        // The written config must actually be wrapped now.
        let attached: Value = serde_json::from_slice(&std::fs::read(&cfg).unwrap()).unwrap();
        assert_eq!(attached["mcpServers"]["filesystem"]["command"], json!(EXE));
        assert_eq!(
            attached["mcpServers"]["web"]["url"],
            json!("http://127.0.0.1:7412/u/web")
        );

        // Detach and confirm byte-identical restoration (stdio + url).
        let r = process_file(
            Op::Detach,
            Client::ClaudeDesktop,
            &cfg,
            EXE,
            &backups,
            false,
            GW_PORT,
            &mut gw,
        );
        assert!(matches!(r.status, FileStatus::Processed { .. }));
        assert_eq!(
            std::fs::read(&cfg).unwrap(),
            original_bytes,
            "detach must restore the original bytes"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A unique temp directory, mirroring the integration test's approach (no
    /// external tempfile dependency).
    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mcpglass-clients-{tag}-{}-{}",
            std::process::id(),
            now_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
