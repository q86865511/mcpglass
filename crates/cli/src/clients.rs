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

pub fn run_attach(target: &str, project: Option<PathBuf>, dry_run: bool) -> i32 {
    run(Op::Attach, target, project, dry_run)
}

pub fn run_detach(target: &str, project: Option<PathBuf>, dry_run: bool) -> i32 {
    run(Op::Detach, target, project, dry_run)
}

fn run(op: Op, target: &str, project: Option<PathBuf>, dry_run: bool) -> i32 {
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

    // For an explicit single target we report a missing file; for `all` we
    // quietly skip clients that aren't installed.
    let explicit = target != "all";
    let mut reports = Vec::new();
    for client in clients {
        let path = config_path(client, &roots, project.as_deref());
        if !explicit && !path.exists() {
            continue;
        }
        reports.push(process_file(op, client, &path, &exe, &backup_dir, dry_run));
    }

    print_report(op, &reports, dry_run);
    0
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

fn process_file(
    op: Op,
    client: Client,
    path: &Path,
    exe: &str,
    backup_dir: &Path,
    dry_run: bool,
) -> FileReport {
    let report = |status| FileReport {
        client,
        path: path.to_path_buf(),
        status,
    };

    if !path.exists() {
        return report(FileStatus::NotFound);
    }
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => return report(FileStatus::Unreadable(format!("read failed: {e}"))),
    };
    // Unparseable file: report and touch nothing.
    let mut doc: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => return report(FileStatus::Unreadable(format!("invalid JSON: {e}"))),
    };
    if servers_ref(&doc).is_none() {
        return report(FileStatus::NoServers);
    }

    let servers = match op {
        Op::Attach => transform_attach(&mut doc, exe),
        Op::Detach => transform_detach(&mut doc),
    };
    let changed = servers.iter().any(|s| matches!(s.outcome, Outcome::Changed));

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

fn servers_ref(doc: &Value) -> Option<&Map<String, Value>> {
    doc.get("mcpServers").and_then(Value::as_object)
}

fn servers_mut(doc: &mut Value) -> Option<&mut Map<String, Value>> {
    doc.get_mut("mcpServers").and_then(Value::as_object_mut)
}

fn transform_attach(doc: &mut Value, exe: &str) -> Vec<ServerReport> {
    let Some(servers) = servers_mut(doc) else {
        return Vec::new();
    };
    servers
        .iter_mut()
        .map(|(name, entry)| ServerReport {
            name: name.clone(),
            outcome: attach_entry(name, entry, exe),
        })
        .collect()
}

fn transform_detach(doc: &mut Value) -> Vec<ServerReport> {
    let Some(servers) = servers_mut(doc) else {
        return Vec::new();
    };
    servers
        .iter_mut()
        .map(|(name, entry)| ServerReport {
            name: name.clone(),
            outcome: detach_entry(entry),
        })
        .collect()
}

fn attach_entry(name: &str, entry: &mut Value, exe: &str) -> Outcome {
    let Some(obj) = entry.as_object_mut() else {
        return Outcome::Skipped("not an object".into());
    };
    // Only stdio entries have a `command`; remote (url/http) entries are skipped.
    let command = match obj.get("command").and_then(Value::as_str) {
        Some(c) => c.to_owned(),
        None => return Outcome::Skipped("remote entry (no command)".into()),
    };
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

fn detach_entry(entry: &mut Value) -> Outcome {
    let Some(obj) = entry.as_object_mut() else {
        return Outcome::Skipped("not an object".into());
    };
    let command = match obj.get("command").and_then(Value::as_str) {
        Some(c) => c.to_owned(),
        None => return Outcome::Skipped("remote entry (no command)".into()),
    };
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
                    println!("    {:<28} {}", s.name, outcome_label(op, &s.outcome));
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
        let reports = transform_attach(&mut doc, EXE);
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
        transform_attach(&mut doc, EXE);
        assert_ne!(doc, original, "attach must change something");
        transform_detach(&mut doc);
        assert_eq!(doc, original, "detach must exactly reverse attach");
    }

    #[test]
    fn attach_is_idempotent() {
        let mut doc = stdio_doc();
        transform_attach(&mut doc, EXE);
        let once = doc.clone();
        let reports = transform_attach(&mut doc, EXE);
        assert!(matches!(reports[0].outcome, Outcome::Unchanged));
        assert_eq!(doc, once, "second attach must be a no-op");
    }

    #[test]
    fn remote_entry_is_skipped_and_untouched() {
        let mut doc = json!({
            "mcpServers": {
                "remote": { "url": "https://example.com/mcp", "type": "http" }
            }
        });
        let before = doc.clone();
        let reports = transform_attach(&mut doc, EXE);
        assert!(matches!(reports[0].outcome, Outcome::Skipped(_)));
        assert_eq!(doc, before, "remote entry must not be modified");
    }

    #[test]
    fn non_array_args_is_skipped_and_untouched() {
        let mut doc = json!({
            "mcpServers": {
                "fs": { "command": "node", "args": "server.js" }
            }
        });
        let before = doc.clone();
        let reports = transform_attach(&mut doc, EXE);
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

        let report = process_file(Op::Attach, Client::Cursor, &path, EXE, &dir, false);
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
        transform_attach(&mut doc, EXE);
        // The wrapped command must itself point at mcpglass now.
        assert_eq!(doc["mcpServers"]["weird"]["command"], json!(EXE));
        transform_detach(&mut doc);
        assert_eq!(doc, original, "special-char args must survive round-trip");
    }

    #[test]
    fn no_args_server_round_trips_without_adding_args_key() {
        let original = json!({
            "mcpServers": { "bare": { "command": "myserver" } }
        });
        let mut doc = original.clone();
        transform_attach(&mut doc, EXE);
        assert!(doc["mcpServers"]["bare"]["args"].is_array());
        transform_detach(&mut doc);
        // detach must drop the synthetic args key to match the original shape.
        assert_eq!(doc, original);
        assert!(doc["mcpServers"]["bare"].as_object().unwrap().get("args").is_none());
    }

    #[test]
    fn smoke_attach_backup_then_detach_restores_bytes() {
        let dir = temp_dir("smoke");
        let cfg = dir.join("claude_desktop_config.json");
        let backups = dir.join("backups");

        // Fake claude-desktop config: 2 stdio servers + 1 remote.
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

        // Attach.
        let r = process_file(Op::Attach, Client::ClaudeDesktop, &cfg, EXE, &backups, false);
        let FileStatus::Processed { servers, wrote } = &r.status else {
            panic!("expected processed, got other status");
        };
        // Two wrapped, one skipped.
        let changed = servers.iter().filter(|s| matches!(s.outcome, Outcome::Changed)).count();
        let skipped = servers.iter().filter(|s| matches!(s.outcome, Outcome::Skipped(_))).count();
        assert_eq!(changed, 2);
        assert_eq!(skipped, 1);
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

        // Detach and confirm byte-identical restoration.
        let r = process_file(Op::Detach, Client::ClaudeDesktop, &cfg, EXE, &backups, false);
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
