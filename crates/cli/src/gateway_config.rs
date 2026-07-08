//! `gateway.toml`: the `name -> upstream URL` table that is the single source of
//! truth shared by `attach`, `detach`, and the `gateway` server.
//!
//! * `attach` records each url-type MCP server's original endpoint here and points
//!   the client at `http://127.0.0.1:<port>/u/<name>`.
//! * `detach` reads it back to restore the original endpoint.
//! * `gateway` reads it (when `--upstream` is not given) to know where to forward.
//!
//! The file lives at `<data_local>/mcpglass/gateway.toml`. Writes are atomic
//! (temp file + rename) so a crash mid-write never leaves a half-written table.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// The gateway's upstream table. `BTreeMap` keeps entries in a stable, sorted
/// order so the file is diff-friendly across rewrites.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// Route name (the `/u/<name>` segment) -> the real upstream MCP endpoint URL.
    #[serde(default)]
    pub servers: BTreeMap<String, String>,
}

impl GatewayConfig {
    /// Parse `gateway.toml` from `path`. Errors if the file is missing or malformed
    /// — callers that want best-effort behaviour use [`load_or_default`](Self::load_or_default).
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading gateway config {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing gateway config {}", path.display()))
    }

    /// Load `gateway.toml`, or an empty config if it is absent or unreadable. Used
    /// on paths where a missing/broken table should not be fatal (a fresh install
    /// has none; the gateway simply has no upstreams to route).
    pub fn load_or_default(path: &Path) -> Self {
        Self::load(path).unwrap_or_default()
    }

    /// The original upstream URL for a route `name`, if recorded.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.servers.get(name).map(String::as_str)
    }

    /// Atomically write the table to `path` (creating parent dirs), via a
    /// same-directory temp file + rename so readers never see a partial file.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating gateway config dir {}", parent.display()))?;
            }
        }
        let text = toml::to_string_pretty(self).context("serializing gateway config")?;

        let file_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("gateway.toml");
        let tmp = path.with_file_name(format!("{file_name}.tmp-{}", std::process::id()));
        std::fs::write(&tmp, text.as_bytes())
            .with_context(|| format!("writing temp gateway config {}", tmp.display()))?;
        if let Err(e) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e).with_context(|| {
                format!("renaming {} into place at {}", tmp.display(), path.display())
            });
        }
        Ok(())
    }
}

/// Default `gateway.toml` location: `<data_local>/mcpglass/gateway.toml`.
pub fn default_config_path() -> Option<PathBuf> {
    directories::BaseDirs::new().map(|b| b.data_local_dir().join("mcpglass").join("gateway.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mcpglass-gwcfg-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = temp_dir("roundtrip");
        let path = dir.join("gateway.toml");

        let mut cfg = GatewayConfig::default();
        cfg.servers
            .insert("github".to_owned(), "https://api.example.com/mcp/".to_owned());
        cfg.servers
            .insert("notion".to_owned(), "https://mcp.notion.com/mcp".to_owned());
        cfg.save(&path).unwrap();

        let loaded = GatewayConfig::load(&path).unwrap();
        assert_eq!(loaded, cfg);
        assert_eq!(loaded.get("github"), Some("https://api.example.com/mcp/"));
        assert_eq!(loaded.get("missing"), None);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_or_default_is_empty_when_absent() {
        let dir = temp_dir("absent");
        let path = dir.join("does-not-exist.toml");
        assert_eq!(GatewayConfig::load_or_default(&path), GatewayConfig::default());
        assert!(GatewayConfig::load(&path).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn save_leaves_no_temp_file_behind() {
        let dir = temp_dir("atomic");
        let path = dir.join("gateway.toml");
        GatewayConfig::default().save(&path).unwrap();
        let entries: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("gateway.toml")]);
        std::fs::remove_dir_all(&dir).ok();
    }
}
