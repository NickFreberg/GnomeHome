//! The part of `config/gnomehome.toml` the Rust services read.
//!
//! Python (`config.py`) validates the whole file. Rust reads only what it needs and
//! ignores every other table. Paths follow the same rules: `~` expands to the home
//! folder, and relative paths resolve against the config file's own folder.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;

/// Where the config lives unless `GNOMEHOME_CONFIG` says otherwise.
pub const DEFAULT_CONFIG_PATH: &str = "config/gnomehome.toml";

#[derive(Debug)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Deserialize)]
struct RawConfig {
    platform: String,
    platforms: BTreeMap<String, RawPlatform>,
    #[serde(default)]
    api: Option<toml::Table>,
    #[serde(default)]
    network: Option<toml::Table>,
}

#[derive(Debug, Deserialize)]
struct RawPlatform {
    db_path: String,
    dev_db_path: String,
    protected_assets: String,
    #[serde(default)]
    pihole_log: Option<String>,
    #[serde(default)]
    run_dir: Option<String>,
    #[serde(default)]
    data_dir: Option<String>,
}

/// Resolved settings for the selected platform.
#[derive(Debug, Clone)]
pub struct Config {
    pub path: PathBuf,
    pub platform: String,
    pub db_path: PathBuf,
    pub dev_db_path: PathBuf,
    pub protected_assets: PathBuf,
    pub pihole_log: Option<PathBuf>,
    pub run_dir: Option<PathBuf>,
    pub data_dir: Option<PathBuf>,
    /// `[api]` as raw TOML, for the API crate to read its own keys from.
    pub api: toml::Table,
    /// `[network]` as raw TOML.
    pub network: toml::Table,
}

impl Config {
    /// Reads the file named by `GNOMEHOME_CONFIG`, or `config/gnomehome.toml`.
    pub fn load_default() -> Result<Config, ConfigError> {
        Config::load(&config_path())
    }

    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|err| {
            ConfigError(format!(
                "cannot read config {}: {err}. Run `just setup`.",
                path.display()
            ))
        })?;
        Config::parse(&text, path)
    }

    pub fn parse(text: &str, path: &Path) -> Result<Config, ConfigError> {
        let raw: RawConfig = toml::from_str(text)
            .map_err(|err| ConfigError(format!("invalid config {}: {err}", path.display())))?;
        let platform = raw.platforms.get(&raw.platform).ok_or_else(|| {
            ConfigError(format!(
                "platform = {:?} has no [platforms.{}] table",
                raw.platform, raw.platform
            ))
        })?;
        let base = path
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
        let resolve = |value: &str| resolve_path(value, &base);
        Ok(Config {
            path: path.to_path_buf(),
            platform: raw.platform.clone(),
            db_path: resolve(&platform.db_path),
            dev_db_path: resolve(&platform.dev_db_path),
            protected_assets: resolve(&platform.protected_assets),
            pihole_log: platform.pihole_log.as_deref().map(resolve),
            run_dir: platform.run_dir.as_deref().map(resolve),
            data_dir: platform.data_dir.as_deref().map(resolve),
            api: raw.api.unwrap_or_default(),
            network: raw.network.unwrap_or_default(),
        })
    }

    /// The real database, or the dev database that holds synthetic data.
    pub fn database(&self, dev: bool) -> &Path {
        if dev {
            &self.dev_db_path
        } else {
            &self.db_path
        }
    }
}

pub fn config_path() -> PathBuf {
    std::env::var_os("GNOMEHOME_CONFIG")
        .map_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH), PathBuf::from)
}

/// `~` expansion, then relative-to-`base`, then lexical normalization (like Python's
/// `os.path.normpath`).
pub fn resolve_path(value: &str, base: &Path) -> PathBuf {
    let expanded = match value.strip_prefix("~/") {
        Some(rest) => std::env::var_os("HOME")
            .map_or_else(|| PathBuf::from(value), |h| PathBuf::from(h).join(rest)),
        None if value == "~" => {
            std::env::var_os("HOME").map_or_else(|| PathBuf::from(value), PathBuf::from)
        }
        None => PathBuf::from(value),
    };
    let joined = if expanded.is_absolute() {
        expanded
    } else {
        base.join(expanded)
    };
    normalize(&joined)
}

fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::repo_root;

    #[test]
    fn example_config_resolves_against_its_folder() {
        let path = repo_root().join("config/gnomehome.example.toml");
        let config = Config::load(&path).unwrap();
        let config_dir = normalize(&repo_root().join("config"));
        assert_eq!(config.platform, "mac");
        assert_eq!(
            config.protected_assets,
            config_dir.join("protected_assets.yaml")
        );
        assert_eq!(
            config.db_path,
            normalize(&repo_root().join("data/gnomehome.sqlite3"))
        );
        assert!(config.database(true).ends_with("dev.sqlite3"));
    }

    #[test]
    fn pi_platform_uses_absolute_paths() {
        let path = repo_root().join("config/gnomehome.example.toml");
        let text = std::fs::read_to_string(&path).unwrap().replacen(
            "platform = \"mac\"",
            "platform = \"pi\"",
            1,
        );
        let config = Config::parse(&text, &path).unwrap();
        assert_eq!(
            config.pihole_log.unwrap(),
            PathBuf::from("/var/log/pihole/pihole.log")
        );
        assert_eq!(
            config.protected_assets,
            PathBuf::from("/etc/gnomehome/protected_assets.yaml")
        );
    }

    #[test]
    fn unknown_platform_is_an_error() {
        let text = "platform = \"vax\"\n[platforms.mac]\ndb_path = \"a\"\ndev_db_path = \"b\"\nprotected_assets = \"c\"\n";
        assert!(Config::parse(text, Path::new("/x/gnomehome.toml")).is_err());
    }
}
