//! GnomeHome API and dashboard backend (stub).
//!
//! For now this serves only `GET /healthz`. HTTPS, authentication (Argon2 passwords plus
//! passkeys or TOTP), and role-based authorization arrive in Phase 8. Until they exist, the
//! server refuses to listen on anything except loopback, so it can never be reached from
//! the LAN or the internet (NFR-01, NFR-05).
//!
//! The bind address comes from `[api].bind` in the shared config file
//! (`config/gnomehome.toml`, or the path in `GNOMEHOME_CONFIG`). Other tables in that file
//! belong to the Python jobs and are ignored here.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use axum::{Json, Router, routing::get};
use serde::Deserialize;
use serde_json::{Value, json};

/// Used when the config file has no `[api]` table. 8787 stays clear of Pi-hole's 8080.
pub const DEFAULT_BIND: &str = "127.0.0.1:8787";

/// Where the shared config file lives unless `GNOMEHOME_CONFIG` says otherwise.
pub const DEFAULT_CONFIG_PATH: &str = "config/gnomehome.toml";

#[derive(Debug, Default, Deserialize)]
struct FileConfig {
    #[serde(default)]
    api: ApiSection,
}

#[derive(Debug, Deserialize)]
struct ApiSection {
    #[serde(default = "default_bind")]
    bind: String,
}

impl Default for ApiSection {
    fn default() -> Self {
        Self {
            bind: default_bind(),
        }
    }
}

fn default_bind() -> String {
    DEFAULT_BIND.to_owned()
}

/// Builds the HTTP router.
pub fn app() -> Router {
    Router::new().route("/healthz", get(healthz))
}

async fn healthz() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "service": "gnomehome-api",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// Resolves the config file path from `GNOMEHOME_CONFIG`, falling back to the default.
pub fn config_path() -> PathBuf {
    std::env::var_os("GNOMEHOME_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH))
}

/// Reads `[api].bind` from the config file at `path`.
///
/// A missing file falls back to [`DEFAULT_BIND`] so `just serve` works before setup.
/// A file that exists but can't be parsed is an error, never silently ignored.
pub fn bind_address_from_file(path: &Path) -> Result<SocketAddr, String> {
    let raw = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => return Err(format!("cannot read {}: {err}", path.display())),
    };
    let config: FileConfig =
        toml::from_str(&raw).map_err(|err| format!("invalid TOML in {}: {err}", path.display()))?;
    parse_bind(&config.api.bind)
}

/// Parses a bind address and enforces the loopback-only rule.
pub fn parse_bind(bind: &str) -> Result<SocketAddr, String> {
    let addr: SocketAddr = bind
        .parse()
        .map_err(|err| format!("api.bind {bind:?} is not an IP:port address: {err}"))?;
    if !addr.ip().is_loopback() {
        return Err(format!(
            "api.bind {bind:?} is not a loopback address. Until TLS and authentication exist \
             (Phase 8), the API only listens on 127.0.0.1 or ::1"
        ));
    }
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[tokio::test]
    async fn healthz_returns_ok() {
        let response = app()
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["status"], "ok");
    }

    #[test]
    fn loopback_binds_are_accepted() {
        assert!(parse_bind("127.0.0.1:8787").is_ok());
        assert!(parse_bind("[::1]:8787").is_ok());
    }

    #[test]
    fn non_loopback_binds_are_refused() {
        assert!(parse_bind("0.0.0.0:8787").is_err());
        assert!(parse_bind("192.0.2.10:8787").is_err());
        assert!(parse_bind("[::]:8787").is_err());
    }

    #[test]
    fn missing_config_file_uses_default() {
        let addr = bind_address_from_file(Path::new("/nonexistent/gnomehome.toml")).unwrap();
        assert_eq!(addr, DEFAULT_BIND.parse().unwrap());
    }

    #[test]
    fn other_tables_in_the_shared_config_are_ignored() {
        let dir = std::env::temp_dir().join(format!("gnomehome-api-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("gnomehome.toml");
        std::fs::write(
            &path,
            "platform = \"mac\"\n[network]\nscan_targets = []\n[api]\nbind = \"127.0.0.1:9999\"\n",
        )
        .unwrap();
        let addr = bind_address_from_file(&path).unwrap();
        assert_eq!(addr.port(), 9999);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
