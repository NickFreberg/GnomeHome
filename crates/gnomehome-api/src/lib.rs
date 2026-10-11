//! GnomeHome API and dashboard backend (Phase 8, NFR-01, NFR-06, FR-19).
//!
//! Every route under `/api` except `/api/login` needs a session, and every
//! state-changing request also needs the session's CSRF token in `X-CSRF-Token`.
//!
//! | Route | Role | What |
//! | --- | --- | --- |
//! | `POST /api/login` | anyone | username, password, and TOTP code; sets the session cookie |
//! | `POST /api/logout` | any | ends the session |
//! | `GET /api/me`, `POST /api/session/extend` | any | who's signed in; keep the session alive |
//! | `GET /api/assets`, `GET /api/incidents` | viewer | the inventory with risk; the incident log |
//! | `POST /api/incidents/{id}/resolve` | analyst | mark an incident resolved |
//! | `GET /api/approvals` | analyst | responses waiting for a decision |
//! | `POST /api/approvals/{run}` | admin + fresh code | approve or deny; the engine acts within a minute |
//! | `GET /api/audit` | admin | verify the hash chain; recent entries |
//!
//! Responses never include protected devices: the database holds none (only
//! existence rows, which are filtered out), and audit entries name them by label.
//! Every login, failure, and action is audited.
//!
//! The server listens on loopback without TLS for development. Anywhere else it
//! requires a certificate and key (HTTPS only), and the Pi's firewall allows the
//! dashboard only from the LAN (NFR-05).

pub mod auth;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::extract::{Path as UrlPath, Query, State};
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use gnomehome_core::audit::{self, Outcome};
use gnomehome_core::time::format_ts;
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::auth::{LoginError, Role, Session};

/// Used when the config file has no `[api]` table. 8787 stays clear of Pi-hole's 8080.
pub const DEFAULT_BIND: &str = "127.0.0.1:8787";
pub const COOKIE: &str = "gh_session";

pub struct AppState {
    pub conn: Mutex<Connection>,
    pub cookie_secure: bool,
    pub clock: Box<dyn Fn() -> DateTime<Utc> + Send + Sync>,
}

impl AppState {
    pub fn new(conn: Connection, cookie_secure: bool) -> AppState {
        AppState {
            conn: Mutex::new(conn),
            cookie_secure,
            clock: Box::new(Utc::now),
        }
    }

    fn now(&self) -> DateTime<Utc> {
        (self.clock)()
    }

    fn db(&self) -> std::sync::MutexGuard<'_, Connection> {
        // A panic while holding the lock leaves SQLite consistent, so carry on.
        self.conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

type Shared = Arc<AppState>;

#[derive(Debug)]
pub struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(_: rusqlite::Error) -> Self {
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, "database error".into())
    }
}

fn err(status: StatusCode, message: &str) -> ApiError {
    ApiError(status, message.to_owned())
}

/// Builds the router. `web_dir`, when given, serves the built dashboard at `/`.
pub fn app(state: Shared, web_dir: Option<&Path>) -> Router {
    let api = Router::new()
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/me", get(me))
        .route("/api/session/extend", post(extend))
        .route("/api/assets", get(assets))
        .route("/api/incidents", get(incidents))
        .route("/api/incidents/{id}/resolve", post(resolve_incident))
        .route("/api/approvals", get(approvals))
        .route("/api/approvals/{run}", post(decide))
        .route("/api/audit", get(audit_log))
        .route("/healthz", get(healthz))
        .with_state(state);
    let router = match web_dir {
        Some(dir) => api.fallback_service(
            tower_http::services::ServeDir::new(dir)
                .fallback(tower_http::services::ServeFile::new(dir.join("index.html"))),
        ),
        None => api,
    };
    router.layer(middleware::from_fn(security_headers))
}

/// Headers on every response: no framing, no sniffing, no referrer, and a strict CSP
/// that still lets the Wasm dashboard run (`wasm-unsafe-eval`, no inline scripts).
async fn security_headers(request: Request<axum::body::Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    let set = |h: &mut HeaderMap, name: &'static str, value: &'static str| {
        h.insert(name, HeaderValue::from_static(value));
    };
    set(
        headers,
        "content-security-policy",
        "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; \
         connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    );
    set(headers, "x-content-type-options", "nosniff");
    set(headers, "x-frame-options", "DENY");
    set(headers, "referrer-policy", "no-referrer");
    set(
        headers,
        "permissions-policy",
        "camera=(), microphone=(), geolocation=()",
    );
    set(headers, "strict-transport-security", "max-age=31536000");
    set(headers, "cache-control", "no-store");
    response
}

async fn healthz() -> Json<Value> {
    Json(
        json!({ "status": "ok", "service": "gnomehome-api", "version": env!("CARGO_PKG_VERSION") }),
    )
}

// ------------------------------------------------------------------ sessions

fn cookie_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == COOKIE)
        .map(|(_, value)| value.to_owned())
        .filter(|t| t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// The signed-in session, if its role is at least `min`. State-changing calls also
/// pass `csrf = true`.
fn authed(
    state: &AppState,
    headers: &HeaderMap,
    min: Role,
    csrf: bool,
) -> Result<(String, Session), ApiError> {
    let token =
        cookie_token(headers).ok_or_else(|| err(StatusCode::UNAUTHORIZED, "sign in first"))?;
    let session = auth::session(&state.db(), &token, state.now()).ok_or_else(|| {
        err(
            StatusCode::UNAUTHORIZED,
            "your session ended; sign in again",
        )
    })?;
    if csrf {
        let sent = headers
            .get("x-csrf-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !auth::constant_time_eq(sent.as_bytes(), session.csrf.as_bytes()) {
            return Err(err(StatusCode::FORBIDDEN, "missing or wrong CSRF token"));
        }
    }
    if session.user.role < min {
        return Err(err(StatusCode::FORBIDDEN, "your role doesn't allow this"));
    }
    Ok((token, session))
}

fn session_json(s: &Session, now: DateTime<Utc>) -> Value {
    json!({
        "username": s.user.username,
        "role": s.user.role.as_str(),
        "csrf": s.csrf,
        "expires_at": format_ts(s.expires_at),
        "mfa_fresh": s.mfa_fresh(now),
    })
}

fn audit(
    state: &AppState,
    actor: &str,
    action: &str,
    target: Option<&str>,
    outcome: Outcome,
    details: Option<Value>,
) {
    let mut conn = state.db();
    if let Err(e) = audit::append(&mut conn, actor, action, target, outcome, details.as_ref()) {
        eprintln!("gnomehome-api: audit append failed: {e}");
    }
}

#[derive(Deserialize)]
struct LoginBody {
    username: String,
    password: String,
    code: String,
}

async fn login(
    State(state): State<Shared>,
    Json(body): Json<LoginBody>,
) -> Result<Response, ApiError> {
    let now = state.now();
    // The username is untrusted text: only a well-formed one goes into the audit log.
    let actor = if auth::valid_username(&body.username) {
        format!("user:{}", body.username)
    } else {
        "anonymous".into()
    };
    if body.password.len() > 1024 || body.code.len() > 16 {
        return Err(err(StatusCode::BAD_REQUEST, "request too large"));
    }
    let result = auth::login(&state.db(), &body.username, &body.password, &body.code, now);
    match result {
        Ok((token, session)) => {
            audit(&state, &actor, "auth.login", None, Outcome::Success, None);
            let secure = if state.cookie_secure { "; Secure" } else { "" };
            let cookie = format!("{COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/{secure}");
            let mut response = Json(session_json(&session, now)).into_response();
            response.headers_mut().insert(
                header::SET_COOKIE,
                HeaderValue::from_str(&cookie)
                    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "cookie"))?,
            );
            Ok(response)
        }
        Err(LoginError::Locked(until)) => {
            audit(
                &state,
                &actor,
                "auth.login",
                None,
                Outcome::Refused,
                Some(json!({ "reason": "locked" })),
            );
            Err(ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                format!("too many failed attempts; try again after {until}"),
            ))
        }
        Err(LoginError::Invalid) => {
            audit(&state, &actor, "auth.login", None, Outcome::Failure, None);
            Err(err(
                StatusCode::UNAUTHORIZED,
                "wrong username, password, or code",
            ))
        }
    }
}

async fn logout(State(state): State<Shared>, headers: HeaderMap) -> Result<Response, ApiError> {
    let (token, session) = authed(&state, &headers, Role::Viewer, true)?;
    auth::logout(&state.db(), &token);
    audit(
        &state,
        &format!("user:{}", session.user.username),
        "auth.logout",
        None,
        Outcome::Success,
        None,
    );
    let secure = if state.cookie_secure { "; Secure" } else { "" };
    let clear = format!("{COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0{secure}");
    let mut response = StatusCode::NO_CONTENT.into_response();
    if let Ok(value) = HeaderValue::from_str(&clear) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    Ok(response)
}

async fn me(State(state): State<Shared>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let (_, session) = authed(&state, &headers, Role::Viewer, false)?;
    Ok(Json(session_json(&session, state.now())))
}

async fn extend(State(state): State<Shared>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let (_, session) = authed(&state, &headers, Role::Viewer, true)?;
    Ok(Json(session_json(&session, state.now())))
}

// ------------------------------------------------------------------ data

fn rows(
    conn: &Connection,
    sql: &str,
    params: impl rusqlite::Params,
) -> Result<Vec<Value>, ApiError> {
    let mut stmt = conn.prepare(sql)?;
    let names: Vec<String> = stmt.column_names().into_iter().map(str::to_owned).collect();
    let out = stmt
        .query_map(params, |r| {
            let mut object = serde_json::Map::new();
            for (i, name) in names.iter().enumerate() {
                let value = match r.get_ref(i)? {
                    rusqlite::types::ValueRef::Null => Value::Null,
                    rusqlite::types::ValueRef::Integer(n) => json!(n),
                    rusqlite::types::ValueRef::Real(f) => json!(f),
                    rusqlite::types::ValueRef::Text(t) => json!(String::from_utf8_lossy(t)),
                    rusqlite::types::ValueRef::Blob(_) => Value::Null,
                };
                object.insert(name.clone(), value);
            }
            Ok(Value::Object(object))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(out)
}

async fn assets(State(state): State<Shared>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    authed(&state, &headers, Role::Viewer, false)?;
    let list = rows(
        &state.db(),
        "SELECT a.id, a.last_ip AS ip, a.mac, a.vendor, a.hostname, a.device_type, a.os_guess, \
         a.mac_randomized, a.first_seen, a.last_seen, r.score AS risk_score, r.level AS risk_level, \
         json_extract(r.factors, '$.summary') AS risk_summary \
         FROM asset a LEFT JOIN risk_score r ON r.asset_id = a.id \
           AND r.score_date = (SELECT MAX(score_date) FROM risk_score WHERE asset_id = a.id) \
         WHERE a.protected = 0 ORDER BY a.last_ip",
        [],
    )?;
    Ok(Json(json!(list)))
}

#[derive(Deserialize)]
struct IncidentQuery {
    #[serde(default)]
    all: bool,
}

async fn incidents(
    State(state): State<Shared>,
    headers: HeaderMap,
    Query(q): Query<IncidentQuery>,
) -> Result<Json<Value>, ApiError> {
    authed(&state, &headers, Role::Viewer, false)?;
    let filter = if q.all {
        ""
    } else {
        "WHERE status IN ('open', 'pending_approval', 'acknowledged')"
    };
    let list = rows(
        &state.db(),
        &format!(
            "SELECT id, created_at, COALESCE(occurred_at, created_at) AS occurred_at, severity, detection, \
             title, device, COALESCE(what_happened, summary) AS what_happened, why_it_matters, next_steps, \
             mitre_technique, confidence, status, outcome, playbook \
             FROM incident {filter} ORDER BY COALESCE(occurred_at, created_at) DESC LIMIT 500"
        ),
        [],
    )?;
    Ok(Json(json!(list)))
}

async fn resolve_incident(
    State(state): State<Shared>,
    headers: HeaderMap,
    UrlPath(id): UrlPath<i64>,
) -> Result<StatusCode, ApiError> {
    let (_, session) = authed(&state, &headers, Role::Analyst, true)?;
    let changed = state.db().execute(
        "UPDATE incident SET status = 'resolved', updated_at = ?1 WHERE id = ?2 AND status <> 'resolved'",
        rusqlite::params![format_ts(state.now()), id],
    )?;
    if changed == 0 {
        return Err(err(
            StatusCode::NOT_FOUND,
            "no open incident with that number",
        ));
    }
    let actor = format!("user:{}", session.user.username);
    audit(
        &state,
        &actor,
        "incident.resolve",
        Some(&format!("incident:{id}")),
        Outcome::Success,
        None,
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn approvals(
    State(state): State<Shared>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    authed(&state, &headers, Role::Analyst, false)?;
    let list = rows(
        &state.db(),
        "SELECT a.run_id, r.playbook, a.requested_at, a.expires_at, i.id AS incident_id, i.title, \
         i.severity, i.device, r.outcome FROM approval a JOIN playbook_run r ON r.id = a.run_id \
         LEFT JOIN incident i ON i.id = r.incident_id \
         WHERE a.decision IS NULL AND a.expires_at > ?1 ORDER BY a.requested_at",
        [format_ts(state.now())],
    )?;
    Ok(Json(json!(list)))
}

#[derive(Deserialize)]
struct DecisionBody {
    decision: String,
    code: String,
}

/// Approve or deny: admins only, with a TOTP code entered right now (disruptive
/// actions need a fresh MFA check, plan "AAA").
async fn decide(
    State(state): State<Shared>,
    headers: HeaderMap,
    UrlPath(run_id): UrlPath<String>,
    Json(body): Json<DecisionBody>,
) -> Result<StatusCode, ApiError> {
    let (token, session) = authed(&state, &headers, Role::Admin, true)?;
    let decision = match body.decision.as_str() {
        "approve" => "approved",
        "deny" => "denied",
        _ => {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "decision must be approve or deny",
            ));
        }
    };
    if run_id.len() != 16 || !run_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(err(StatusCode::BAD_REQUEST, "not a run ID"));
    }
    let now = state.now();
    let actor = format!("user:{}", session.user.username);
    if !auth::reverify(&state.db(), &token, session.user.id, &body.code, now) {
        audit(
            &state,
            &actor,
            "auth.mfa",
            Some(&format!("run:{run_id}")),
            Outcome::Failure,
            None,
        );
        return Err(err(
            StatusCode::FORBIDDEN,
            "enter a current code from your authenticator app",
        ));
    }
    gnomehome_playbook::engine::record_decision(&mut state.db(), &run_id, &actor, decision, now)
        .map_err(|e| ApiError(StatusCode::CONFLICT, e))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn audit_log(
    State(state): State<Shared>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    authed(&state, &headers, Role::Admin, false)?;
    let conn = state.db();
    let report = audit::verify(&conn)?;
    let recent = rows(
        &conn,
        "SELECT seq, ts, actor, action, target, result FROM audit_log ORDER BY seq DESC LIMIT 50",
        [],
    )?;
    Ok(Json(
        json!({ "rows": report.rows, "ok": report.ok(), "problems": report.problems, "recent": recent }),
    ))
}

// ------------------------------------------------------------------ config

/// `[api]` settings, resolved against the config file's folder.
#[derive(Debug, Clone)]
pub struct ApiConfig {
    pub bind: SocketAddr,
    pub tls: Option<(PathBuf, PathBuf)>,
    pub web_dir: Option<PathBuf>,
    pub cookie_secure: bool,
}

pub fn api_config(table: &toml::Table, base: &Path) -> Result<ApiConfig, String> {
    let get = |key: &str| table.get(key).and_then(|v| v.as_str());
    let bind_text = get("bind").unwrap_or(DEFAULT_BIND);
    let bind: SocketAddr = bind_text
        .parse()
        .map_err(|e| format!("api.bind {bind_text:?} is not an IP:port address: {e}"))?;
    let path = |key: &str| get(key).map(|v| gnomehome_core::config::resolve_path(v, base));
    let tls = match (path("tls_cert"), path("tls_key")) {
        (Some(cert), Some(key)) => Some((cert, key)),
        (None, None) => None,
        _ => return Err("set both api.tls_cert and api.tls_key, or neither".into()),
    };
    if !bind.ip().is_loopback() && tls.is_none() {
        return Err(format!(
            "api.bind {bind_text:?} is not a loopback address, so it needs HTTPS: set api.tls_cert and api.tls_key"
        ));
    }
    if bind.ip().is_unspecified() {
        return Err(
            "api.bind must name one address (the Pi's LAN address), not 0.0.0.0 or ::".into(),
        );
    }
    let cookie_secure = table
        .get("cookie_secure")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    Ok(ApiConfig {
        bind,
        tls,
        web_dir: path("web_dir"),
        cookie_secure,
    })
}

#[cfg(test)]
mod tests;
