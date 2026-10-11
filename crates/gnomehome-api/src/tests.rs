use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{DateTime, Utc};
use gnomehome_core::testkit::migrated_db;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::*;
use crate::auth::{Role, add_user, base32_decode, totp_code};

const PASSWORD: &str = "correct horse battery";

struct Fixture {
    _dir: tempfile::TempDir,
    state: Shared,
    clock: Arc<AtomicI64>,
    secrets: Vec<(String, String)>,
}

fn fixture() -> Fixture {
    let (dir, path) = migrated_db();
    let conn = gnomehome_core::db::open(&path).unwrap();
    let t0: DateTime<Utc> = gnomehome_core::time::parse_ts("2026-10-11T12:00:00.000Z").unwrap();
    let mut secrets = Vec::new();
    for (name, role) in [
        ("vera", Role::Viewer),
        ("ana", Role::Analyst),
        ("owner", Role::Admin),
    ] {
        secrets.push((
            name.to_owned(),
            add_user(&conn, name, PASSWORD, role, t0).unwrap(),
        ));
    }
    conn.execute_batch(
        "INSERT INTO asset (id, mac, first_seen, last_seen, last_ip, vendor, hostname) VALUES \
           (1, '00:00:5e:00:53:51', '2026-10-11T00:00:00.000Z', '2026-10-11T00:00:00.000Z', '192.0.2.51', 'Example Camera Co', 'cam'); \
         INSERT INTO asset (id, mac, protected, first_seen, last_seen) VALUES \
           (2, '00:00:5e:00:53:01', 1, '2026-10-11T00:00:00.000Z', '2026-10-11T00:00:00.000Z'); \
         INSERT INTO incident (id, created_at, updated_at, asset_id, detection, severity, title, summary) VALUES \
           (7, '2026-10-11T00:00:00.000Z', '2026-10-11T00:00:00.000Z', 1, 'dns.beaconing', 'medium', 'Regular check-ins', 's'); \
         INSERT INTO playbook_run (id, playbook, version, incident_id, asset_id, tier, status, dry_run, started_at) VALUES \
           ('00000000000000aa', 'quarantine-suspected-c2', 1, 7, 1, 'ask_first', 'awaiting_approval', 1, '2026-10-11T12:00:00.000Z'); \
         INSERT INTO approval (run_id, requested_at, expires_at) VALUES \
           ('00000000000000aa', '2026-10-11T12:00:00.000Z', '2026-10-11T13:00:00.000Z');",
    )
    .unwrap();
    let clock = Arc::new(AtomicI64::new(t0.timestamp()));
    let tick = Arc::clone(&clock);
    let mut state = AppState::new(conn, true);
    state.clock =
        Box::new(move || DateTime::from_timestamp(tick.load(Ordering::SeqCst), 0).unwrap());
    Fixture {
        _dir: dir,
        state: Arc::new(state),
        clock,
        secrets,
    }
}

impl Fixture {
    fn code(&self, user: &str) -> String {
        let secret = &self.secrets.iter().find(|(n, _)| n == user).unwrap().1;
        let step = self.clock.load(Ordering::SeqCst) / 30;
        format!("{:06}", totp_code(&base32_decode(secret).unwrap(), step))
    }

    fn advance(&self, seconds: i64) {
        self.clock.fetch_add(seconds, Ordering::SeqCst);
    }

    async fn call(
        &self,
        method: &str,
        uri: &str,
        cookie: Option<&str>,
        csrf: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value, axum::http::HeaderMap) {
        let mut request = Request::builder().method(method).uri(uri);
        if let Some(c) = cookie {
            request = request.header("cookie", format!("{COOKIE}={c}"));
        }
        if let Some(t) = csrf {
            request = request.header("x-csrf-token", t);
        }
        let request = match body {
            Some(b) => request
                .header("content-type", "application/json")
                .body(Body::from(b.to_string())),
            None => request.body(Body::empty()),
        }
        .unwrap();
        let response = app(Arc::clone(&self.state), None)
            .oneshot(request)
            .await
            .unwrap();
        let (status, headers) = (response.status(), response.headers().clone());
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, value, headers)
    }

    /// Signs in and returns (cookie token, csrf token).
    async fn login(&self, user: &str) -> (String, String) {
        let body = json!({ "username": user, "password": PASSWORD, "code": self.code(user) });
        let (status, value, headers) = self
            .call("POST", "/api/login", None, None, Some(body))
            .await;
        assert_eq!(status, StatusCode::OK, "{value}");
        let cookie = headers
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert!(
            cookie.contains("HttpOnly")
                && cookie.contains("SameSite=Strict")
                && cookie.contains("Secure")
        );
        let token = cookie
            .split(';')
            .next()
            .unwrap()
            .split_once('=')
            .unwrap()
            .1
            .to_owned();
        self.advance(30); // the next login needs the next code
        (token, value["csrf"].as_str().unwrap().to_owned())
    }

    fn audit_actions(&self) -> Vec<(String, String, String)> {
        let conn = self.state.db();
        let mut stmt = conn
            .prepare("SELECT actor, action, result FROM audit_log ORDER BY seq")
            .unwrap();
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }
}

#[tokio::test]
async fn health_and_security_headers() {
    let f = fixture();
    let (status, value, headers) = f.call("GET", "/healthz", None, None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["status"], "ok");
    let csp = headers
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(csp.contains("frame-ancestors 'none'") && csp.contains("'wasm-unsafe-eval'"));
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
}

#[tokio::test]
async fn everything_needs_a_session() {
    let f = fixture();
    for uri in [
        "/api/me",
        "/api/assets",
        "/api/incidents",
        "/api/approvals",
        "/api/audit",
    ] {
        assert_eq!(
            f.call("GET", uri, None, None, None).await.0,
            StatusCode::UNAUTHORIZED,
            "{uri}"
        );
    }
    let forged = "a".repeat(64);
    assert_eq!(
        f.call("GET", "/api/assets", Some(&forged), None, None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn login_failures_are_generic_and_audited() {
    let f = fixture();
    let wrong = json!({ "username": "owner", "password": "nope", "code": f.code("owner") });
    let (status, value, _) = f.call("POST", "/api/login", None, None, Some(wrong)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(value["error"], "wrong username, password, or code");
    let ghost = json!({ "username": "ghost", "password": PASSWORD, "code": "123456" });
    assert_eq!(
        f.call("POST", "/api/login", None, None, Some(ghost))
            .await
            .1,
        value
    );
    let hostile = json!({ "username": "x'; DROP TABLE asset;--", "password": "p", "code": "1" });
    f.call("POST", "/api/login", None, None, Some(hostile))
        .await;
    let log = f.audit_actions();
    assert_eq!(
        log[0],
        ("user:owner".into(), "auth.login".into(), "failure".into())
    );
    assert_eq!(log[2].0, "anonymous"); // malformed usernames never reach the audit log
}

#[tokio::test]
async fn viewers_see_data_but_not_the_protected_device() {
    let f = fixture();
    let (token, _) = f.login("vera").await;
    let (status, assets, _) = f.call("GET", "/api/assets", Some(&token), None, None).await;
    assert_eq!(status, StatusCode::OK);
    let list = assets.as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["ip"], "192.0.2.51");
    assert!(!assets.to_string().contains("53:01"));
    let (_, incidents, _) = f
        .call("GET", "/api/incidents", Some(&token), None, None)
        .await;
    assert_eq!(incidents[0]["title"], "Regular check-ins");
    // Viewers can't see approvals or the audit log, or resolve incidents.
    assert_eq!(
        f.call("GET", "/api/approvals", Some(&token), None, None)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.call("GET", "/api/audit", Some(&token), None, None)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn state_changes_need_the_csrf_token() {
    let f = fixture();
    let (token, csrf) = f.login("ana").await;
    let uri = "/api/incidents/7/resolve";
    assert_eq!(
        f.call("POST", uri, Some(&token), None, None).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.call("POST", uri, Some(&token), Some("wrong"), None)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.call("POST", uri, Some(&token), Some(&csrf), None).await.0,
        StatusCode::NO_CONTENT
    );
    assert!(
        f.audit_actions()
            .iter()
            .any(|a| a.0 == "user:ana" && a.1 == "incident.resolve")
    );
}

#[tokio::test]
async fn approving_needs_an_admin_and_a_fresh_code() {
    let f = fixture();
    let uri = "/api/approvals/00000000000000aa";
    let (ana, ana_csrf) = f.login("ana").await;
    let body = json!({ "decision": "approve", "code": f.code("ana") });
    assert_eq!(
        f.call("POST", uri, Some(&ana), Some(&ana_csrf), Some(body))
            .await
            .0,
        StatusCode::FORBIDDEN
    );

    let (owner, csrf) = f.login("owner").await;
    let (_, waiting, _) = f
        .call("GET", "/api/approvals", Some(&owner), None, None)
        .await;
    assert_eq!(waiting[0]["run_id"], "00000000000000aa");
    let stale = json!({ "decision": "approve", "code": "000000" });
    assert_eq!(
        f.call("POST", uri, Some(&owner), Some(&csrf), Some(stale))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let good = json!({ "decision": "approve", "code": f.code("owner") });
    assert_eq!(
        f.call("POST", uri, Some(&owner), Some(&csrf), Some(good))
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    let decision: String = f
        .state
        .db()
        .query_row("SELECT decided_by FROM approval", [], |r| r.get(0))
        .unwrap();
    assert_eq!(decision, "user:owner");
    // Deciding twice is a conflict, not a second action.
    f.advance(30);
    let again = json!({ "decision": "deny", "code": f.code("owner") });
    assert_eq!(
        f.call("POST", uri, Some(&owner), Some(&csrf), Some(again))
            .await
            .0,
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn sessions_time_out_and_logout_ends_them() {
    let f = fixture();
    let (token, csrf) = f.login("vera").await;
    f.advance(29 * 60);
    assert_eq!(
        f.call(
            "POST",
            "/api/session/extend",
            Some(&token),
            Some(&csrf),
            None
        )
        .await
        .0,
        StatusCode::OK
    );
    f.advance(29 * 60);
    assert_eq!(
        f.call("GET", "/api/me", Some(&token), None, None).await.0,
        StatusCode::OK
    );
    f.advance(31 * 60);
    assert_eq!(
        f.call("GET", "/api/me", Some(&token), None, None).await.0,
        StatusCode::UNAUTHORIZED
    );

    let (token, csrf) = f.login("vera").await;
    let (status, _, headers) = f
        .call("POST", "/api/logout", Some(&token), Some(&csrf), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        headers
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    assert_eq!(
        f.call("GET", "/api/me", Some(&token), None, None).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn admins_can_verify_the_audit_chain() {
    let f = fixture();
    let (token, _) = f.login("owner").await;
    let (status, value, _) = f.call("GET", "/api/audit", Some(&token), None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["ok"], true);
    assert_eq!(value["recent"][0]["action"], "auth.login");
}

#[test]
fn binding_beyond_loopback_needs_tls() {
    let base = Path::new("/etc/gnomehome");
    let table = |text: &str| -> toml::Table { toml::from_str(text).unwrap() };
    assert!(api_config(&table("bind = \"127.0.0.1:8787\""), base).is_ok());
    assert!(api_config(&table("bind = \"192.0.2.2:8443\""), base).is_err());
    assert!(
        api_config(
            &table("bind = \"0.0.0.0:8443\"\ntls_cert = \"c.pem\"\ntls_key = \"k.pem\""),
            base
        )
        .is_err()
    );
    let ok = api_config(
        &table("bind = \"192.0.2.2:8443\"\ntls_cert = \"c.pem\"\ntls_key = \"k.pem\""),
        base,
    )
    .unwrap();
    assert_eq!(ok.tls.unwrap().0, Path::new("/etc/gnomehome/c.pem"));
    assert!(
        api_config(
            &table("bind = \"192.0.2.2:8443\"\ntls_cert = \"c.pem\""),
            base
        )
        .is_err()
    );
}
