//! Calls to gnomehome-api. The session cookie travels automatically (same origin);
//! every state-changing call also sends the session's CSRF token.

use gloo_net::http::{Request, Response};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::json;

use crate::model::{Approval, Asset, Incident, Me};

#[derive(Deserialize)]
struct ErrorBody {
    error: String,
}

async fn read<T: DeserializeOwned>(response: Response) -> Result<T, String> {
    if response.ok() {
        response
            .json::<T>()
            .await
            .map_err(|e| format!("unexpected reply: {e}"))
    } else {
        Err(error_of(response).await)
    }
}

async fn error_of(response: Response) -> String {
    match response.json::<ErrorBody>().await {
        Ok(body) => body.error,
        Err(_) => format!("the server answered {}", response.status()),
    }
}

async fn ok(response: Response) -> Result<(), String> {
    if response.ok() {
        Ok(())
    } else {
        Err(error_of(response).await)
    }
}

fn net(e: gloo_net::Error) -> String {
    format!("can't reach GnomeHome: {e}")
}

pub async fn login(username: &str, password: &str, code: &str) -> Result<Me, String> {
    let body = json!({ "username": username, "password": password, "code": code });
    let request = Request::post("/api/login").json(&body).map_err(net)?;
    read(request.send().await.map_err(net)?).await
}

pub async fn me() -> Result<Me, String> {
    read(Request::get("/api/me").send().await.map_err(net)?).await
}

pub async fn extend(csrf: &str) -> Result<Me, String> {
    let request = Request::post("/api/session/extend").header("X-CSRF-Token", csrf);
    read(request.send().await.map_err(net)?).await
}

pub async fn logout(csrf: &str) -> Result<(), String> {
    let request = Request::post("/api/logout").header("X-CSRF-Token", csrf);
    ok(request.send().await.map_err(net)?).await
}

pub async fn assets() -> Result<Vec<Asset>, String> {
    read(Request::get("/api/assets").send().await.map_err(net)?).await
}

pub async fn incidents() -> Result<Vec<Incident>, String> {
    read(Request::get("/api/incidents").send().await.map_err(net)?).await
}

pub async fn approvals() -> Result<Vec<Approval>, String> {
    read(Request::get("/api/approvals").send().await.map_err(net)?).await
}

pub async fn resolve(csrf: &str, id: i64) -> Result<(), String> {
    let request =
        Request::post(&format!("/api/incidents/{id}/resolve")).header("X-CSRF-Token", csrf);
    ok(request.send().await.map_err(net)?).await
}

pub async fn decide(csrf: &str, run_id: &str, approve: bool, code: &str) -> Result<(), String> {
    let body = json!({ "decision": if approve { "approve" } else { "deny" }, "code": code });
    let request = Request::post(&format!("/api/approvals/{run_id}"))
        .header("X-CSRF-Token", csrf)
        .json(&body)
        .map_err(net)?;
    ok(request.send().await.map_err(net)?).await
}
