//! `gnomehome-api`: the dashboard server and its account tool.
//!
//! ```text
//! gnomehome-api [serve]                        run the server (just serve)
//! gnomehome-api user add NAME --role ROLE      roles: viewer, analyst, admin
//! gnomehome-api user list
//! gnomehome-api user disable NAME | enable NAME
//! gnomehome-api user reset-mfa NAME            a new authenticator secret
//! gnomehome-api user password NAME
//! ```
//!
//! Global options: `--config PATH`, `--dev` (the synthetic-data database).
//! Passwords are read from the terminal without echo, or from standard input with
//! `--password-stdin`.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use chrono::Utc;
use gnomehome_api::auth::{self, Role};
use gnomehome_api::{AppState, api_config, app};
use gnomehome_core::audit::{self, Outcome};
use gnomehome_core::config::{Config, config_path};
use gnomehome_core::db;

const USAGE: &str = "usage: gnomehome-api [--config PATH] [--dev] [serve | user add NAME --role ROLE | \
    user list | user disable NAME | user enable NAME | user reset-mfa NAME | user password NAME] [--password-stdin]";

#[tokio::main]
async fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut config = config_path();
    let mut dev = false;
    let mut stdin_password = false;
    let mut role = None;
    let mut rest = Vec::new();
    while !args.is_empty() {
        let arg = args.remove(0);
        match arg.as_str() {
            "--config" if !args.is_empty() => config = PathBuf::from(args.remove(0)),
            "--role" if !args.is_empty() => role = Some(args.remove(0)),
            "--dev" => dev = true,
            "--password-stdin" => stdin_password = true,
            "-h" | "--help" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            _ => rest.push(arg),
        }
    }
    let result = match rest
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] | ["serve"] => serve(&config, dev).await,
        ["user", command @ ..] => users(&config, dev, command, role.as_deref(), stdin_password),
        _ => Err(USAGE.to_owned()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("gnomehome-api: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn open(config: &Config, dev: bool) -> Result<rusqlite::Connection, String> {
    let path = config.database(dev);
    let conn = db::open(path)
        .map_err(|e| format!("{}: {e}. Run `just migrate` first.", path.display()))?;
    db::require_schema(&conn, 7).map_err(|e| e.to_string())?;
    Ok(conn)
}

async fn serve(config_file: &std::path::Path, dev: bool) -> Result<(), String> {
    let config = Config::load(config_file).map_err(|e| e.to_string())?;
    let base = config_file
        .parent()
        .map_or_else(|| PathBuf::from("."), std::path::Path::to_path_buf);
    let api = api_config(&config.api, &base)?;
    let conn = open(&config, dev)?;
    let users: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM app_user WHERE disabled = 0",
            [],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    if users == 0 {
        eprintln!("gnomehome-api: no accounts yet. Create one with: just user-add <name> admin");
    }
    let state = Arc::new(AppState::new(conn, api.cookie_secure));
    let router = app(state, api.web_dir.as_deref());

    let shutdown = async {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    match &api.tls {
        None => {
            let listener = tokio::net::TcpListener::bind(api.bind)
                .await
                .map_err(|e| format!("cannot listen on {}: {e}", api.bind))?;
            println!(
                "gnomehome-api listening on http://{} (loopback only; Ctrl+C to stop)",
                api.bind
            );
            axum::serve(listener, router)
                .with_graceful_shutdown(shutdown)
                .await
                .map_err(|e| format!("server error: {e}"))
        }
        Some((cert, key)) => {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
                .await
                .map_err(|e| format!("can't load the TLS certificate or key: {e}"))?;
            println!(
                "gnomehome-api listening on https://{} (Ctrl+C to stop)",
                api.bind
            );
            let handle = axum_server::Handle::new();
            let stopper = handle.clone();
            tokio::spawn(async move {
                shutdown.await;
                stopper.graceful_shutdown(Some(std::time::Duration::from_secs(5)));
            });
            axum_server::bind_rustls(api.bind, tls)
                .handle(handle)
                .serve(router.into_make_service())
                .await
                .map_err(|e| format!("server error: {e}"))
        }
    }
}

fn read_password(stdin: bool) -> Result<String, String> {
    if stdin {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        return Ok(line.trim_end_matches(['\r', '\n']).to_owned());
    }
    let first = rpassword::prompt_password("Password (12 or more characters): ")
        .map_err(|e| e.to_string())?;
    let again = rpassword::prompt_password("Same password again: ").map_err(|e| e.to_string())?;
    if first != again {
        return Err("the passwords don't match".into());
    }
    Ok(first)
}

fn print_mfa(username: &str, secret: &str) {
    println!("Add this account to your authenticator app (any TOTP app works):");
    println!("  account: GnomeHome ({username})");
    println!("  secret:  {secret}");
    println!("  or the link: {}", auth::otpauth_uri(username, secret));
    println!("The secret is shown only now. Store it like a password.");
}

fn users(
    config_file: &std::path::Path,
    dev: bool,
    command: &[&str],
    role: Option<&str>,
    stdin: bool,
) -> Result<(), String> {
    let config = Config::load(config_file).map_err(|e| e.to_string())?;
    let mut conn = open(&config, dev)?;
    let now = Utc::now();
    let mut record = |action: &str, name: &str| {
        let _ = audit::append(
            &mut conn,
            "system:cli",
            action,
            Some(&format!("user:{name}")),
            Outcome::Success,
            None,
        );
    };
    match command {
        ["add", name] => {
            let role = role
                .and_then(Role::parse)
                .ok_or("give a role: --role viewer|analyst|admin")?;
            let password = read_password(stdin)?;
            let conn = open(&config, dev)?;
            let secret = auth::add_user(&conn, name, &password, role, now)?;
            drop(conn);
            record("user.add", name);
            println!("Created {name} ({}).", role.as_str());
            print_mfa(name, &secret);
        }
        ["list"] => {
            let conn = open(&config, dev)?;
            let mut stmt = conn
                .prepare(
                    "SELECT username, role, disabled, created_at FROM app_user ORDER BY username",
                )
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, String>(3)?,
                    ))
                })
                .map_err(|e| e.to_string())?;
            for row in rows {
                let (name, role, disabled, created) = row.map_err(|e| e.to_string())?;
                let state = if disabled == 1 { " (disabled)" } else { "" };
                println!("{name:<20} {role:<8} created {created}{state}");
            }
        }
        [
            action @ ("disable" | "enable" | "reset-mfa" | "password"),
            name,
        ] => {
            let conn = open(&config, dev)?;
            let changed = match *action {
                "disable" => conn.execute("UPDATE app_user SET disabled = 1 WHERE username = ?1", [name]),
                "enable" => conn.execute("UPDATE app_user SET disabled = 0, failed_logins = 0, locked_until = NULL WHERE username = ?1", [name]),
                "reset-mfa" => {
                    let secret = auth::new_totp_secret();
                    let n = conn.execute(
                        "UPDATE app_user SET totp_secret = ?1, last_totp_step = 0 WHERE username = ?2",
                        [&secret, *name],
                    );
                    if matches!(n, Ok(1)) {
                        print_mfa(name, &secret);
                    }
                    n
                }
                _ => {
                    let password = read_password(stdin)?;
                    auth::password_ok(&password)?;
                    conn.execute(
                        "UPDATE app_user SET password_hash = ?1 WHERE username = ?2",
                        [&auth::hash_password(&password), *name],
                    )
                }
            }
            .map_err(|e| e.to_string())?;
            if changed == 0 {
                return Err(format!("no user named {name:?}"));
            }
            // Any change to an account ends its sessions.
            conn.execute(
                "DELETE FROM app_session WHERE user_id = (SELECT id FROM app_user WHERE username = ?1)",
                [name],
            )
            .map_err(|e| e.to_string())?;
            drop(conn);
            record(&format!("user.{action}"), name);
            println!("Done: {action} {name}.");
        }
        _ => return Err(USAGE.to_owned()),
    }
    Ok(())
}
