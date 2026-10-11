//! `gnomehome-playbook`: run the automated Blue Team.
//!
//! ```text
//! gnomehome-playbook run                     new incidents, approvals, expiries (1-minute timer)
//! gnomehome-playbook run-scheduled <name>    a scheduled playbook (weekly timer)
//! gnomehome-playbook approvals               requests waiting for the owner
//! gnomehome-playbook approve <run> [--by n]  approve, and act right away
//! gnomehome-playbook deny <run> [--by n]
//! gnomehome-playbook actions                 temporary blocks and quarantines
//! gnomehome-playbook validate [dir]          check the playbook files
//! ```
//!
//! Global options: `--config PATH`, `--dev` (the synthetic-data database).
//! Output names devices by address and protected devices by label only.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use gnomehome_core::config::{Config, config_path};
use gnomehome_core::db;
use gnomehome_core::protected::{Guard, ProtectedAssets};
use gnomehome_playbook::effects::{PiholeClient, RealEffects};
use gnomehome_playbook::engine::{Engine, Report, Settings};
use gnomehome_playbook::playbook::load_dir;

const USAGE: &str = "usage: gnomehome-playbook [--config PATH] [--dev] \
    <run | run-scheduled NAME | approvals | approve RUN [--by NAME] | deny RUN [--by NAME] | actions | validate [DIR]>";

fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut config = config_path();
    let mut dev = false;
    let mut by = "user:local".to_owned();
    let mut rest = Vec::new();
    while !args.is_empty() {
        let arg = args.remove(0);
        match arg.as_str() {
            "--config" if !args.is_empty() => config = PathBuf::from(args.remove(0)),
            "--by" if !args.is_empty() => by = format!("user:{}", args.remove(0)),
            "--dev" => dev = true,
            "-h" | "--help" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            _ => rest.push(arg),
        }
    }
    match run(&config, dev, &by, &rest) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("gnomehome-playbook: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn run(config_file: &std::path::Path, dev: bool, by: &str, args: &[String]) -> Result<(), String> {
    let command: Vec<&str> = args.iter().map(String::as_str).collect();
    // `validate <dir>` checks files only, so it works before any config exists.
    if let ["validate", dir] = command.as_slice() {
        return validate(&PathBuf::from(dir));
    }
    let config = Config::load(config_file).map_err(|e| e.to_string())?;
    let playbooks_dir = config
        .playbooks_dir
        .clone()
        .ok_or("playbooks_dir isn't set for this platform")?;
    if let ["validate"] = command.as_slice() {
        return validate(&playbooks_dir);
    }

    let playbooks = load_dir(&playbooks_dir).map_err(|e| e.to_string())?;
    // Fail closed: no valid protected list, no engine.
    let guard =
        Guard::new(ProtectedAssets::load(&config.protected_assets).map_err(|e| e.to_string())?);
    let db_path = config.database(dev);
    let conn = db::open(db_path).map_err(|e| format!("{}: {e}", db_path.display()))?;
    db::require_schema(&conn, 6).map_err(|e| e.to_string())?;
    let settings = Settings::from_table(&config.response, dev);
    let pihole_api = config
        .response
        .get("pihole_api")
        .and_then(|v| v.as_str())
        .unwrap_or("http://127.0.0.1/api")
        .to_owned();
    let pihole = match &config.pihole_password_file {
        Some(file) if settings.live => Some(PiholeClient::new(&pihole_api, file)?),
        _ => None,
    };
    let effects = RealEffects {
        pihole,
        cli: config.gnomehome_cli.clone(),
        config_path: config.path.clone(),
        timeout: Duration::from_secs(120),
    };
    let mode = if settings.live { "live" } else { "dry run" };
    let mut engine = Engine::new(conn, guard, playbooks, settings, effects);

    match command.as_slice() {
        ["run"] => {
            let report = engine.run_once().map_err(|e| e.to_string())?;
            print_report(&report, mode);
        }
        ["run-scheduled", name] => {
            let report = engine.run_scheduled(name)?;
            print_report(&report, mode);
        }
        ["approve", run_id] => {
            let report = engine.approve(run_id, by)?;
            println!("Approved run {run_id}.");
            print_report(&report, mode);
        }
        ["deny", run_id] => {
            engine.deny(run_id, by)?;
            println!("Denied run {run_id}. Nothing was done.");
        }
        ["approvals"] => {
            let mut stmt = engine
                .conn
                .prepare(
                    "SELECT a.run_id, r.playbook, a.expires_at, COALESCE(i.title, ''), \
                     COALESCE(i.outcome, '') FROM approval a JOIN playbook_run r ON r.id = a.run_id \
                     LEFT JOIN incident i ON i.id = r.incident_id \
                     WHERE a.decision IS NULL AND a.expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
                     ORDER BY a.requested_at",
                )
                .map_err(|e| e.to_string())?;
            let rows: Vec<(String, String, String, String, String)> = stmt
                .query_map([], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                })
                .map_err(|e| e.to_string())?
                .collect::<Result<_, _>>()
                .map_err(|e| e.to_string())?;
            if rows.is_empty() {
                println!("No approvals waiting.");
            }
            for (run_id, playbook, expires, title, outcome) in rows {
                println!("{run_id}  {playbook}  (expires {expires})\n    {title}\n    {outcome}");
            }
        }
        ["actions"] => {
            let mut stmt = engine
                .conn
                .prepare(
                    "SELECT kind, target, dry_run, expires_at, released_at FROM response_action \
                     ORDER BY started_at DESC LIMIT 50",
                )
                .map_err(|e| e.to_string())?;
            let rows: Vec<(String, String, bool, String, Option<String>)> = stmt
                .query_map([], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                })
                .map_err(|e| e.to_string())?
                .collect::<Result<_, _>>()
                .map_err(|e| e.to_string())?;
            if rows.is_empty() {
                println!("No response actions yet.");
            }
            for (kind, target, dry_run, expires, released) in rows {
                let state = match released {
                    Some(at) => format!("released {at}"),
                    None => format!("until {expires}"),
                };
                let dry = if dry_run { " (dry run)" } else { "" };
                println!("{kind:<18} {target:<30} {state}{dry}");
            }
        }
        _ => return Err(USAGE.to_owned()),
    }
    Ok(())
}

fn validate(dir: &std::path::Path) -> Result<(), String> {
    for p in load_dir(dir).map_err(|e| e.to_string())? {
        let mitre = [p.mitre_technique.as_deref(), p.mitre_mitigation.as_deref()]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(", ");
        println!("ok  {:<28} {:?}  MITRE {mitre}", p.name, p.tier);
    }
    Ok(())
}

fn print_report(r: &Report, mode: &str) {
    println!(
        "Playbooks ({mode}): {} started, {} done, {} waiting for approval, {} skipped, \
         {} refused (protected), {} failed, {} denied, {} expired, {} released.",
        r.started,
        r.succeeded,
        r.awaiting_approval,
        r.skipped,
        r.refused,
        r.failed,
        r.denied,
        r.expired,
        r.released
    );
}
