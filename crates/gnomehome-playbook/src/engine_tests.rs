use std::cell::Cell;
use std::path::PathBuf;
use std::rc::Rc;

use chrono::{DateTime, Duration, Utc};
use gnomehome_core::protected::{Guard, ProtectedAssets};
use gnomehome_core::testkit::{migrated_db, repo_root};
use rusqlite::{Connection, params};

use super::*;
use crate::effects::{Effects, HelperOutcome};
use crate::playbook::load_dir;

#[derive(Default)]
struct Fake {
    calls: Vec<String>,
    helper_refuses: bool,
}

impl Effects for Fake {
    fn pihole_block(&mut self, domain: &str, _comment: &str) -> Result<(), String> {
        self.calls.push(format!("block {domain}"));
        Ok(())
    }
    fn pihole_unblock(&mut self, domain: &str) -> Result<(), String> {
        self.calls.push(format!("unblock {domain}"));
        Ok(())
    }
    fn helper(&mut self, args: &[String]) -> HelperOutcome {
        self.calls.push(format!("helper {}", args.join(" ")));
        if self.helper_refuses {
            HelperOutcome::Refused
        } else {
            HelperOutcome::Done("ok".into())
        }
    }
}

const T0: &str = "2026-10-11T12:00:00.000Z";

struct Setup {
    _dir: tempfile::TempDir,
    engine: Engine<Fake>,
    clock: Rc<Cell<DateTime<Utc>>>,
}

fn guard() -> Guard {
    Guard::new(
        ProtectedAssets::load(&repo_root().join("config/protected_assets.example.yaml")).unwrap(),
    )
}

fn setup(settings: Settings) -> Setup {
    let (dir, path) = migrated_db();
    let conn = gnomehome_core::db::open(&path).unwrap();
    conn.execute(
        "INSERT INTO asset (id, mac, first_seen, last_seen, last_ip) \
         VALUES (1, '00:00:5e:00:53:51', ?1, ?1, '192.0.2.51')",
        [T0],
    )
    .unwrap();
    let playbooks =
        load_dir(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../playbooks")).unwrap();
    let clock = Rc::new(Cell::new(gnomehome_core::time::parse_ts(T0).unwrap()));
    let tick = Rc::clone(&clock);
    let engine = Engine::new(conn, guard(), playbooks, settings, Fake::default())
        .with_clock(move || tick.get());
    Setup {
        _dir: dir,
        engine,
        clock,
    }
}

fn incident(
    conn: &Connection,
    detection: &str,
    confidence: f64,
    asset: Option<i64>,
    evidence: &str,
) -> i64 {
    conn.execute(
        "INSERT INTO incident (created_at, updated_at, asset_id, detection, severity, confidence, \
         title, summary, evidence) VALUES (?1, ?1, ?2, ?3, 'high', ?4, 't', 's', ?5)",
        params![T0, asset, detection, confidence, evidence],
    )
    .unwrap();
    conn.last_insert_rowid()
}

fn run_status(conn: &Connection) -> Vec<(String, String)> {
    let mut stmt = conn
        .prepare("SELECT playbook, status FROM playbook_run ORDER BY started_at, rowid")
        .unwrap();
    stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn one<T: rusqlite::types::FromSql>(conn: &Connection, sql: &str) -> T {
    conn.query_row(sql, [], |r| r.get(0)).unwrap()
}

fn live(actions: &[&str]) -> Settings {
    Settings {
        live: true,
        live_actions: actions.iter().map(|a| (*a).to_owned()).collect(),
        approval_minutes: 60,
        dev: false,
    }
}

const BAD: &str = r#"{"indicator": "malware-drop.test", "resolved": 2, "blocked": 0}"#;

#[test]
fn auto_act_in_dry_run_records_but_changes_nothing() {
    let mut s = setup(Settings::dry_run());
    let id = incident(&s.engine.conn, "dns.threat_intel", 0.9, Some(1), BAD);
    let report = s.engine.run_once().unwrap();
    assert_eq!((report.started, report.succeeded), (1, 1));
    assert!(s.engine.effects.calls.is_empty());
    let conn = &s.engine.conn;
    assert_eq!(
        run_status(conn),
        [("block-known-bad-domain".into(), "succeeded".into())]
    );
    let outcome: String = one(
        conn,
        &format!("SELECT outcome FROM incident WHERE id = {id}"),
    );
    assert!(
        outcome.starts_with("Dry run: would block \"malware-drop.test\""),
        "{outcome}"
    );
    assert_eq!(one::<i64>(conn, "SELECT dry_run FROM response_action"), 1);
    assert_eq!(
        one::<String>(conn, "SELECT kind FROM notification_outbox"),
        "action_taken"
    );
    let phases: Vec<String> = conn
        .prepare("SELECT phase FROM playbook_step ORDER BY seq")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(phases, ["detect", "enrich", "decide", "act", "report"]);
    assert!(gnomehome_core::audit::verify(conn).unwrap().ok());
    // A second pass doesn't run the same incident again.
    assert_eq!(s.engine.run_once().unwrap().started, 0);
}

#[test]
fn live_actions_must_be_listed_to_run_for_real() {
    let mut s = setup(live(&["router.quarantine"])); // live, but blocking isn't listed
    incident(&s.engine.conn, "dns.threat_intel", 0.9, Some(1), BAD);
    s.engine.run_once().unwrap();
    assert!(s.engine.effects.calls.is_empty());

    let mut s = setup(live(&["pihole.block_domain"]));
    incident(&s.engine.conn, "dns.threat_intel", 0.9, Some(1), BAD);
    s.engine.run_once().unwrap();
    assert_eq!(s.engine.effects.calls, ["block malware-drop.test"]);
    assert_eq!(
        one::<i64>(&s.engine.conn, "SELECT dry_run FROM response_action"),
        0
    );

    // When the block expires, it's lifted.
    s.clock.set(s.clock.get() + Duration::hours(169));
    assert_eq!(s.engine.run_once().unwrap().released, 1);
    assert_eq!(
        s.engine.effects.calls.last().unwrap(),
        "unblock malware-drop.test"
    );
}

#[test]
fn decide_skips_what_the_trigger_rules_out() {
    let mut s = setup(live(&["pihole.block_domain"]));
    let blocked = r#"{"indicator": "malware-drop.test", "resolved": 0, "blocked": 3}"#;
    incident(&s.engine.conn, "dns.threat_intel", 0.9, Some(1), blocked);
    incident(&s.engine.conn, "dns.threat_intel", 0.5, Some(1), BAD);
    let report = s.engine.run_once().unwrap();
    assert_eq!(report.skipped, 2);
    assert!(s.engine.effects.calls.is_empty());
    let outcomes: Vec<String> = s
        .engine
        .conn
        .prepare("SELECT outcome FROM incident ORDER BY id")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(
        outcomes[0]
            .contains("the incident's \"resolved\" is 0, and the playbook needs more than 0"),
        "{}",
        outcomes[0]
    );
    assert!(outcomes[1].contains("confidence 0.50 is below"));
}

#[test]
fn a_domain_naming_the_laptop_is_refused_and_audited_by_label() {
    let mut s = setup(live(&["pihole.block_domain"]));
    let evil = r#"{"indicator": "00-00-5e-00-53-01.lan.test", "resolved": 1}"#;
    incident(&s.engine.conn, "dns.threat_intel", 0.9, Some(1), evil);
    let report = s.engine.run_once().unwrap();
    assert_eq!(report.refused, 1);
    assert!(s.engine.effects.calls.is_empty());
    let conn = &s.engine.conn;
    let (target, details): (String, String) = conn
        .query_row(
            "SELECT target, details FROM audit_log WHERE action = 'guard.refused'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(target, "protected:Work laptop");
    assert!(!details.contains("53-01") && !details.contains("53:01"));
}

#[test]
fn quarantine_waits_for_approval_then_acts() {
    let mut s = setup(Settings::dry_run());
    let id = incident(&s.engine.conn, "dns.beaconing", 0.9, Some(1), "{}");
    let report = s.engine.run_once().unwrap();
    assert_eq!(report.awaiting_approval, 1);
    assert!(s.engine.effects.calls.is_empty());
    let conn = &s.engine.conn;
    assert_eq!(
        one::<String>(
            conn,
            &format!("SELECT status FROM incident WHERE id = {id}")
        ),
        "pending_approval"
    );
    assert_eq!(
        one::<String>(conn, "SELECT kind FROM notification_outbox"),
        "approval_needed"
    );
    let run_id: String = one(conn, "SELECT id FROM playbook_run");

    let report = s.engine.approve(&run_id, "user:owner").unwrap();
    assert_eq!(report.succeeded, 1);
    assert_eq!(
        s.engine.effects.calls,
        [format!(
            "helper quarantine --mac 00:00:5e:00:53:51 --block --run-id {run_id}"
        )]
    );
    let conn = &s.engine.conn;
    assert_eq!(run_status(conn)[0].1, "succeeded");
    assert_eq!(
        one::<String>(
            conn,
            &format!("SELECT status FROM incident WHERE id = {id}")
        ),
        "open"
    );
    assert_eq!(
        one::<String>(conn, "SELECT kind FROM response_action"),
        "router_quarantine"
    );
    assert!(s.engine.approve(&run_id, "user:owner").is_err()); // already decided
}

#[test]
fn denied_and_expired_requests_do_nothing() {
    let mut s = setup(Settings::dry_run());
    incident(&s.engine.conn, "dns.beaconing", 0.9, Some(1), "{}");
    incident(&s.engine.conn, "dns.dga", 0.9, Some(1), "{}");
    s.engine.run_once().unwrap();
    let runs: Vec<String> = s
        .engine
        .conn
        .prepare("SELECT id FROM playbook_run ORDER BY rowid")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(s.engine.deny(&runs[0], "user:owner").unwrap().denied, 1);
    s.clock.set(s.clock.get() + Duration::minutes(61));
    assert_eq!(s.engine.run_once().unwrap().expired, 1);
    assert!(s.engine.approve(&runs[1], "user:owner").is_err()); // too late
    assert!(s.engine.effects.calls.is_empty());
    let statuses: Vec<String> = run_status(&s.engine.conn)
        .into_iter()
        .map(|r| r.1)
        .collect();
    assert_eq!(statuses, ["denied", "expired"]);
}

#[test]
fn the_guard_is_checked_again_when_an_approval_arrives() {
    let mut s = setup(Settings::dry_run());
    incident(&s.engine.conn, "dns.beaconing", 0.9, Some(1), "{}");
    s.engine.run_once().unwrap();
    let run_id: String = one(&s.engine.conn, "SELECT id FROM playbook_run");
    // While the request waited, the owner added this device to the protected list.
    let list = "version: 1\nprotected:\n  - label: New work phone\n    reason: employer device\n    \
                macs: [\"00:00:5e:00:53:51\"]\n    ips: [\"192.0.2.51\"]\n";
    s.engine.guard = Guard::new(ProtectedAssets::parse(list).unwrap());
    let report = s.engine.approve(&run_id, "user:owner").unwrap();
    assert_eq!(report.refused, 1);
    assert!(s.engine.effects.calls.is_empty());
    let target: String = one(
        &s.engine.conn,
        "SELECT target FROM audit_log WHERE action = 'guard.refused'",
    );
    assert_eq!(target, "protected:New work phone");
}

#[test]
fn a_device_on_the_list_is_refused_before_any_request_is_made() {
    let mut s = setup(Settings::dry_run());
    // The list names this MAC, but the database hasn't been scrubbed yet.
    s.engine
        .conn
        .execute(
            "INSERT INTO asset (id, mac, first_seen, last_seen, last_ip) \
             VALUES (2, '00:00:5e:00:53:01', ?1, ?1, '192.0.2.77')",
            [T0],
        )
        .unwrap();
    incident(&s.engine.conn, "dns.dga", 0.9, Some(2), "{}");
    let report = s.engine.run_once().unwrap();
    assert_eq!((report.refused, report.awaiting_approval), (1, 0));
    assert_eq!(
        one::<i64>(&s.engine.conn, "SELECT COUNT(*) FROM approval"),
        0
    );
}

#[test]
fn the_python_guard_has_the_last_word() {
    let mut s = setup(Settings::dry_run());
    s.engine.effects.helper_refuses = true;
    incident(&s.engine.conn, "dns.beaconing", 0.9, Some(1), "{}");
    s.engine.run_once().unwrap();
    let run_id: String = one(&s.engine.conn, "SELECT id FROM playbook_run");
    assert_eq!(s.engine.approve(&run_id, "user:owner").unwrap().refused, 1);
    assert_eq!(
        one::<i64>(&s.engine.conn, "SELECT COUNT(*) FROM response_action"),
        0
    );
}

#[test]
fn incidents_without_a_device_cant_be_quarantined() {
    let mut s = setup(Settings::dry_run());
    incident(&s.engine.conn, "dns.dga", 0.9, None, "{}");
    assert_eq!(s.engine.run_once().unwrap().skipped, 1);
}

#[test]
fn the_weekly_playbook_runs_the_self_assessment() {
    let mut s = setup(Settings::dry_run());
    let report = s.engine.run_scheduled("weekly-self-assessment").unwrap();
    assert_eq!(report.succeeded, 1);
    assert_eq!(s.engine.effects.calls, ["helper self-assess"]);
    assert!(s.engine.run_scheduled("block-known-bad-domain").is_err());
}

#[test]
fn settings_default_to_dry_run() {
    let table: toml::Table =
        toml::from_str("mode = \"liv\"\nlive_actions = [\"pihole.block_domain\"]").unwrap();
    assert!(!Settings::from_table(&table, false).live);
    assert!(!Settings::from_table(&toml::Table::new(), false).live);
}

#[test]
fn ai_suggestions_always_ask_first_and_only_from_the_allow_list() {
    let mut s = setup(live(&["router.quarantine", "pihole.block_domain"]));
    let ok = r#"{"playbook": "quarantine-suspected-c2", "source": "ai.checkin"}"#;
    let not_allowed =
        r#"{"playbook": "block-known-bad-domain", "indicator": "x.test", "resolved": 1}"#;
    incident(&s.engine.conn, "ai.suggestion", 0.0, Some(1), ok); // no confidence: still asks
    incident(&s.engine.conn, "ai.suggestion", 0.0, Some(1), not_allowed);
    let report = s.engine.run_once().unwrap();
    assert_eq!((report.started, report.awaiting_approval), (1, 1));
    assert!(s.engine.effects.calls.is_empty()); // live mode, yet nothing acted
}
