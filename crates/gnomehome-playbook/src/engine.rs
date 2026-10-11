//! The playbook engine: incidents in, decisions and (maybe) actions out.
//!
//! For each new incident that a playbook's trigger names, the engine runs five
//! stages and records every one in `playbook_step` and the audit log:
//!
//! 1. **detect**: the incident that triggered it
//! 2. **enrich**: the device it's about, and the **protected-asset check**. A protected
//!    target stops the run here, refused and audited by label.
//! 3. **decide**: the trigger's conditions (confidence, evidence)
//! 4. **act**: `auto_act` acts now; `ask_first` asks the owner and waits; nothing acts
//!    for real unless `[response] mode = "live"` and the action is in `live_actions`
//! 5. **report**: a plain-English outcome on the incident, and a push (fixed text)
//!
//! Approved requests run on the next pass, and the guard is checked again first,
//! because the list may have changed while the request waited. Temporary actions
//! (blocks, quarantines) are released when they expire.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};

use chrono::{DateTime, Duration, Utc};
use gnomehome_core::audit::{self, Outcome};
use gnomehome_core::protected::{Guard, Match};
use gnomehome_core::time::format_ts;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};

use crate::Tier;
use crate::effects::{Effects, HelperOutcome, valid_domain};
use crate::playbook::{Action, Condition, Op, Param, Playbook};

const ACTOR: &str = "system:playbook";

/// What `[response]` in the config allows.
#[derive(Debug, Clone)]
pub struct Settings {
    pub live: bool,
    pub live_actions: Vec<String>,
    pub approval_minutes: i64,
    /// Pass `--dev` to the Python helper (synthetic data).
    pub dev: bool,
}

impl Settings {
    pub fn dry_run() -> Settings {
        Settings {
            live: false,
            live_actions: Vec::new(),
            approval_minutes: 60,
            dev: false,
        }
    }

    pub fn is_live(&self, action: &Action) -> bool {
        self.live && self.live_actions.iter().any(|a| a == action.name())
    }

    /// Reads `[response]`. Unknown values fall back to the safe choice (dry run).
    pub fn from_table(table: &toml::Table, dev: bool) -> Settings {
        let live = table.get("mode").and_then(|v| v.as_str()) == Some("live");
        let live_actions = table
            .get("live_actions")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let approval_minutes = table
            .get("approval_minutes")
            .and_then(|v| v.as_integer())
            .filter(|m| (5..=7 * 24 * 60).contains(m))
            .unwrap_or(60);
        Settings {
            live,
            live_actions,
            approval_minutes,
            dev,
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    pub started: usize,
    pub succeeded: usize,
    pub awaiting_approval: usize,
    pub skipped: usize,
    pub refused: usize,
    pub failed: usize,
    pub denied: usize,
    pub expired: usize,
    pub released: usize,
}

#[derive(Debug, Clone)]
struct Incident {
    id: i64,
    detection: String,
    confidence: Option<f64>,
    asset_id: Option<i64>,
    evidence: Value,
}

#[derive(Debug, Clone)]
struct Device {
    ip: Option<String>,
    mac: String,
}

/// Why a run stopped before acting.
enum Stop {
    /// A protected target: the label, the action, and what matched (never the identifier).
    Refused {
        label: String,
        action: &'static str,
        matched_on: String,
    },
    Skipped(String),
}

enum ActResult {
    Done(Vec<String>),
    Refused(String),
    Failed(String),
}

pub struct Engine<E: Effects> {
    pub conn: Connection,
    pub guard: Guard,
    pub playbooks: Vec<Playbook>,
    pub settings: Settings,
    pub effects: E,
    clock: Box<dyn Fn() -> DateTime<Utc>>,
}

impl<E: Effects> Engine<E> {
    pub fn new(
        conn: Connection,
        guard: Guard,
        playbooks: Vec<Playbook>,
        settings: Settings,
        effects: E,
    ) -> Engine<E> {
        Engine {
            conn,
            guard,
            playbooks,
            settings,
            effects,
            clock: Box::new(Utc::now),
        }
    }

    /// For tests: a fixed or moving clock.
    pub fn with_clock(mut self, clock: impl Fn() -> DateTime<Utc> + 'static) -> Engine<E> {
        self.clock = Box::new(clock);
        self
    }

    fn now(&self) -> DateTime<Utc> {
        (self.clock)()
    }

    /// One pass, as the 1-minute timer runs it: new incidents, decided or expired
    /// approvals, and temporary actions that have run their course.
    pub fn run_once(&mut self) -> rusqlite::Result<Report> {
        let mut report = Report::default();
        self.process_incidents(&mut report)?;
        self.process_approvals(&mut report)?;
        self.release_expired(&mut report)?;
        Ok(report)
    }

    // ------------------------------------------------------------------ incidents

    fn process_incidents(&mut self, report: &mut Report) -> rusqlite::Result<()> {
        let incidents: Vec<Incident> = {
            let mut stmt = self.conn.prepare(
                "SELECT id, detection, confidence, asset_id, evidence FROM incident \
                 WHERE status = 'open' AND playbook IS NULL ORDER BY id",
            )?;
            stmt.query_map([], |r| {
                Ok(Incident {
                    id: r.get(0)?,
                    detection: r.get(1)?,
                    confidence: r.get(2)?,
                    asset_id: r.get(3)?,
                    evidence: serde_json::from_str(&r.get::<_, String>(4)?).unwrap_or(Value::Null),
                })
            })?
            .collect::<Result<_, _>>()?
        };
        for incident in incidents {
            let Some(playbook) = self
                .playbooks
                .iter()
                .find(|p| p.tier != Tier::Scheduled && p.matches(&incident.detection))
                .cloned()
            else {
                continue;
            };
            report.started += 1;
            self.start_run(&playbook, &incident, report)?;
        }
        Ok(())
    }

    fn start_run(
        &mut self,
        playbook: &Playbook,
        incident: &Incident,
        report: &mut Report,
    ) -> rusqlite::Result<()> {
        let run_id = new_run_id();
        let dry_run = !playbook.actions.iter().any(|a| self.settings.is_live(a));
        let device = match incident.asset_id {
            Some(id) => self.device(id)?,
            None => None,
        };
        let protected_asset = match incident.asset_id {
            Some(id) => self.asset_is_protected(id)?,
            None => false,
        };
        // The schema refuses a run aimed at a protected asset, so record it without one.
        let asset_id = if protected_asset {
            None
        } else {
            incident.asset_id
        };
        self.conn.execute(
            "INSERT INTO playbook_run (id, playbook, version, incident_id, asset_id, tier, status, \
             dry_run, started_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'running', ?7, ?8)",
            params![
                run_id,
                playbook.name,
                playbook.version,
                incident.id,
                asset_id,
                tier_name(playbook.tier),
                dry_run,
                self.ts()
            ],
        )?;
        self.step(
            &run_id,
            "detect",
            None,
            "ok",
            json!({ "incident_id": incident.id, "detection": incident.detection }),
        )?;

        // enrich, including the protected-asset check
        let stop = if protected_asset {
            Some(Stop::Refused {
                label: "protected device".to_owned(),
                action: "playbook",
                matched_on: "asset".to_owned(),
            })
        } else {
            self.check_targets(playbook, incident, device.as_ref())
        };
        match stop {
            Some(Stop::Refused {
                label,
                action,
                matched_on,
            }) => {
                self.step(
                    &run_id,
                    "enrich",
                    Some(action),
                    "refused",
                    json!({ "protected": label }),
                )?;
                self.audit_refusal(action, &label, &matched_on)?;
                let outcome =
                    format!("Refused: the target is protected device '{label}'. Nothing was done.");
                self.finish(&run_id, incident.id, playbook, "refused", &outcome, None)?;
                report.refused += 1;
                return Ok(());
            }
            Some(Stop::Skipped(why)) => {
                self.step(&run_id, "enrich", None, "skipped", json!({ "reason": why }))?;
                let outcome = format!("Skipped: {why}.");
                self.finish(&run_id, incident.id, playbook, "skipped", &outcome, None)?;
                report.skipped += 1;
                return Ok(());
            }
            None => {
                let detail = match &device {
                    Some(d) => json!({ "device": d.ip, "has_mac": true }),
                    None => json!({ "device": null }),
                };
                self.step(&run_id, "enrich", None, "ok", detail)?;
            }
        }

        // decide
        if let Err(why) = decide(playbook, incident) {
            self.step(&run_id, "decide", None, "skipped", json!({ "reason": why }))?;
            let outcome = format!("Skipped: {why}.");
            self.finish(&run_id, incident.id, playbook, "skipped", &outcome, None)?;
            report.skipped += 1;
            return Ok(());
        }
        self.step(
            &run_id,
            "decide",
            None,
            "ok",
            json!({ "conditions": "met" }),
        )?;

        // act
        if playbook.tier == Tier::AskFirst {
            let expires = self.now() + Duration::minutes(self.settings.approval_minutes);
            self.conn.execute(
                "INSERT INTO approval (run_id, requested_at, expires_at) VALUES (?1, ?2, ?3)",
                params![run_id, self.ts(), format_ts(expires)],
            )?;
            let what = describe(&playbook.actions);
            self.step(
                &run_id,
                "act",
                None,
                "skipped",
                json!({ "awaiting_approval_until": format_ts(expires) }),
            )?;
            self.conn.execute(
                "UPDATE playbook_run SET status = 'awaiting_approval' WHERE id = ?1",
                [&run_id],
            )?;
            let outcome = format!(
                "Waiting for approval to {what}. Approve or deny with `just approve {run_id}` \
                 (or `just deny {run_id}`) before {}.",
                format_ts(expires)
            );
            self.update_incident(incident.id, playbook, &run_id, "pending_approval", &outcome)?;
            self.notify("approval_needed", Some(incident.id))?;
            report.awaiting_approval += 1;
            return Ok(());
        }
        self.act_and_report(&run_id, playbook, Some(incident), device.as_ref(), report)
    }

    /// Checks every target the playbook would touch. Returns why it must stop, if it must.
    fn check_targets(
        &mut self,
        playbook: &Playbook,
        incident: &Incident,
        device: Option<&Device>,
    ) -> Option<Stop> {
        for action in &playbook.actions {
            match action {
                Action::RouterQuarantine { .. } => {
                    let Some(device) = device else {
                        return Some(Stop::Skipped(
                            "the incident isn't tied to one device, so there's nothing to quarantine"
                                .to_owned(),
                        ));
                    };
                    if let Err(refusal) = self.guard.require_allowed(
                        action.name(),
                        device.ip.as_deref(),
                        Some(&device.mac),
                    ) {
                        return Some(Stop::Refused {
                            label: refusal.label,
                            action: action.name(),
                            matched_on: refusal.matched_on,
                        });
                    }
                }
                Action::PiholeBlock { domain, .. } => {
                    let Some(domain) = resolve(domain, &incident.evidence) else {
                        return Some(Stop::Skipped(
                            "the incident has no domain to block".to_owned(),
                        ));
                    };
                    if let Some(m) = self.guard.find_in_text(&domain) {
                        return Some(Stop::Refused {
                            label: m.label,
                            action: action.name(),
                            matched_on: m.matched_on,
                        });
                    }
                    if !valid_domain(&domain) {
                        return Some(Stop::Skipped(format!(
                            "{domain:?} isn't a domain Pi-hole can block"
                        )));
                    }
                }
                Action::SelfAssess => {}
            }
        }
        None
    }

    fn act_and_report(
        &mut self,
        run_id: &str,
        playbook: &Playbook,
        incident: Option<&Incident>,
        device: Option<&Device>,
        report: &mut Report,
    ) -> rusqlite::Result<()> {
        let incident_id = incident.map(|i| i.id);
        let result = self.execute(run_id, playbook, incident, device)?;
        let (status, outcome, kind) = match result {
            ActResult::Done(lines) => {
                report.succeeded += 1;
                let kind = playbook.notify_on_success.then_some("action_taken");
                ("succeeded", lines.join(" "), kind)
            }
            ActResult::Refused(label) => {
                report.refused += 1;
                (
                    "refused",
                    format!("Refused: the target is protected device '{label}'. Nothing was done."),
                    None,
                )
            }
            ActResult::Failed(why) => {
                report.failed += 1;
                (
                    "failed",
                    format!("The playbook failed: {why}"),
                    Some("action_failed"),
                )
            }
        };
        match incident_id {
            Some(id) => self.finish(run_id, id, playbook, status, &outcome, kind),
            None => self.finish_scheduled(run_id, status, &outcome),
        }
    }

    fn execute(
        &mut self,
        run_id: &str,
        playbook: &Playbook,
        incident: Option<&Incident>,
        device: Option<&Device>,
    ) -> rusqlite::Result<ActResult> {
        let mut lines = Vec::new();
        for action in &playbook.actions {
            let live = self.settings.is_live(action);
            match action {
                Action::PiholeBlock { domain, hours } => {
                    let evidence = incident.map_or(&Value::Null, |i| &i.evidence);
                    let Some(domain) = resolve(domain, evidence) else {
                        return Ok(ActResult::Failed("no domain to block".into()));
                    };
                    if let Some(m) = self.guard.find_in_text(&domain) {
                        self.refuse(run_id, action.name(), &m)?;
                        return Ok(ActResult::Refused(m.label));
                    }
                    if live {
                        let comment = format!("GnomeHome playbook {} run {run_id}", playbook.name);
                        if let Err(e) = self.effects.pihole_block(&domain, &comment) {
                            self.step(
                                run_id,
                                "act",
                                Some(action.name()),
                                "failed",
                                json!({ "error": e }),
                            )?;
                            return Ok(ActResult::Failed(e));
                        }
                    }
                    let expires = self.now() + Duration::hours(*hours);
                    self.record_action(run_id, "pihole_block", &domain, None, !live, expires)?;
                    self.step(
                        run_id,
                        "act",
                        Some(action.name()),
                        if live { "ok" } else { "dry_run" },
                        json!({ "domain": domain, "hours": hours }),
                    )?;
                    lines.push(if live {
                        format!(
                            "Blocked \"{domain}\" in Pi-hole for {hours} hours (until {}).",
                            format_ts(expires)
                        )
                    } else {
                        format!(
                            "Dry run: would block \"{domain}\" in Pi-hole for {hours} hours. \
                             Nothing was changed."
                        )
                    });
                }
                Action::RouterQuarantine { hours } => {
                    let Some(device) = device else {
                        return Ok(ActResult::Failed("no device to quarantine".into()));
                    };
                    // Check again right before acting: the list may have changed.
                    if let Some(m) = self
                        .guard
                        .assets
                        .match_target(device.ip.as_deref(), Some(&device.mac))
                    {
                        self.refuse(run_id, action.name(), &m)?;
                        return Ok(ActResult::Refused(m.label));
                    }
                    let mut args = vec![
                        "quarantine".to_owned(),
                        "--mac".to_owned(),
                        device.mac.clone(),
                        "--block".to_owned(),
                        "--run-id".to_owned(),
                        run_id.to_owned(),
                    ];
                    if live {
                        args.push("--live".to_owned());
                    }
                    if self.settings.dev {
                        args.push("--dev".to_owned());
                    }
                    match self.effects.helper(&args) {
                        HelperOutcome::Done(_) => {}
                        HelperOutcome::Refused => {
                            let label = "protected device (refused by the Python guard)";
                            self.step(run_id, "act", Some(action.name()), "refused", json!({}))?;
                            return Ok(ActResult::Refused(label.to_owned()));
                        }
                        HelperOutcome::Failed(e) => {
                            self.step(
                                run_id,
                                "act",
                                Some(action.name()),
                                "failed",
                                json!({ "error": e }),
                            )?;
                            return Ok(ActResult::Failed(e));
                        }
                    }
                    let expires = self.now() + Duration::hours(*hours);
                    let asset_id = incident.and_then(|i| i.asset_id);
                    self.record_action(
                        run_id,
                        "router_quarantine",
                        &device.mac,
                        asset_id,
                        !live,
                        expires,
                    )?;
                    self.step(
                        run_id,
                        "act",
                        Some(action.name()),
                        if live { "ok" } else { "dry_run" },
                        json!({ "device": device.ip, "hours": hours }),
                    )?;
                    let who = device.ip.as_deref().unwrap_or("the device");
                    lines.push(if live {
                        format!(
                            "Quarantined {who} at the router for {hours} hours (until {}).",
                            format_ts(expires)
                        )
                    } else {
                        format!(
                            "Dry run: would quarantine {who} at the router for {hours} hours. \
                             Nothing was changed."
                        )
                    });
                }
                Action::SelfAssess => {
                    let mut args = vec!["self-assess".to_owned()];
                    if self.settings.dev {
                        args.push("--dev".to_owned());
                    }
                    match self.effects.helper(&args) {
                        HelperOutcome::Done(out) => {
                            self.step(
                                run_id,
                                "act",
                                Some(action.name()),
                                "ok",
                                json!({ "output": out }),
                            )?;
                            lines.push(format!("Self-assessment done. {out}"));
                        }
                        HelperOutcome::Refused | HelperOutcome::Failed(_) => {
                            let e = "the self-assessment helper failed".to_owned();
                            self.step(
                                run_id,
                                "act",
                                Some(action.name()),
                                "failed",
                                json!({ "error": e }),
                            )?;
                            return Ok(ActResult::Failed(e));
                        }
                    }
                }
            }
        }
        Ok(ActResult::Done(lines))
    }

    // ------------------------------------------------------------------ approvals

    /// Approves a waiting run and carries it out right away.
    pub fn approve(&mut self, run_id: &str, by: &str) -> Result<Report, String> {
        self.decide_approval(run_id, by, "approved")?;
        let mut report = Report::default();
        self.process_approvals(&mut report)
            .map_err(|e| e.to_string())?;
        Ok(report)
    }

    pub fn deny(&mut self, run_id: &str, by: &str) -> Result<Report, String> {
        self.decide_approval(run_id, by, "denied")?;
        let mut report = Report::default();
        self.process_approvals(&mut report)
            .map_err(|e| e.to_string())?;
        Ok(report)
    }

    fn decide_approval(&mut self, run_id: &str, by: &str, decision: &str) -> Result<(), String> {
        let now = self.ts();
        let changed = self
            .conn
            .execute(
                "UPDATE approval SET decision = ?1, decided_at = ?2, decided_by = ?3 \
                 WHERE run_id = ?4 AND decision IS NULL AND expires_at > ?2",
                params![decision, now, by, run_id],
            )
            .map_err(|e| e.to_string())?;
        if changed == 0 {
            return Err(format!(
                "no open approval request for run {run_id} (it may have expired or been decided)"
            ));
        }
        audit::append(
            &mut self.conn,
            by,
            &format!(
                "playbook.{}",
                if decision == "approved" {
                    "approve"
                } else {
                    "deny"
                }
            ),
            Some(&format!("run:{run_id}")),
            Outcome::Success,
            None,
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn process_approvals(&mut self, report: &mut Report) -> rusqlite::Result<()> {
        let now = self.ts();
        // Unanswered requests expire, and nothing happens.
        let expired: Vec<(String, Option<i64>)> = {
            let mut stmt = self.conn.prepare(
                "SELECT a.run_id, r.incident_id FROM approval a JOIN playbook_run r ON r.id = a.run_id \
                 WHERE a.decision IS NULL AND a.expires_at <= ?1",
            )?;
            stmt.query_map([&now], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<_, _>>()?
        };
        for (run_id, incident_id) in expired {
            self.conn.execute(
                "UPDATE approval SET decision = 'expired', decided_at = ?1 WHERE run_id = ?2",
                params![now, run_id],
            )?;
            self.conn.execute(
                "UPDATE playbook_run SET status = 'expired', finished_at = ?1, outcome = ?2 WHERE id = ?3",
                params![now, "The approval request expired. Nothing was done.", run_id],
            )?;
            if let Some(id) = incident_id {
                self.set_incident_outcome(
                    id,
                    "open",
                    "The approval request expired. Nothing was done.",
                )?;
            }
            self.audit(
                "playbook.expired",
                &format!("run:{run_id}"),
                Outcome::Success,
                json!({}),
            )?;
            report.expired += 1;
        }

        let decided: Vec<(String, String, String)> = {
            let mut stmt = self.conn.prepare(
                "SELECT a.run_id, a.decision, COALESCE(a.decided_by, '') FROM approval a \
                 JOIN playbook_run r ON r.id = a.run_id \
                 WHERE a.decision IN ('approved', 'denied') AND r.status = 'awaiting_approval'",
            )?;
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<Result<_, _>>()?
        };
        for (run_id, decision, by) in decided {
            let (name, incident_id): (String, Option<i64>) = self.conn.query_row(
                "SELECT playbook, incident_id FROM playbook_run WHERE id = ?1",
                [&run_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let Some(playbook) = self.playbooks.iter().find(|p| p.name == name).cloned() else {
                self.finish_scheduled(
                    &run_id,
                    "failed",
                    &format!("Playbook {name} no longer exists."),
                )?;
                report.failed += 1;
                continue;
            };
            if decision == "denied" {
                let outcome = format!("Denied by {by}. Nothing was done.");
                self.conn.execute(
                    "UPDATE playbook_run SET status = 'denied', finished_at = ?1, outcome = ?2 WHERE id = ?3",
                    params![self.ts(), outcome, run_id],
                )?;
                if let Some(id) = incident_id {
                    self.set_incident_outcome(id, "open", &outcome)?;
                }
                report.denied += 1;
                continue;
            }
            self.conn.execute(
                "UPDATE playbook_run SET status = 'approved' WHERE id = ?1",
                [&run_id],
            )?;
            let incident = match incident_id {
                Some(id) => self.incident(id)?,
                None => None,
            };
            let device = match incident.as_ref().and_then(|i| i.asset_id) {
                Some(id) => self.device(id)?,
                None => None,
            };
            // The list may have changed while the request waited: check again.
            if let Some(incident) = &incident {
                if let Some(stop) = self.check_targets(&playbook, incident, device.as_ref()) {
                    let (status, outcome) = match stop {
                        Stop::Refused {
                            label,
                            action,
                            matched_on,
                        } => {
                            self.audit_refusal(action, &label, &matched_on)?;
                            report.refused += 1;
                            (
                                "refused",
                                format!(
                                    "Refused: the target is protected device '{label}'. Nothing was done."
                                ),
                            )
                        }
                        Stop::Skipped(why) => {
                            report.skipped += 1;
                            ("skipped", format!("Skipped: {why}."))
                        }
                    };
                    self.finish(&run_id, incident.id, &playbook, status, &outcome, None)?;
                    continue;
                }
            }
            self.act_and_report(
                &run_id,
                &playbook,
                incident.as_ref(),
                device.as_ref(),
                report,
            )?;
        }
        Ok(())
    }

    // ------------------------------------------------------------------ releases

    fn release_expired(&mut self, report: &mut Report) -> rusqlite::Result<()> {
        let due: Vec<(i64, String, String, String, bool)> = {
            let mut stmt = self.conn.prepare(
                "SELECT id, run_id, kind, target, dry_run FROM response_action \
                 WHERE released_at IS NULL AND expires_at <= ?1",
            )?;
            stmt.query_map([self.ts()], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .collect::<Result<_, _>>()?
        };
        for (id, run_id, kind, target, dry_run) in due {
            let result = if dry_run {
                Ok(())
            } else if kind == "pihole_block" {
                self.effects.pihole_unblock(&target)
            } else {
                let mut args = vec![
                    "quarantine".to_owned(),
                    "--mac".to_owned(),
                    target.clone(),
                    "--release".to_owned(),
                    "--run-id".to_owned(),
                    run_id.clone(),
                    "--live".to_owned(),
                ];
                if self.settings.dev {
                    args.push("--dev".to_owned());
                }
                match self.effects.helper(&args) {
                    HelperOutcome::Done(_) => Ok(()),
                    HelperOutcome::Refused => Err("refused by the Python guard".to_owned()),
                    HelperOutcome::Failed(e) => Err(e),
                }
            };
            let action = if kind == "pihole_block" {
                "pihole.unblock_domain"
            } else {
                "router.release"
            };
            match result {
                Ok(()) => {
                    self.conn.execute(
                        "UPDATE response_action SET released_at = ?1 WHERE id = ?2",
                        params![self.ts(), id],
                    )?;
                    let status = if dry_run { "dry_run" } else { "ok" };
                    self.step(
                        &run_id,
                        "release",
                        Some(action),
                        status,
                        json!({ "action_id": id }),
                    )?;
                    report.released += 1;
                }
                Err(e) => {
                    // Left in place: the next pass tries again.
                    self.step(
                        &run_id,
                        "release",
                        Some(action),
                        "failed",
                        json!({ "error": e }),
                    )?;
                    report.failed += 1;
                }
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------ scheduled

    /// Runs a scheduled playbook (the weekly self-assessment).
    pub fn run_scheduled(&mut self, name: &str) -> Result<Report, String> {
        let playbook = self
            .playbooks
            .iter()
            .find(|p| p.name == name && p.tier == Tier::Scheduled)
            .cloned()
            .ok_or_else(|| format!("no scheduled playbook named {name:?}"))?;
        let run_id = new_run_id();
        let mut report = Report {
            started: 1,
            ..Report::default()
        };
        let result = (|| -> rusqlite::Result<()> {
            self.conn.execute(
                "INSERT INTO playbook_run (id, playbook, version, tier, status, dry_run, started_at) \
                 VALUES (?1, ?2, ?3, 'scheduled', 'running', 0, ?4)",
                params![run_id, playbook.name, playbook.version, self.ts()],
            )?;
            self.step(&run_id, "detect", None, "ok", json!({ "schedule": name }))?;
            self.act_and_report(&run_id, &playbook, None, None, &mut report)
        })();
        result.map_err(|e| e.to_string())?;
        Ok(report)
    }

    // ------------------------------------------------------------------ helpers

    fn ts(&self) -> String {
        format_ts(self.now())
    }

    fn device(&self, asset_id: i64) -> rusqlite::Result<Option<Device>> {
        self.conn
            .query_row(
                "SELECT last_ip, mac FROM asset WHERE id = ?1",
                [asset_id],
                |r| {
                    Ok(Device {
                        ip: r.get(0)?,
                        mac: r.get(1)?,
                    })
                },
            )
            .optional()
    }

    fn asset_is_protected(&self, asset_id: i64) -> rusqlite::Result<bool> {
        Ok(self
            .conn
            .query_row(
                "SELECT protected FROM asset WHERE id = ?1",
                [asset_id],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            == Some(1))
    }

    fn incident(&self, id: i64) -> rusqlite::Result<Option<Incident>> {
        self.conn
            .query_row(
                "SELECT id, detection, confidence, asset_id, evidence FROM incident WHERE id = ?1",
                [id],
                |r| {
                    Ok(Incident {
                        id: r.get(0)?,
                        detection: r.get(1)?,
                        confidence: r.get(2)?,
                        asset_id: r.get(3)?,
                        evidence: serde_json::from_str(&r.get::<_, String>(4)?)
                            .unwrap_or(Value::Null),
                    })
                },
            )
            .optional()
    }

    fn step(
        &mut self,
        run_id: &str,
        phase: &str,
        action: Option<&str>,
        status: &str,
        detail: Value,
    ) -> rusqlite::Result<()> {
        let seq: i64 = self.conn.query_row(
            "SELECT COALESCE(MAX(seq), 0) + 1 FROM playbook_step WHERE run_id = ?1",
            [run_id],
            |r| r.get(0),
        )?;
        self.conn.execute(
            "INSERT INTO playbook_step (run_id, seq, phase, action, status, detail, at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                run_id,
                seq,
                phase,
                action,
                status,
                detail.to_string(),
                self.ts()
            ],
        )?;
        let outcome = match status {
            "refused" => Outcome::Refused,
            "failed" => Outcome::Failure,
            _ => Outcome::Success,
        };
        let mut details = json!({ "run_id": run_id, "status": status });
        if let Some(a) = action {
            details["action"] = json!(a);
        }
        self.audit(
            &format!("playbook.{phase}"),
            &format!("run:{run_id}"),
            outcome,
            details,
        )
    }

    fn refuse(&mut self, run_id: &str, action: &str, m: &Match) -> rusqlite::Result<()> {
        self.step(
            run_id,
            "act",
            Some(action),
            "refused",
            json!({ "protected": m.label }),
        )?;
        self.audit_refusal(action, &m.label, &m.matched_on)
    }

    /// The guard's refusal, by label only (docs/audit-log.md).
    fn audit_refusal(
        &mut self,
        action: &str,
        label: &str,
        matched_on: &str,
    ) -> rusqlite::Result<()> {
        audit::append(
            &mut self.conn,
            ACTOR,
            "guard.refused",
            Some(&audit::protected_target(label)),
            Outcome::Refused,
            Some(&json!({ "attempted_action": action, "matched_on": matched_on })),
        )?;
        Ok(())
    }

    fn audit(
        &mut self,
        action: &str,
        target: &str,
        outcome: Outcome,
        details: Value,
    ) -> rusqlite::Result<()> {
        audit::append(
            &mut self.conn,
            ACTOR,
            action,
            Some(target),
            outcome,
            Some(&details),
        )?;
        Ok(())
    }

    fn record_action(
        &mut self,
        run_id: &str,
        kind: &str,
        target: &str,
        asset_id: Option<i64>,
        dry_run: bool,
        expires: DateTime<Utc>,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO response_action (run_id, kind, target, asset_id, dry_run, started_at, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![run_id, kind, target, asset_id, dry_run, self.ts(), format_ts(expires)],
        )?;
        Ok(())
    }

    fn notify(&mut self, kind: &str, incident_id: Option<i64>) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO notification_outbox (kind, incident_id, created_at) VALUES (?1, ?2, ?3)",
            params![kind, incident_id, self.ts()],
        )?;
        Ok(())
    }

    fn update_incident(
        &mut self,
        incident_id: i64,
        playbook: &Playbook,
        run_id: &str,
        status: &str,
        outcome: &str,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE incident SET playbook = ?1, playbook_run_id = ?2, tier = ?3, status = ?4, \
             outcome = ?5, updated_at = ?6 WHERE id = ?7",
            params![
                playbook.name,
                run_id,
                tier_name(playbook.tier),
                status,
                outcome,
                self.ts(),
                incident_id
            ],
        )?;
        Ok(())
    }

    fn set_incident_outcome(
        &mut self,
        incident_id: i64,
        status: &str,
        outcome: &str,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE incident SET status = ?1, outcome = ?2, updated_at = ?3 WHERE id = ?4",
            params![status, outcome, self.ts(), incident_id],
        )?;
        Ok(())
    }

    fn finish(
        &mut self,
        run_id: &str,
        incident_id: i64,
        playbook: &Playbook,
        status: &str,
        outcome: &str,
        notify: Option<&str>,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE playbook_run SET status = ?1, finished_at = ?2, outcome = ?3 WHERE id = ?4",
            params![status, self.ts(), outcome, run_id],
        )?;
        self.update_incident(incident_id, playbook, run_id, "open", outcome)?;
        self.step(run_id, "report", None, "ok", json!({ "status": status }))?;
        if let Some(kind) = notify {
            self.notify(kind, Some(incident_id))?;
        }
        Ok(())
    }

    fn finish_scheduled(
        &mut self,
        run_id: &str,
        status: &str,
        outcome: &str,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE playbook_run SET status = ?1, finished_at = ?2, outcome = ?3 WHERE id = ?4",
            params![status, self.ts(), outcome, run_id],
        )?;
        self.step(run_id, "report", None, "ok", json!({ "status": status }))
    }
}

/// The trigger's conditions, checked in the decide stage.
fn decide(playbook: &Playbook, incident: &Incident) -> Result<(), String> {
    let Some(trigger) = &playbook.trigger else {
        return Ok(());
    };
    if let Some(min) = trigger.min_confidence {
        let confidence = incident.confidence.unwrap_or(0.0);
        if confidence < min {
            return Err(format!(
                "confidence {confidence:.2} is below the playbook's {min:.2}"
            ));
        }
    }
    for condition in &trigger.evidence {
        if !holds(condition, &incident.evidence[&condition.key]) {
            return Err(format!(
                "evidence {} doesn't meet {:?} {}",
                condition.key, condition.op, condition.value
            ));
        }
    }
    Ok(())
}

fn holds(c: &Condition, actual: &Value) -> bool {
    let cmp = |f: fn(f64, f64) -> bool| match (actual.as_f64(), c.value.as_f64()) {
        (Some(a), Some(b)) => f(a, b),
        _ => false,
    };
    match c.op {
        Op::Eq => actual == &c.value,
        Op::Ne => actual != &c.value,
        Op::Gt => cmp(|a, b| a > b),
        Op::Gte => cmp(|a, b| a >= b),
        Op::Lt => cmp(|a, b| a < b),
        Op::Lte => cmp(|a, b| a <= b),
        Op::In => c
            .value
            .as_array()
            .is_some_and(|items| items.contains(actual)),
    }
}

/// A parameter's value. Evidence values are device-influenced text: they're checked
/// (domain syntax, guard) before use and never reach a shell.
fn resolve(param: &Param, evidence: &Value) -> Option<String> {
    match param {
        Param::Literal(s) => Some(s.clone()),
        Param::Evidence(key) => evidence[key.as_str()]
            .as_str()
            .map(|s| s.trim().trim_end_matches('.').to_ascii_lowercase()),
    }
}

fn describe(actions: &[Action]) -> String {
    actions
        .iter()
        .map(|a| match a {
            Action::PiholeBlock { hours, .. } => {
                format!("block the domain in Pi-hole for {hours} hours")
            }
            Action::RouterQuarantine { hours } => {
                format!("quarantine the device at the router for {hours} hours")
            }
            Action::SelfAssess => "run the self-assessment".to_owned(),
        })
        .collect::<Vec<_>>()
        .join(" and ")
}

fn tier_name(tier: Tier) -> &'static str {
    match tier {
        Tier::AutoAct => "auto_act",
        Tier::AskFirst => "ask_first",
        Tier::Scheduled => "scheduled",
    }
}

/// A random 16-hex-digit run ID. Process-random hashing is enough: IDs need to be
/// unique, not secret.
fn new_run_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
    hasher.write_i64(Utc::now().timestamp_nanos_opt().unwrap_or_default());
    format!("{:016x}", hasher.finish())
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
