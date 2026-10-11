//! Playbook files: YAML in `playbooks/`, mapped to MITRE ATT&CK (NFR-13).
//!
//! ```yaml
//! name: block-known-bad-domain
//! version: 1
//! description: Block a threat-list domain in Pi-hole after a device resolved it.
//! tier: auto_act                 # auto_act, ask_first, or scheduled
//! mitre: { technique: T1071.004, mitigation: M1021 }
//! trigger:
//!   detection: dns.threat_intel  # or a list
//!   min_confidence: 0.8
//!   evidence:
//!     resolved: { gt: 0 }        # eq, ne, gt, gte, lt, lte, in
//! act:
//!   - action: pihole.block_domain
//!     domain: "{evidence.indicator}"
//!     hours: 168
//! report:
//!   notify: action_taken         # or none
//! ```
//!
//! Loading is strict, like the protected-asset list: unknown keys, duplicate keys,
//! unknown actions, and missing MITRE mappings are all errors. The rules that keep
//! automation safe are enforced here, not left to each file:
//!
//! - `router.quarantine` is disruptive, so it's only allowed in `ask_first` (R-03).
//! - A parameter is either a literal or one whole `{evidence.<key>}` reference, never
//!   text glued around incident data.

use std::fmt;
use std::path::Path;

use gnomehome_core::protected::reject_duplicate_keys;
use serde_json::Value;
use yaml_rust2::{Yaml, YamlLoader};

use crate::Tier;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaybookError(pub String);

impl fmt::Display for PlaybookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PlaybookError {}

#[derive(Debug, Clone, PartialEq)]
pub struct Playbook {
    pub name: String,
    pub version: i64,
    pub description: String,
    pub tier: Tier,
    pub mitre_technique: Option<String>,
    pub mitre_mitigation: Option<String>,
    pub trigger: Option<Trigger>,
    pub actions: Vec<Action>,
    pub notify_on_success: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Trigger {
    pub detections: Vec<String>,
    pub min_confidence: Option<f64>,
    pub evidence: Vec<Condition>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Condition {
    pub key: String,
    pub op: Op,
    pub value: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    Gt,
    Gte,
    Lt,
    Lte,
    In,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Param {
    Literal(String),
    /// A whole `{evidence.<key>}` reference.
    Evidence(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    PiholeBlock { domain: Param, hours: i64 },
    RouterQuarantine { hours: i64 },
    SelfAssess,
}

impl Action {
    /// The name used in YAML and in `[response] live_actions`.
    pub fn name(&self) -> &'static str {
        match self {
            Action::PiholeBlock { .. } => "pihole.block_domain",
            Action::RouterQuarantine { .. } => "router.quarantine",
            Action::SelfAssess => "python.self_assess",
        }
    }

    /// Whether the action changes anything on the network (and so obeys dry run).
    pub fn has_effect(&self) -> bool {
        !matches!(self, Action::SelfAssess)
    }
}

impl Playbook {
    pub fn matches(&self, detection: &str) -> bool {
        self.trigger
            .as_ref()
            .is_some_and(|t| t.detections.iter().any(|d| d == detection))
    }
}

/// Every `*.yaml` playbook in a folder, sorted by file name. Names must be unique.
pub fn load_dir(dir: &Path) -> Result<Vec<Playbook>, PlaybookError> {
    let entries = std::fs::read_dir(dir).map_err(|e| {
        PlaybookError(format!(
            "cannot read playbooks folder {}: {e}",
            dir.display()
        ))
    })?;
    let mut paths: Vec<_> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "yaml" || x == "yml"))
        .collect();
    paths.sort();
    let mut out: Vec<Playbook> = Vec::new();
    for path in paths {
        let text = std::fs::read_to_string(&path)
            .map_err(|e| PlaybookError(format!("{}: {e}", path.display())))?;
        let playbook =
            parse(&text).map_err(|e| PlaybookError(format!("{}: {}", path.display(), e.0)))?;
        if out.iter().any(|p| p.name == playbook.name) {
            return Err(PlaybookError(format!(
                "{}: duplicate playbook name {:?}",
                path.display(),
                playbook.name
            )));
        }
        out.push(playbook);
    }
    Ok(out)
}

pub fn parse(text: &str) -> Result<Playbook, PlaybookError> {
    let err = |m: &str| PlaybookError(m.to_owned());
    reject_duplicate_keys(text).map_err(|e| PlaybookError(e.0))?;
    let docs = YamlLoader::load_from_str(text).map_err(|e| err(&format!("invalid YAML: {e}")))?;
    let doc = docs
        .first()
        .filter(|d| d.as_hash().is_some())
        .ok_or_else(|| err("a playbook is a YAML mapping"))?;
    only_keys(
        doc,
        &[
            "name",
            "version",
            "description",
            "tier",
            "mitre",
            "trigger",
            "act",
            "report",
        ],
        "playbook",
    )?;

    let name = doc["name"]
        .as_str()
        .filter(|n| valid_name(n))
        .ok_or_else(|| err("name must be lowercase letters, digits, and dashes"))?;
    let version = doc["version"]
        .as_i64()
        .filter(|v| *v >= 1)
        .ok_or_else(|| err("version must be a whole number, 1 or more"))?;
    let description = doc["description"]
        .as_str()
        .filter(|d| !d.trim().is_empty())
        .ok_or_else(|| err("description is required"))?;
    let tier = match doc["tier"].as_str() {
        Some("auto_act") => Tier::AutoAct,
        Some("ask_first") => Tier::AskFirst,
        Some("scheduled") => Tier::Scheduled,
        _ => return Err(err("tier must be auto_act, ask_first, or scheduled")),
    };

    let mitre = &doc["mitre"];
    if mitre.as_hash().is_none() {
        return Err(err(
            "mitre is required (NFR-13): a technique, a mitigation, or both",
        ));
    }
    only_keys(mitre, &["technique", "mitigation"], "mitre")?;
    let technique = optional_str(&mitre["technique"], "mitre.technique")?;
    let mitigation = optional_str(&mitre["mitigation"], "mitre.mitigation")?;
    if technique.is_none() && mitigation.is_none() {
        return Err(err(
            "mitre needs a technique (T1234) or a mitigation (M1234)",
        ));
    }
    if let Some(t) = &technique
        && !valid_mitre(t, 'T', true)
    {
        return Err(err(&format!(
            "{t:?} is not a MITRE technique ID like T1071.004"
        )));
    }
    if let Some(m) = &mitigation
        && !valid_mitre(m, 'M', false)
    {
        return Err(err(&format!(
            "{m:?} is not a MITRE mitigation ID like M1021"
        )));
    }

    let trigger = match (&doc["trigger"], tier) {
        (Yaml::BadValue, Tier::Scheduled) => None,
        (_, Tier::Scheduled) => return Err(err("scheduled playbooks have no trigger")),
        (Yaml::BadValue, _) => return Err(err("trigger is required")),
        (t, _) => Some(parse_trigger(t)?),
    };

    let act = doc["act"]
        .as_vec()
        .filter(|a| !a.is_empty())
        .ok_or_else(|| err("act must be a non-empty list of actions"))?;
    let actions = act
        .iter()
        .map(|a| parse_action(a, tier))
        .collect::<Result<Vec<_>, _>>()?;

    let notify_on_success = match &doc["report"] {
        Yaml::BadValue => true,
        report => {
            only_keys(report, &["notify"], "report")?;
            match report["notify"].as_str() {
                Some("action_taken") | None => true,
                Some("none") => false,
                Some(other) => {
                    return Err(err(&format!(
                        "report.notify must be action_taken or none, not {other:?}"
                    )));
                }
            }
        }
    };

    Ok(Playbook {
        name: name.to_owned(),
        version,
        description: description.trim().to_owned(),
        tier,
        mitre_technique: technique,
        mitre_mitigation: mitigation,
        trigger,
        actions,
        notify_on_success,
    })
}

fn parse_trigger(t: &Yaml) -> Result<Trigger, PlaybookError> {
    let err = |m: String| PlaybookError(m);
    only_keys(t, &["detection", "min_confidence", "evidence"], "trigger")?;
    let detections: Vec<String> = match &t["detection"] {
        Yaml::String(s) => vec![s.clone()],
        Yaml::Array(items) => items
            .iter()
            .map(|i| i.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| err("trigger.detection must be a string or a list of strings".into()))?,
        _ => return Err(err("trigger.detection is required".into())),
    };
    if detections.is_empty() || !detections.iter().all(|d| valid_detection(d)) {
        return Err(err(format!(
            "trigger.detection {detections:?} must name detections like dns.beaconing"
        )));
    }
    let min_confidence = match &t["min_confidence"] {
        Yaml::BadValue => None,
        v => Some(
            number(v)
                .filter(|c| (0.0..=1.0).contains(c))
                .ok_or_else(|| err("trigger.min_confidence must be between 0 and 1".into()))?,
        ),
    };
    let mut evidence = Vec::new();
    if let Some(map) = t["evidence"].as_hash() {
        for (key, cond) in map {
            let key = key
                .as_str()
                .filter(|k| valid_key(k))
                .ok_or_else(|| err("trigger.evidence keys must be simple names".into()))?;
            let pairs = cond.as_hash().filter(|h| h.len() == 1).ok_or_else(|| {
                err(format!(
                    "trigger.evidence.{key} must be one comparison, like {{ gt: 0 }}"
                ))
            })?;
            let (op, value) = pairs.iter().next().expect("checked: one entry");
            let op = match op.as_str() {
                Some("eq") => Op::Eq,
                Some("ne") => Op::Ne,
                Some("gt") => Op::Gt,
                Some("gte") => Op::Gte,
                Some("lt") => Op::Lt,
                Some("lte") => Op::Lte,
                Some("in") => Op::In,
                _ => {
                    return Err(err(format!(
                        "trigger.evidence.{key}: use eq, ne, gt, gte, lt, lte, or in"
                    )));
                }
            };
            let value = to_json(value).ok_or_else(|| {
                err(format!(
                    "trigger.evidence.{key}: the value must be a number, string, or list"
                ))
            })?;
            if op == Op::In && !value.is_array() {
                return Err(err(format!("trigger.evidence.{key}: `in` needs a list")));
            }
            evidence.push(Condition {
                key: key.to_owned(),
                op,
                value,
            });
        }
    } else if !matches!(t["evidence"], Yaml::BadValue) {
        return Err(err("trigger.evidence must be a mapping".into()));
    }
    Ok(Trigger {
        detections,
        min_confidence,
        evidence,
    })
}

fn parse_action(a: &Yaml, tier: Tier) -> Result<Action, PlaybookError> {
    let err = |m: String| PlaybookError(m);
    let name = a["action"]
        .as_str()
        .ok_or_else(|| err("every act entry needs an action".into()))?;
    let hours = |a: &Yaml| -> Result<i64, PlaybookError> {
        a["hours"]
            .as_i64()
            .filter(|h| (1..=720).contains(h))
            .ok_or_else(|| err(format!("{name}: hours must be 1 to 720")))
    };
    let action = match name {
        "pihole.block_domain" => {
            only_keys(a, &["action", "domain", "hours"], name)?;
            let raw = a["domain"]
                .as_str()
                .ok_or_else(|| err(format!("{name}: domain is required")))?;
            Action::PiholeBlock {
                domain: parse_param(raw, name)?,
                hours: hours(a)?,
            }
        }
        "router.quarantine" => {
            only_keys(a, &["action", "device", "hours"], name)?;
            if a["device"].as_str() != Some("incident") {
                return Err(err(format!(
                    "{name}: device must be `incident` (the incident's own device)"
                )));
            }
            if tier != Tier::AskFirst {
                return Err(err(format!(
                    "{name} is disruptive, so it's only allowed in ask_first playbooks (R-03)"
                )));
            }
            Action::RouterQuarantine { hours: hours(a)? }
        }
        "python.self_assess" => {
            only_keys(a, &["action"], name)?;
            if tier != Tier::Scheduled {
                return Err(err(format!("{name} belongs in a scheduled playbook")));
            }
            Action::SelfAssess
        }
        other => return Err(err(format!("unknown action {other:?}"))),
    };
    if tier == Tier::Scheduled && action.has_effect() {
        return Err(err(format!(
            "{name}: scheduled playbooks may only report, not change the network"
        )));
    }
    Ok(action)
}

fn parse_param(raw: &str, action: &str) -> Result<Param, PlaybookError> {
    if let Some(inner) = raw.strip_prefix('{').and_then(|r| r.strip_suffix('}')) {
        let key = inner.strip_prefix("evidence.").filter(|k| valid_key(k));
        return key.map(|k| Param::Evidence(k.to_owned())).ok_or_else(|| {
            PlaybookError(format!(
                "{action}: {raw:?} must be a whole {{evidence.<key>}} reference"
            ))
        });
    }
    if raw.contains('{') || raw.contains('}') {
        return Err(PlaybookError(format!(
            "{action}: {raw:?} mixes text and a reference; use one whole reference"
        )));
    }
    Ok(Param::Literal(raw.to_owned()))
}

fn only_keys(map: &Yaml, allowed: &[&str], at: &str) -> Result<(), PlaybookError> {
    let hash = map
        .as_hash()
        .ok_or_else(|| PlaybookError(format!("{at} must be a mapping")))?;
    for key in hash.keys() {
        let name = key.as_str().unwrap_or("<non-string key>");
        if !allowed.contains(&name) {
            return Err(PlaybookError(format!("{at}: unknown key {name:?}")));
        }
    }
    Ok(())
}

fn optional_str(v: &Yaml, at: &str) -> Result<Option<String>, PlaybookError> {
    match v {
        Yaml::BadValue | Yaml::Null => Ok(None),
        Yaml::String(s) => Ok(Some(s.clone())),
        _ => Err(PlaybookError(format!("{at} must be a string"))),
    }
}

fn number(v: &Yaml) -> Option<f64> {
    match v {
        Yaml::Integer(i) => Some(*i as f64),
        Yaml::Real(r) => r.parse().ok(),
        _ => None,
    }
}

fn to_json(v: &Yaml) -> Option<Value> {
    match v {
        Yaml::Integer(i) => Some(Value::from(*i)),
        Yaml::Real(r) => r.parse::<f64>().ok().map(Value::from),
        Yaml::String(s) => Some(Value::from(s.as_str())),
        Yaml::Boolean(b) => Some(Value::from(*b)),
        Yaml::Array(items) => items
            .iter()
            .map(to_json)
            .collect::<Option<Vec<_>>>()
            .map(Value::from),
        _ => None,
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn valid_detection(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 64
        && d.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_')
}

fn valid_key(k: &str) -> bool {
    !k.is_empty()
        && k.len() <= 64
        && k.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn valid_mitre(id: &str, prefix: char, allow_sub: bool) -> bool {
    let Some(rest) = id.strip_prefix(prefix) else {
        return false;
    };
    let (main, sub) = match rest.split_once('.') {
        Some((m, s)) if allow_sub => (m, Some(s)),
        Some(_) => return false,
        None => (rest, None),
    };
    let digits = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_digit());
    digits(main, 4) && sub.is_none_or(|s| digits(s, 3))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn repo_playbooks() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../playbooks")
    }

    #[test]
    fn the_shipped_playbooks_load() {
        let all = load_dir(&repo_playbooks()).unwrap();
        let names: Vec<&str> = all.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "block-known-bad-domain",
                "quarantine-suspected-c2",
                "weekly-self-assessment"
            ]
        );
        let block = &all[0];
        assert_eq!(block.tier, Tier::AutoAct);
        assert!(block.matches("dns.threat_intel") && !block.matches("dns.dga"));
        assert_eq!(
            block.actions,
            [Action::PiholeBlock {
                domain: Param::Evidence("indicator".into()),
                hours: 168
            }]
        );
        assert_eq!(block.trigger.as_ref().unwrap().evidence[0].op, Op::Gt);
        assert!(all[1].matches("dns.dga") && all[1].matches("dns.beaconing"));
        assert!(all[2].trigger.is_none() && !all[2].notify_on_success);
    }

    const BASE: &str = "name: t\nversion: 1\ndescription: d\nmitre: { technique: T1071.004 }\n";

    fn with(rest: &str) -> Result<Playbook, PlaybookError> {
        parse(&format!("{BASE}{rest}"))
    }

    #[test]
    fn unsafe_or_sloppy_playbooks_are_refused() {
        let quarantine =
            "act:\n  - action: router.quarantine\n    device: incident\n    hours: 24\n";
        let trigger = "trigger: { detection: dns.dga }\n";
        let cases = [
            (
                format!("tier: auto_act\n{trigger}{quarantine}"),
                "only allowed in ask_first",
            ),
            (
                format!("tier: ask_first\n{trigger}act:\n  - action: shell.run\n"),
                "unknown action",
            ),
            (
                format!(
                    "tier: auto_act\n{trigger}act:\n  - action: pihole.block_domain\n    domain: \"x.{{evidence.indicator}}\"\n    hours: 1\n"
                ),
                "mixes text",
            ),
            (
                format!(
                    "tier: auto_act\n{trigger}act:\n  - action: pihole.block_domain\n    domain: \"{{asset.mac}}\"\n    hours: 1\n"
                ),
                "whole {evidence",
            ),
            (
                format!(
                    "tier: ask_first\n{trigger}{}",
                    quarantine.replace("24", "9999")
                ),
                "hours must be",
            ),
            (
                format!("tier: ask_first\n{quarantine}"),
                "trigger is required",
            ),
            (
                format!("tier: scheduled\n{trigger}act:\n  - action: python.self_assess\n"),
                "no trigger",
            ),
            (
                format!("tier: ask_first\n{trigger}{quarantine}extra: 1\n"),
                "unknown key",
            ),
            (
                format!("tier: ask_first\ntier: auto_act\n{trigger}{quarantine}"),
                "duplicate key",
            ),
        ];
        for (text, message) in cases {
            let error = with(&text).unwrap_err();
            assert!(error.0.contains(message), "{text}\n-> {error}");
        }
        let no_mitre = "name: t\nversion: 1\ndescription: d\ntier: scheduled\nact:\n  - action: python.self_assess\n";
        assert!(parse(no_mitre).unwrap_err().0.contains("NFR-13"));
    }

    #[test]
    fn mitre_ids_are_checked() {
        assert!(valid_mitre("T1071", 'T', true));
        assert!(valid_mitre("T1071.004", 'T', true));
        assert!(!valid_mitre("T1071.4", 'T', true));
        assert!(valid_mitre("M1021", 'M', false));
        assert!(!valid_mitre("M1021.001", 'M', false));
        assert!(!valid_mitre("X1021", 'M', false));
    }
}
