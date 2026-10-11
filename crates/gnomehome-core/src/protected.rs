//! The protected-asset guard: the Rust port of `python/gnomehome/protected.py`.
//!
//! It must agree with the Python guard on every case in `testdata/guard_vectors.yaml`
//! (the tests below load that file). The rules are the same:
//!
//! - **Fail closed.** A missing, empty, or invalid list is an error, and anything that
//!   can't be parsed counts as protected.
//! - **Active actions** (scan, quarantine, block) call [`Guard::require_allowed`].
//! - **Passive collectors** drop records with [`Guard::is_protected`],
//!   [`Guard::touches_protected`], or [`Guard::text_mentions_protected`] *before* storage.
//! - **Audit entries** name a protected device by label only.
//!
//! YAML is parsed as YAML 1.2, so an unquoted all-digit MAC stays a string (YAML 1.1's
//! base-60 integers don't exist in 1.2). Duplicate keys are rejected.

use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::path::Path;

use yaml_rust2::{Yaml, YamlLoader};

use crate::identifiers::{Network, is_multicast, normalize_ip, normalize_mac};

/// The list is missing or invalid. Nothing may run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedListError(pub String);

impl fmt::Display for ProtectedListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ProtectedListError {}

/// An active action was refused because its target is protected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedTargetError {
    pub action: String,
    pub label: String,
    pub matched_on: String,
}

impl fmt::Display for ProtectedTargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "refused {:?}: target is protected asset {:?} (matched on {})",
            self.action, self.label, self.matched_on
        )
    }
}

impl std::error::Error for ProtectedTargetError {}

#[derive(Debug, Clone)]
pub struct ProtectedEntry {
    pub label: String,
    pub reason: String,
    pub macs: HashSet<String>,
    pub networks: Vec<Network>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    pub label: String,
    /// "mac", "ip", "unparseable-mac", or "unparseable-ip".
    pub matched_on: String,
}

const UNPARSEABLE: &str = "unparseable-identifier";

#[derive(Debug, Clone)]
pub struct ProtectedAssets {
    pub entries: Vec<ProtectedEntry>,
}

impl ProtectedAssets {
    pub fn load(path: &Path) -> Result<ProtectedAssets, ProtectedListError> {
        let text = std::fs::read_to_string(path).map_err(|err| {
            ProtectedListError(format!(
                "protected-asset list not readable: {}: {err}. Nothing may scan or act without it.",
                path.display()
            ))
        })?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<ProtectedAssets, ProtectedListError> {
        let err = |msg: &str| ProtectedListError(msg.to_owned());
        reject_duplicate_keys(text)?;
        let docs =
            YamlLoader::load_from_str(text).map_err(|e| err(&format!("invalid YAML: {e}")))?;
        let doc = docs
            .first()
            .ok_or_else(|| err("expected a mapping with 'version' and 'protected'"))?;
        let map = doc
            .as_hash()
            .ok_or_else(|| err("expected a mapping with 'version' and 'protected'"))?;
        only_keys(map, &["version", "protected"], "top level")?;
        let version = match &doc["version"] {
            Yaml::Integer(1) => true,
            Yaml::String(s) => s == "1",
            _ => false,
        };
        if !version {
            return Err(err("version must be 1"));
        }
        let items = doc["protected"]
            .as_vec()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                err("'protected' must be a non-empty list (an empty list is refused)")
            })?;
        let mut entries = Vec::new();
        let mut labels = HashSet::new();
        for (index, item) in items.iter().enumerate() {
            let entry = parse_entry(item, index + 1)?;
            if !labels.insert(entry.label.clone()) {
                return Err(err(&format!("duplicate label {:?}", entry.label)));
            }
            entries.push(entry);
        }
        Ok(ProtectedAssets { entries })
    }

    /// The matching entry, or None. Unparseable input always matches.
    pub fn match_target(&self, ip: Option<&str>, mac: Option<&str>) -> Option<Match> {
        let hit = |label: &str, on: &str| {
            Some(Match {
                label: label.to_owned(),
                matched_on: on.to_owned(),
            })
        };
        if let Some(mac) = mac {
            let Ok(normalized) = normalize_mac(mac) else {
                return hit(UNPARSEABLE, "unparseable-mac");
            };
            if let Some(entry) = self.entries.iter().find(|e| e.macs.contains(&normalized)) {
                return hit(&entry.label, "mac");
            }
        }
        if let Some(ip) = ip {
            let Ok(addr) = normalize_ip(ip) else {
                return hit(UNPARSEABLE, "unparseable-ip");
            };
            if let Some(entry) = self
                .entries
                .iter()
                .find(|e| e.networks.iter().any(|n| n.contains(addr)))
            {
                return hit(&entry.label, "ip");
            }
        }
        None
    }
}

fn parse_entry(item: &Yaml, index: usize) -> Result<ProtectedEntry, ProtectedListError> {
    let at = format!("protected entry #{index}");
    let err = |msg: String| ProtectedListError(msg);
    let map = item
        .as_hash()
        .ok_or_else(|| err(format!("{at} must be a mapping")))?;
    only_keys(map, &["label", "reason", "macs", "ips"], &at)?;
    let label = item["label"]
        .as_str()
        .filter(|l| valid_label(l))
        .ok_or_else(|| {
            err(format!(
                "{at}: label must be 1-64 letters, digits, spaces, dots, dashes, or underscores"
            ))
        })?;
    let reason = item["reason"].as_str().filter(|r| !r.trim().is_empty());
    let reason = reason.ok_or_else(|| err(format!("{at}: reason is required")))?;
    let macs_raw = string_list(&item["macs"])
        .ok_or_else(|| err(format!("{at}: macs must be a non-empty list of strings")))?;
    let mut macs = HashSet::new();
    for raw in macs_raw {
        let mac = normalize_mac(raw).map_err(|e| err(format!("{at}: {e}")))?;
        if is_multicast(&mac) || mac == "00:00:00:00:00:00" {
            return Err(err(format!(
                "{at}: {raw:?} is not a single device's MAC address"
            )));
        }
        macs.insert(mac);
    }
    let ips_raw = string_list(&item["ips"]).ok_or_else(|| {
        err(format!(
            "{at}: ips must be a non-empty list (nmap excludes by IP)"
        ))
    })?;
    let mut networks = Vec::new();
    for raw in ips_raw {
        networks.push(Network::parse(raw).map_err(|e| err(format!("{at}: {e}")))?);
    }
    Ok(ProtectedEntry {
        label: label.to_owned(),
        reason: reason.trim().to_owned(),
        macs,
        networks,
    })
}

fn string_list(value: &Yaml) -> Option<Vec<&str>> {
    let items = value.as_vec().filter(|v| !v.is_empty())?;
    items.iter().map(Yaml::as_str).collect()
}

fn valid_label(label: &str) -> bool {
    let mut chars = label.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    label.chars().count() <= 64
        && first.is_ascii_alphanumeric()
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '_' | '-'))
}

fn only_keys(
    map: &yaml_rust2::yaml::Hash,
    allowed: &[&str],
    at: &str,
) -> Result<(), ProtectedListError> {
    for key in map.keys() {
        let name = key.as_str().unwrap_or("<non-string key>");
        if !allowed.contains(&name) {
            return Err(ProtectedListError(format!("{at}: unknown key {name:?}")));
        }
    }
    Ok(())
}

/// yaml-rust2 keeps the last of two duplicate keys, which could silently drop a MAC.
/// This walks the parser's events and rejects any mapping with a repeated key. Other
/// YAML readers (the playbook engine) use it too.
pub fn reject_duplicate_keys(text: &str) -> Result<(), ProtectedListError> {
    use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser};
    use yaml_rust2::scanner::Marker;

    struct Checker {
        // One frame per open collection: Some(keys seen, expecting a key) for mappings.
        stack: Vec<Option<(HashSet<String>, bool)>>,
        duplicate: Option<String>,
    }
    impl Checker {
        fn value_done(&mut self) {
            if let Some(Some((_, expecting_key))) = self.stack.last_mut() {
                *expecting_key = !*expecting_key;
            }
        }
    }
    impl MarkedEventReceiver for Checker {
        fn on_event(&mut self, event: Event, _mark: Marker) {
            match event {
                Event::MappingStart(..) => {
                    self.stack.push(Some((HashSet::new(), true)));
                }
                Event::SequenceStart(..) => self.stack.push(None),
                Event::MappingEnd | Event::SequenceEnd => {
                    self.stack.pop();
                    self.value_done();
                }
                Event::Scalar(value, ..) => {
                    if let Some(Some((keys, true))) = self.stack.last_mut() {
                        if !keys.insert(value.clone()) && self.duplicate.is_none() {
                            self.duplicate = Some(value);
                        }
                    }
                    self.value_done();
                }
                Event::Alias(_) => self.value_done(),
                _ => {}
            }
        }
    }
    let mut checker = Checker {
        stack: Vec::new(),
        duplicate: None,
    };
    let mut parser = Parser::new_from_str(text);
    parser
        .load(&mut checker, true)
        .map_err(|e| ProtectedListError(format!("invalid YAML: {e}")))?;
    match checker.duplicate {
        Some(key) => Err(ProtectedListError(format!("duplicate key {key:?}"))),
        None => Ok(()),
    }
}

/// Enforces the list for one process.
#[derive(Debug, Clone)]
pub struct Guard {
    pub assets: ProtectedAssets,
}

impl Guard {
    pub fn new(assets: ProtectedAssets) -> Guard {
        Guard { assets }
    }

    pub fn is_protected(&self, ip: Option<&str>, mac: Option<&str>) -> bool {
        self.assets.match_target(ip, mac).is_some()
    }

    /// True if any of these identifiers is protected (None values are skipped).
    pub fn touches_protected(&self, ips: &[Option<&str>], macs: &[Option<&str>]) -> bool {
        ips.iter()
            .flatten()
            .any(|ip| self.is_protected(Some(ip), None))
            || macs
                .iter()
                .flatten()
                .any(|mac| self.is_protected(None, Some(mac)))
    }

    /// Refuses an active action against a protected target. The caller audits the
    /// refusal by label only (see [`crate::audit`]).
    pub fn require_allowed(
        &self,
        action: &str,
        ip: Option<&str>,
        mac: Option<&str>,
    ) -> Result<(), ProtectedTargetError> {
        assert!(
            ip.is_some() || mac.is_some(),
            "require_allowed needs an ip or a mac"
        );
        match self.assets.match_target(ip, mac) {
            None => Ok(()),
            Some(m) => Err(ProtectedTargetError {
                action: action.to_owned(),
                label: m.label,
                matched_on: m.matched_on,
            }),
        }
    }

    /// True if free text contains a protected IPv4 address or MAC (including the
    /// 14-octet iptables `MAC=` field, checked with a sliding 6-octet window).
    pub fn text_mentions_protected(&self, text: &str) -> bool {
        self.find_in_text(text).is_some()
    }

    /// The first protected device mentioned in free text, so a refusal can be audited
    /// by its label.
    pub fn find_in_text(&self, text: &str) -> Option<Match> {
        for token in runs(text, |c| c.is_ascii_digit() || c == '.') {
            if is_ipv4_token(token) && normalize_ip(token).is_ok() {
                if let Some(m) = self.assets.match_target(Some(token), None) {
                    return Some(m);
                }
            }
        }
        for token in runs(text, |c| c.is_ascii_hexdigit() || c == ':' || c == '-') {
            let octets: Vec<&str> = token.split([':', '-']).collect();
            if octets.len() < 6
                || !octets
                    .iter()
                    .all(|o| o.len() == 2 && o.chars().all(|c| c.is_ascii_hexdigit()))
            {
                continue;
            }
            for window in octets.windows(6) {
                if let Some(m) = self.assets.match_target(None, Some(&window.join(":"))) {
                    return Some(m);
                }
            }
        }
        None
    }
}

/// Maximal runs of characters matching `keep`.
fn runs(text: &str, keep: impl Fn(char) -> bool) -> impl Iterator<Item = &str> {
    text.split(move |c: char| !keep(c))
        .filter(|s| !s.is_empty())
}

fn is_ipv4_token(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|p| (1..=3).contains(&p.len()) && p.chars().all(|c| c.is_ascii_digit()))
}

/// For tests and tools: parse an address the way the guard does.
pub fn parse_ip(value: &str) -> Option<IpAddr> {
    normalize_ip(value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn repo() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn vectors() -> Yaml {
        let text = std::fs::read_to_string(repo().join("testdata/guard_vectors.yaml")).unwrap();
        YamlLoader::load_from_str(&text).unwrap().remove(0)
    }

    fn opt(y: &Yaml) -> Option<&str> {
        y.as_str()
    }

    #[test]
    fn shared_guard_vectors() {
        let v = vectors();
        let guard =
            Guard::new(ProtectedAssets::parse(v["protected_list"].as_str().unwrap()).unwrap());
        for case in v["cases"].as_vec().unwrap() {
            let got = guard.is_protected(opt(&case["ip"]), opt(&case["mac"]));
            assert_eq!(
                got,
                case["protected"].as_bool().unwrap(),
                "case {:?}",
                case["name"]
            );
        }
    }

    #[test]
    fn shared_text_vectors() {
        let v = vectors();
        let guard =
            Guard::new(ProtectedAssets::parse(v["protected_list"].as_str().unwrap()).unwrap());
        for case in v["text_cases"].as_vec().unwrap() {
            let got = guard.text_mentions_protected(case["text"].as_str().unwrap());
            assert_eq!(
                got,
                case["protected"].as_bool().unwrap(),
                "case {:?}",
                case["name"]
            );
        }
    }

    #[test]
    fn example_file_loads_and_refuses_the_laptop() {
        let assets =
            ProtectedAssets::load(&repo().join("config/protected_assets.example.yaml")).unwrap();
        let guard = Guard::new(assets);
        let err = guard
            .require_allowed("quarantine", None, Some("00-00-5E-00-53-01"))
            .unwrap_err();
        assert_eq!(err.label, "Work laptop");
        assert!(
            guard
                .require_allowed("scan", Some("192.0.2.11"), None)
                .is_ok()
        );
    }

    fn list(macs: &str, ips: &str) -> String {
        format!(
            "version: 1\nprotected:\n  - label: L\n    reason: r\n    macs: {macs}\n    ips: {ips}\n"
        )
    }

    #[test]
    fn invalid_lists_fail_closed() {
        let cases = [
            ("".to_owned(), "expected a mapping"),
            (
                "version: 2\nprotected: []\n".to_owned(),
                "version must be 1",
            ),
            ("version: 1\nprotected: []\n".to_owned(), "non-empty"),
            (list("[]", "[\"192.0.2.10\"]"), "macs"),
            (list("[\"00:00:5e:00:53:01\"]", "[]"), "ips"),
            (
                list("[\"not-a-mac\"]", "[\"192.0.2.10\"]"),
                "invalid identifier",
            ),
            (
                list("[\"ff:ff:ff:ff:ff:ff\"]", "[\"192.0.2.10\"]"),
                "single device",
            ),
            (
                list("[\"00:00:5e:00:53:01\"]", "[\"192.0.2.10\"]") + "extra: 1\n",
                "unknown key",
            ),
            (
                list("[\"00:00:5e:00:53:01\"]", "[\"192.0.2.10\"]")
                    .replace("    macs:", "    macs: [\"00:00:5e:00:53:09\"]\n    macs:"),
                "duplicate key",
            ),
        ];
        for (text, message) in cases {
            let err = ProtectedAssets::parse(&text).unwrap_err();
            assert!(err.0.contains(message), "{text:?} -> {err}");
        }
    }

    #[test]
    fn unquoted_all_digit_mac_stays_a_string() {
        // In YAML 1.1 this unquoted value is a base-60 integer. YAML 1.2 keeps it a string.
        let mac = "10:20:30:40:50:58"; // hygiene: allow
        let assets =
            ProtectedAssets::parse(&list(&format!("[{mac}]"), "[\"192.0.2.10\"]")).unwrap();
        assert!(Guard::new(assets).is_protected(None, Some(&mac.replace(':', "-"))));
    }
}
