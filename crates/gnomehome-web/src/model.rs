//! The dashboard's data and the arithmetic on it, kept free of any UI so it's tested
//! on the host (`cargo test -p gnomehome-web`). Counting, sorting, and filtering
//! happen here in the browser, not on the Pi (NFR-08).

use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Low,
    Medium,
    High,
    Critical,
}

impl Level {
    pub fn parse(text: &str) -> Option<Level> {
        match text {
            "low" => Some(Level::Low),
            "medium" => Some(Level::Medium),
            "high" => Some(Level::High),
            "critical" => Some(Level::Critical),
            _ => None,
        }
    }

    /// Risk is always a word as well as a color and an icon (design system).
    pub fn word(self) -> &'static str {
        match self {
            Level::Low => "Low",
            Level::Medium => "Medium",
            Level::High => "High",
            Level::Critical => "Critical",
        }
    }

    pub fn css(self) -> &'static str {
        match self {
            Level::Low => "risk-low",
            Level::Medium => "risk-medium",
            Level::High | Level::Critical => "risk-high",
        }
    }

    pub const ALL: [Level; 4] = [Level::Critical, Level::High, Level::Medium, Level::Low];
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Me {
    pub username: String,
    pub role: String,
    pub csrf: String,
    pub expires_at: String,
}

impl Me {
    pub fn can_approve(&self) -> bool {
        self.role == "admin"
    }

    pub fn can_resolve(&self) -> bool {
        self.role == "admin" || self.role == "analyst"
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Asset {
    pub id: i64,
    pub ip: Option<String>,
    pub mac: String,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
    pub device_type: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub risk_score: Option<f64>,
    pub risk_level: Option<String>,
    pub risk_summary: Option<String>,
}

impl Asset {
    pub fn level(&self) -> Option<Level> {
        self.risk_level.as_deref().and_then(Level::parse)
    }

    /// The name to show: the manufacturer, or the device's own name (labeled), or the MAC.
    pub fn display_name(&self) -> String {
        match (&self.vendor, &self.hostname) {
            (Some(v), Some(h)) => format!("{v} (calls itself \"{h}\")"),
            (Some(v), None) => v.clone(),
            (None, Some(h)) => format!("Unknown maker (calls itself \"{h}\")"),
            (None, None) => format!("Unknown device {}", self.mac),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Incident {
    pub id: i64,
    pub occurred_at: String,
    pub severity: String,
    pub detection: String,
    pub title: String,
    pub device: Option<String>,
    pub what_happened: Option<String>,
    pub why_it_matters: Option<String>,
    pub next_steps: Option<String>,
    pub mitre_technique: Option<String>,
    pub status: String,
    pub outcome: Option<String>,
}

impl Incident {
    pub fn level(&self) -> Level {
        Level::parse(&self.severity).unwrap_or(Level::Low)
    }

    pub fn mitre_url(&self) -> Option<String> {
        self.mitre_technique.as_ref().map(|t| {
            format!(
                "https://attack.mitre.org/techniques/{}/",
                t.replace('.', "/")
            )
        })
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Approval {
    pub run_id: String,
    pub playbook: String,
    pub expires_at: String,
    pub title: Option<String>,
    pub severity: Option<String>,
    pub device: Option<String>,
    pub outcome: Option<String>,
}

/// How many devices sit at each risk level, highest first, plus the unscored count.
pub fn risk_counts(assets: &[Asset]) -> (Vec<(Level, usize)>, usize) {
    let counts = Level::ALL
        .iter()
        .map(|l| (*l, assets.iter().filter(|a| a.level() == Some(*l)).count()))
        .collect();
    let unscored = assets.iter().filter(|a| a.level().is_none()).count();
    (counts, unscored)
}

pub fn severity_counts(incidents: &[Incident]) -> Vec<(Level, usize)> {
    Level::ALL
        .iter()
        .map(|l| (*l, incidents.iter().filter(|i| i.level() == *l).count()))
        .filter(|(_, n)| *n > 0)
        .collect()
}

/// Riskiest first, then by address.
pub fn sort_by_risk(assets: &mut [Asset]) {
    assets.sort_by(|a, b| {
        b.risk_score
            .unwrap_or(-1.0)
            .total_cmp(&a.risk_score.unwrap_or(-1.0))
            .then_with(|| a.ip.cmp(&b.ip))
    });
}

/// Case-insensitive match on address, MAC, maker, name, or type.
pub fn matches(asset: &Asset, query: &str) -> bool {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return true;
    }
    [
        asset.ip.as_deref(),
        Some(asset.mac.as_str()),
        asset.vendor.as_deref(),
        asset.hostname.as_deref(),
        asset.device_type.as_deref(),
    ]
    .into_iter()
    .flatten()
    .any(|field| field.to_lowercase().contains(&q))
}

/// The calm one-line status (the only place the gnome voice appears).
pub fn status_line(devices: usize, open_incidents: usize) -> String {
    let d = if devices == 1 {
        "1 device".to_owned()
    } else {
        format!("{devices} devices")
    };
    match open_incidents {
        0 => format!("All quiet in the garden. {d}, no open incidents."),
        1 => format!("{d}, 1 open incident."),
        n => format!("{d}, {n} open incidents."),
    }
}

/// Seconds between two of GnomeHome's timestamps (`2026-10-11T14:03:00.000Z`).
pub fn seconds_between(from: &str, to: &str) -> Option<i64> {
    Some(epoch_seconds(to)? - epoch_seconds(from)?)
}

fn epoch_seconds(ts: &str) -> Option<i64> {
    let b = ts.as_bytes();
    if b.len() != 24 || b[10] != b'T' || b[23] != b'Z' {
        return None;
    }
    let n = |r: std::ops::Range<usize>| ts.get(r)?.parse::<i64>().ok();
    let (y, m, d) = (n(0..4)?, n(5..7)?, n(8..10)?);
    let (hh, mm, ss) = (n(11..13)?, n(14..16)?, n(17..19)?);
    // Days from civil (Howard Hinnant's algorithm).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hh * 3600 + mm * 60 + ss)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asset(ip: &str, level: Option<&str>, score: Option<f64>) -> Asset {
        Asset {
            id: 1,
            ip: Some(ip.into()),
            mac: "00:00:5e:00:53:51".into(),
            vendor: Some("Example Camera Co".into()),
            hostname: None,
            device_type: Some("webcam".into()),
            first_seen: "2026-10-11T00:00:00.000Z".into(),
            last_seen: "2026-10-11T00:00:00.000Z".into(),
            risk_score: score,
            risk_level: level.map(str::to_owned),
            risk_summary: None,
        }
    }

    #[test]
    fn counts_sorts_and_filters() {
        let mut list = vec![
            asset("192.0.2.30", Some("low"), Some(10.0)),
            asset("192.0.2.51", Some("high"), Some(72.0)),
            asset("192.0.2.99", None, None),
        ];
        let (counts, unscored) = risk_counts(&list);
        assert_eq!(
            counts,
            [
                (Level::Critical, 0),
                (Level::High, 1),
                (Level::Medium, 0),
                (Level::Low, 1)
            ]
        );
        assert_eq!(unscored, 1);
        sort_by_risk(&mut list);
        assert_eq!(list[0].ip.as_deref(), Some("192.0.2.51"));
        assert!(
            matches(&list[0], "CAMERA")
                && matches(&list[0], "53:51")
                && !matches(&list[0], "printer")
        );
    }

    #[test]
    fn words_and_status_lines() {
        assert_eq!(Level::Critical.word(), "Critical");
        assert_eq!(Level::Critical.css(), Level::High.css());
        assert_eq!(
            status_line(14, 0),
            "All quiet in the garden. 14 devices, no open incidents."
        );
        assert_eq!(status_line(1, 2), "1 device, 2 open incidents.");
    }

    #[test]
    fn timestamps_subtract() {
        assert_eq!(
            seconds_between("2026-10-11T23:59:00.000Z", "2026-10-12T00:01:30.000Z"),
            Some(150)
        );
        assert_eq!(
            seconds_between("2024-02-28T00:00:00.000Z", "2024-03-01T00:00:00.000Z"),
            Some(2 * 86_400)
        );
        assert_eq!(seconds_between("bad", "2026-10-11T00:00:00.000Z"), None);
    }

    #[test]
    fn names_label_device_supplied_text() {
        let mut a = asset("192.0.2.51", None, None);
        a.hostname = Some("garage-cam".into());
        assert_eq!(
            a.display_name(),
            "Example Camera Co (calls itself \"garage-cam\")"
        );
    }
}
