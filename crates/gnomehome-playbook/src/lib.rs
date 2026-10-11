//! GnomeHome playbook engine (stub).
//!
//! The automated Blue Team is a small SOAR engine. Each detection runs a YAML playbook,
//! mapped to MITRE ATT&CK (NFR-13), through five stages: detect, enrich, decide, act, report.
//! The tier decides how much automation is allowed:
//!
//! | Tier        | When                        | Example                                   |
//! |-------------|-----------------------------|-------------------------------------------|
//! | `AutoAct`   | High confidence, low impact | Block a known-bad domain in Pi-hole       |
//! | `AskFirst`  | Disruptive to a device/user | Quarantine a device after push approval   |
//! | `Scheduled` | Weekly                      | Self-assessment of devices, ports, CVEs   |
//!
//! # Protected assets
//!
//! The engine, not each playbook, checks every target against the protected-asset list
//! before the act stage. It refuses protected targets and writes the refusal to the audit log
//! (plan, "Protected assets", step 6). The Python guard in `python/gnomehome/protected.py`
//! defines the semantics, and the Rust port must pass the shared vectors in
//! `testdata/guard_vectors.yaml`. Until that port exists, this crate has no way to act on
//! anything.

/// How much automation a playbook is allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// High confidence, low impact: runs without asking.
    AutoAct,
    /// Disruptive: waits for an admin's approval (with a fresh MFA check) before acting.
    AskFirst,
    /// Runs on a schedule, such as the weekly self-assessment.
    Scheduled,
}

impl Tier {
    /// Whether a human must approve before the act stage runs.
    pub fn requires_approval(self) -> bool {
        matches!(self, Tier::AskFirst)
    }
}

/// The stages every playbook runs through, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {
    Detect,
    Enrich,
    Decide,
    /// The only stage with side effects. The protected-asset check runs right before it.
    Act,
    Report,
}

impl Stage {
    /// All stages in execution order.
    pub const ORDER: [Stage; 5] = [
        Stage::Detect,
        Stage::Enrich,
        Stage::Decide,
        Stage::Act,
        Stage::Report,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_ask_first_requires_approval() {
        assert!(Tier::AskFirst.requires_approval());
        assert!(!Tier::AutoAct.requires_approval());
        assert!(!Tier::Scheduled.requires_approval());
    }

    #[test]
    fn stages_run_detect_to_report() {
        assert!(Stage::ORDER.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(Stage::ORDER.first(), Some(&Stage::Detect));
        assert_eq!(Stage::ORDER.last(), Some(&Stage::Report));
    }
}
