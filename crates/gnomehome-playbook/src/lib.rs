//! GnomeHome playbook engine: the automated Blue Team (Phase 7, FR-13, FR-15, FR-16, FR-17).
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
//! before the act stage, and again right before an approved action runs. It refuses
//! protected targets and writes the refusal to the audit log by label only (plan,
//! "Protected assets", step 6). The guard is `gnomehome_core::protected`, the Rust port
//! that passes the shared vectors in `testdata/guard_vectors.yaml`. The schema refuses
//! runs and quarantines aimed at protected devices too.
//!
//! # Dry run
//!
//! Nothing changes on the network unless `[response] mode = "live"` *and* the action is
//! listed in `live_actions`. Until then, every run records what it would have done.
//!
//! - [`playbook`]: the YAML format and its validation
//! - [`engine`]: detect, enrich, decide, act, report; approvals; releases
//! - [`effects`]: Pi-hole's API on loopback and the Python helper

pub mod effects;
pub mod engine;
pub mod playbook;

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
