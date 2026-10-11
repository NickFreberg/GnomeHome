# Decisions log

Decisions made while building GnomeHome, and the ones still waiting on the owner. `docs/PLAN.md` stays the
source of truth: anything here that changes the plan's scope is listed as **open** until the owner agrees.

## Open: waiting on the owner

### D-1. FR-14 (on-demand capture by ARP spoofing) is not built

- **Plan says:** FR-14, "Capture one suspicious device's traffic on demand via ARP spoofing for deeper
  inspection" (Phase 7, risk R-10 accepted).
- **What was built instead:** nothing that spoofs ARP or intercepts another device's traffic. The deeper look at
  a suspicious device uses what GnomeHome already sees passively: its DNS history (`event` rows from the
  Pi-hole tailer), its router connection records (FR-08), and its scan results. The playbook engine can
  quarantine through the router (FR-13), which is the response the plan uses for a device that needs stopping.
- **Why:** an ARP-spoofing tool puts the Pi in the middle of another device's traffic, and on a network that also
  carries a work laptop it's the one feature where a bug could reach a protected device (R-12). It's also the
  highest-risk component to publish in a portfolio repository.
- **Owner decides:** keep FR-14 out (and mark it out of scope in the plan), or build it later as a separate,
  explicitly approved piece of work with its own review of R-10 and R-12.

### D-8. Pi-to-Azure transport: HTTPS with a write-only token, not WireGuard (yet)

- **Plan says:** "In transit, Pi to Azure: WireGuard tunnel" (NFR-02).
- **What was built:** the nightly upload uses HTTPS (TLS 1.2+) with a service SAS that can only create and
  write files in one container, tied to a revocable stored access policy, to a storage account that accepts
  only the home IP (`infra/modules/storage.bicep`, `python/gnomehome/upload.py`).
- **Why:** Azure has no managed WireGuard endpoint. A VPN gateway or a small VM to terminate WireGuard
  costs more than the whole $25 budget, and a VM adds a server to patch.
- **Owner decides:** accept HTTPS plus the IP restriction for now, or add a WireGuard endpoint (a B1s VM with
  a private endpoint to storage) and raise the budget.

## Made during the build

| ID | Decision | Where |
| --- | --- | --- |
| D-2 | nmap gets raw-socket rights as systemd *ambient capabilities* on the two scan units only, rather than `setcap` on the system nmap binary | `deploy/pi/README.md` |
| D-3 | New-device alerts come from router syslog (DHCP), so no router password is stored for Phases 1 to 3 | `collectors/router_syslog.py` |
| D-4 | Response actions (Pi-hole block, router quarantine, notifications) run dry-run by default until the owner turns each on | Phase 7 |
| D-5 | Cloud pieces (Bicep, Databricks bundle, Container App) are written and validated locally, never deployed from this repository's tooling | Phase 6 |
| D-6 | The DNS tailer stops if the protected list becomes invalid, rather than continuing with the last good copy | `crates/gnomehome-dnstail` |
| D-7 | A device that skips Pi-hole is reported once (low severity), not repeatedly. The router's backup DNS can be listed in `allowed_dns_servers` | `analytics/detect.py` |
| D-9 | The protected list never leaves the Pi. The export drops protected rows on the Pi, and the cloud verifies the manifest's `guard_checked` flag and checksums instead of re-checking identifiers | `export.py`, `databricks/src/silver.py` |
| D-10 | The device classifier is hand-weighted and explainable rather than trained: one household never has enough labeled devices. Its own name counts for little, since a device can call itself anything | `ml/classifier.py` |
| D-12 | Quarantine is a temporary iptables rule on the router over the pinned SSH (FR-13's second option), not the asusrouter library: one fixed command template, testable, and gone after a router reboot. It stops internet traffic, not traffic between two devices on the same Wi-Fi | `responders/router_quarantine.py` |
| D-13 | Every response action needs two switches to run for real: `[response] mode = "live"` and the action named in `live_actions`. Quarantine is only allowed in ask-first playbooks, enforced by the playbook loader (R-03) | `crates/gnomehome-playbook` |
| D-14 | Push notifications carry a fixed kind only. The outbox schema can't hold free text, and Azure receives `{TimeGenerated, Kind}` | `notify_relay.py`, `0006_response.sql` |
| D-15 | Dashboard MFA is TOTP (any authenticator app) for now. Passkeys and the YubiKey from the plan can be added later; TOTP needs no browser or hardware support to start | `crates/gnomehome-api/src/auth.rs` |
| D-16 | The API only records an approval decision; the playbook engine acts within a minute. The always-on web server never needs router or Pi-hole access | `crates/gnomehome-api` |
| D-17 | The AI check-in may suggest only `quarantine-suspected-c2`, always ask-first, for a device in the summary that the Pi knows and that isn't protected | `python/gnomehome/agent/prompt.py`, `checkin.py`, playbook engine |
| D-18 | The dashboard certificate starts self-signed; step-ca 24-hour certificates (plan) replace it later | `deploy/pi/README.md` |
| D-11 | Anomaly detection uses robust z-scores against each device's own history (no training), flags rises only, and has per-feature and relative floors so normal variation stays quiet | `ml/anomaly.py` |
