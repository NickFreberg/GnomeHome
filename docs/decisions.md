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

## Made during the build

| ID | Decision | Where |
| --- | --- | --- |
| D-2 | nmap gets raw-socket rights as systemd *ambient capabilities* on the two scan units only, rather than `setcap` on the system nmap binary | `deploy/pi/README.md` |
| D-3 | New-device alerts come from router syslog (DHCP), so no router password is stored for Phases 1 to 3 | `collectors/router_syslog.py` |
| D-4 | Response actions (Pi-hole block, router quarantine, notifications) run dry-run by default until the owner turns each on | Phase 7 |
| D-5 | Cloud pieces (Bicep, Databricks bundle, Container App) are written and validated locally, never deployed from this repository's tooling | Phase 6 |
| D-6 | The DNS tailer stops if the protected list becomes invalid, rather than continuing with the last good copy | `crates/gnomehome-dnstail` |
| D-7 | A device that skips Pi-hole is reported once (low severity), not repeatedly. The router's backup DNS can be listed in `allowed_dns_servers` | `analytics/detect.py` |
