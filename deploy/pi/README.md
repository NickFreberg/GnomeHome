# deploy/pi: Linux-only pieces for the Raspberry Pi

Everything in GnomeHome runs on the Mac except what lives here. These pieces only make sense on the Pi
(Raspberry Pi OS Lite 64-bit), and nothing in this folder is used on the Mac.

The Pi arrives Monday, and this folder fills in then. Planned contents, all driven by values in
`config/gnomehome.toml` (`platform = "pi"`) rather than hardcoded:

| Piece | What it does | Plan reference |
| --- | --- | --- |
| `systemd/gnomehome-discover.{service,timer}` | Runs `gnomehome discover` every `schedules.discovery_every_minutes` | FR-01, FR-03 |
| `systemd/gnomehome-scan.{service,timer}` | Runs `gnomehome scan` every `schedules.service_scan_every_minutes` | FR-01, FR-02 |
| Service sandboxing | Each job as its own unprivileged user, with `NoNewPrivileges`, `ProtectSystem=strict`, and `ReadWritePaths` limited to `/var/lib/gnomehome`; `RuntimeDirectory=gnomehome` provides `/run/gnomehome` | Security design, hardening |
| nmap raw-socket rights | `nmap_privilege = "capabilities"`, so nmap runs with `--privileged` and **no sudo**. Options to decide on Monday: file capabilities on a dedicated nmap copy that only the scan user can execute, or `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN` on the scan service | "Packet-capture capabilities granted only to the binaries that need them" |
| `/etc/gnomehome/protected_assets.yaml` | The real protected list, `root:gnomehome` `0640` | Protected assets, step 4 |
| LUKS with Adiantum | Full-disk encryption (the Pi 3 has no AES acceleration) | NFR-03 |
| Host firewall, key-only SSH | The dashboard is reachable only from the LAN | R-01 |
| rsyslog receiver | Router syslog to the Pi | FR-07 |

## Before enabling any timer on the Pi

1. Install Pi-hole natively (no Docker on the Pi, to save RAM), per the plan's Phase 1.
2. `just setup`, then set `platform = "pi"` and fill in the protected list.
3. `just doctor`, `just protected-check`, `just scan-dry`.
4. Run the zero-packet test on the Pi: [`docs/runbooks/zero-packet-test.md`](../../docs/runbooks/zero-packet-test.md).
5. Only then enable the timers.

Rust binaries for the Pi are cross-compiled on the Mac with `cross` (generic aarch64, never
`target-cpu=native`) and copied over. They're never built on the Pi.
