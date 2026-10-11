# deploy/pi: Linux-only pieces for the Raspberry Pi

Everything in GnomeHome runs on the Mac except what lives here. Nothing in this folder is used on the Mac.

> **Status: written before the Pi arrived, not yet run on real hardware.** `systemd-analyze verify`
> passes on the rendered units. The rsyslog and logrotate files couldn't be checked yet. Expect small
> fixes on the first install.

## What's here

`templates/` holds the Pi's system files. `just render-units` fills them from `config/gnomehome.toml`
(the `[platforms.pi]` table, `[schedules]`, `[retention]`, and `[network] router_ip`), so no path,
user, schedule, or IP is hardcoded.

| Rendered file | Installed as | What it does |
| --- | --- | --- |
| `gnomehome-discover.service` / `.timer` | `/etc/systemd/system/` | Host discovery every `discovery_every_minutes` |
| `gnomehome-scan.service` / `.timer` | `/etc/systemd/system/` | Service scan every `service_scan_every_minutes` |
| `gnomehome-syslog.service` / `.timer` | `/etc/systemd/system/` | Router syslog ingest every `syslog_every_minutes` (DHCP, new-device and drift alerts) |
| `gnomehome-enrich.service` / `.timer` | `/etc/systemd/system/` | Daily at `enrich_daily_at`: CVEs from NVD, EPSS, KEV, threat-intel feeds, then risk scores |
| `gnomehome-analyze.service` / `.timer` | `/etc/systemd/system/` | DNS analytics every `analyze_every_minutes` (beaconing, DGA, threat intel, DNS bypass) |
| `gnomehome-flows.service` / `.timer` | `/etc/systemd/system/` | Router connection-table pull over SSH every `flows_every_minutes` |
| `gnomehome-dnstail.service` | `/etc/systemd/system/` | Always on: follows `pihole_log` into the database (the Rust tailer) |
| `gnomehome-export.service` / `.timer` | `/etc/systemd/system/` | Nightly at `upload_nightly_at`: export yesterday (protected rows dropped) and upload it if `[cloud]` is configured |
| `tmpfiles-gnomehome.conf` | `/etc/tmpfiles.d/gnomehome.conf` | Creates the data, scans, and run folders at boot |
| `rsyslog-gnomehome.conf` | `/etc/rsyslog.d/30-gnomehome.conf` | Accepts the router's syslog (UDP 514, from `router_ip` only) into `router_syslog_path` |
| `logrotate-gnomehome` | `/etc/logrotate.d/gnomehome` | Keeps `retention.syslog_days` of raw router syslog |

**How the services are locked down:**

- **One unprivileged user.** Every job runs as the unprivileged `service_user`, with `ProtectSystem=strict`,
  `NoNewPrivileges`, a system-call filter, `MemoryMax=256M`, and write access only to the data and run folders.
- **Raw-socket rights for the nmap jobs only.** nmap needs `CAP_NET_RAW` and `CAP_NET_ADMIN` to see MAC
  addresses. Only the discover and scan units get them, as *ambient capabilities* that nmap inherits.
  That's the plan's "capabilities only to what needs them", without `setcap` on the system nmap binary,
  which would let any user on the Pi send raw packets. No sudo is involved.
- **No network where none is needed.** The syslog, analyze, and DNS tailer services work on local files and the
  database only, so they run with `PrivateNetwork=yes` and no capabilities. The flows service may reach the
  router's address and nothing else (`IPAddressAllow=router_ip`).
- **The always-on tailer is small.** `MemoryMax=64M`, and it joins `pihole_log_group` only to read Pi-hole's log.
  If the protected-asset list becomes invalid, it stops instead of running unguarded, and systemd keeps
  retrying every 30 seconds so the failure shows in `systemctl status`.
- **A busy lock is a quiet skip.** Exit code 75 ("another scan holds the lock") counts as success, so the
  discover and scan timers can overlap.

## Install on the Pi (Monday)

Run these on the Pi (Raspberry Pi OS Lite 64-bit). Each `sudo` line changes the system. Read it before running it.

**1. Packages, service user, folders**

```
sudo apt update && sudo apt install -y git nmap rsyslog tcpdump
sudo useradd --system --home-dir /var/lib/gnomehome --shell /usr/sbin/nologin gnomehome
sudo install -d -o root -g gnomehome -m 0750 /etc/gnomehome
```

rsyslog is no longer installed by default on recent Raspberry Pi OS, and GnomeHome needs it to receive the
router's syslog.

**2. Code and Python environment**

```
curl -LsSf https://astral.sh/uv/install.sh | sh          # installs uv for your user
sudo git clone https://github.com/NickFreberg/GnomeHome.git /opt/gnomehome
cd /opt/gnomehome && sudo git checkout phase-1-foundation
sudo ~/.local/bin/uv sync --no-dev --python /usr/bin/python3
```

`--python /usr/bin/python3` uses the Pi's own Python (3.11 or newer). That keeps the interpreter outside
your home folder, which the services can't see (`ProtectHome=yes`).

**3. Config and protected list**

```
sudo install -o root -g gnomehome -m 0640 config/gnomehome.example.toml /etc/gnomehome/gnomehome.toml
sudo install -o root -g gnomehome -m 0640 config/protected_assets.example.yaml /etc/gnomehome/protected_assets.yaml
sudo nano /etc/gnomehome/gnomehome.toml          # platform = "pi", your LAN, router_ip
sudo nano /etc/gnomehome/protected_assets.yaml   # the laptop's real MACs and reserved IP
```

Optional: put your free NVD API key in `/etc/gnomehome/nvd_api_key` (`root:gnomehome`, mode `0640`).
Enrichment works without it, just more slowly.

**4. Render and install the system files**

```
sudo GNOMEHOME_CONFIG=/etc/gnomehome/gnomehome.toml /opt/gnomehome/.venv/bin/gnomehome render-units --out ~/gnomehome-units
cd ~/gnomehome-units
sudo install -m 0644 gnomehome-*.service gnomehome-*.timer /etc/systemd/system/
sudo install -m 0644 tmpfiles-gnomehome.conf /etc/tmpfiles.d/gnomehome.conf
sudo install -m 0644 rsyslog-gnomehome.conf /etc/rsyslog.d/30-gnomehome.conf
sudo install -m 0644 logrotate-gnomehome /etc/logrotate.d/gnomehome
sudo systemd-tmpfiles --create /etc/tmpfiles.d/gnomehome.conf
sudo rsyslogd -N1 && sudo systemctl restart rsyslog       # -N1 checks the config first
sudo systemctl daemon-reload
```

**5. Database and checks, as the service user**

```
G="sudo -u gnomehome env GNOMEHOME_CONFIG=/etc/gnomehome/gnomehome.toml /opt/gnomehome/.venv/bin/gnomehome"
$G migrate
$G doctor
$G protected-check
$G scan --dry-run
```

**5b. Rust binaries (built on the Mac)**

The DNS tailer is Rust. Build it on the Mac for the Pi's CPU, then copy it over. `cross` builds inside a
Docker container, so Docker Desktop must be running. On the **Mac**:

```
cargo install cross --locked     # once; installs into ~/.cargo/bin (no sudo)
just build-pi                    # target/aarch64-unknown-linux-gnu/release/
scp target/aarch64-unknown-linux-gnu/release/gnomehome-dnstail <you>@<pi>:
```

Then on the **Pi**:

```
sudo install -D -o root -g root -m 0755 ~/gnomehome-dnstail /opt/gnomehome/bin/gnomehome-dnstail
ls -l /var/log/pihole/pihole.log     # check the group matches pihole_log_group (usually pihole)
sudo -u gnomehome env GNOMEHOME_CONFIG=/etc/gnomehome/gnomehome.toml /opt/gnomehome/bin/gnomehome-dnstail --once
```

The `--once` run should report queries stored. If it reports a permission error, the log's group differs
from `pihole_log_group`: fix the config and render the units again.

**6. Point the router's syslog at the Pi**

In the router: **Administration**, then **System**, then set **Remote Log Server** to the Pi's IP. Check that lines arrive:

```
sudo tail -f /var/log/gnomehome/router.log
sudo systemctl start gnomehome-syslog.service && journalctl -u gnomehome-syslog -n 20
```

**7. Zero-packet test on the Pi**

Do this **before enabling any scan timer**: [`docs/runbooks/zero-packet-test.md`](../../docs/runbooks/zero-packet-test.md).
On the Pi, the scan in step 3 of that runbook is `sudo systemctl start gnomehome-scan.service`.

**8. Turn on the schedules**

```
sudo systemctl enable --now gnomehome-dnstail.service
sudo systemctl enable --now gnomehome-syslog.timer gnomehome-discover.timer gnomehome-scan.timer gnomehome-enrich.timer gnomehome-analyze.timer
systemctl list-timers 'gnomehome-*'
```

**9. Optional: router connection data (FR-08)**

Phases 1 to 3 don't need this (risk R-06: a firmware update can break it). In the router, enable SSH
(**Administration**, then **System**: LAN only, port 22, key login only). Then on the Pi:

```
sudo -u gnomehome ssh-keygen -t ed25519 -N "" -f /var/lib/gnomehome/router_ssh_key
sudo cat /var/lib/gnomehome/router_ssh_key.pub       # paste into the router's Authorized Keys
ssh-keyscan -t ed25519 <router_ip> | sudo tee /etc/gnomehome/router_known_hosts
sudo install -o gnomehome -g gnomehome -m 0600 /var/lib/gnomehome/router_ssh_key /etc/gnomehome/router_ssh_key
```

Compare the key `ssh-keyscan` printed with the one the router shows, if it shows one: that file is what stops
anyone else from impersonating the router later. Then `sudo systemctl start gnomehome-flows.service`, check
`journalctl -u gnomehome-flows -n 20`, and enable `gnomehome-flows.timer`.

## Still to do on the Pi

- Host firewall (nftables): UDP 514 only from the router, SSH and the dashboard only from the LAN (R-01)
- LUKS full-disk encryption with Adiantum (NFR-03), key-only SSH
- Pi-hole installed natively (no Docker on the Pi), per Phase 1

Rust binaries for the Pi are cross-compiled on the Mac with `cross` (generic aarch64, never
`target-cpu=native`) and copied over (step 5b). They're never built on the Pi.
