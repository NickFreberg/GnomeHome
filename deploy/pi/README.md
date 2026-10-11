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
| `gnomehome-enrich.service` / `.timer` | `/etc/systemd/system/` | Daily at `enrich_daily_at`: CVEs from NVD, EPSS, KEV, then risk scores |
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
- **No network for the syslog job.** It reads one local file, so it runs with `PrivateNetwork=yes` and no capabilities.
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
sudo systemctl enable --now gnomehome-syslog.timer gnomehome-discover.timer gnomehome-scan.timer gnomehome-enrich.timer
systemctl list-timers 'gnomehome-*'
```

## Still to do on the Pi

- Host firewall (nftables): UDP 514 only from the router, SSH and the dashboard only from the LAN (R-01)
- LUKS full-disk encryption with Adiantum (NFR-03), key-only SSH
- Pi-hole installed natively (no Docker on the Pi), per Phase 1

Rust binaries for the Pi are cross-compiled on the Mac with `cross` (generic aarch64, never
`target-cpu=native`) and copied over. They're never built on the Pi.
