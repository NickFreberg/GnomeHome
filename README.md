# GnomeHome

A hardened home network detection and response (NDR) system. A Raspberry Pi 3B+ is the sensor and first
responder, Azure is the control plane, and Azure Databricks does analytics and ML. It gives one household the core of a
SOC (inventory, risk scoring, detection, and response) on a $35 computer.

The full project plan, which is the source of truth, is in [`docs/PLAN.md`](docs/PLAN.md).

> **Status:** Phases 1 to 3 (the minimum complete project: inventory, alerts, vulnerability risk
> scoring), developed on an M1 MacBook before the Pi arrives. The Pi's system files are written but
> not yet run on hardware.

## What's here so far

- **One config file** (`config/gnomehome.toml`) with a `platform = "mac" | "pi"` switch holding every path,
  interface, schedule, and retention window. No hardcoded Linux paths in code.
- **The protected-asset guard** (`python/gnomehome/protected.py`): the do-not-touch list for the work
  laptop, enforced by every collector and responder, by the database schema itself, and by the scan job at
  several layers. It fails closed.
- **SQLite schema** in WAL mode with checksummed migrations: assets, services, CVEs and vulnerabilities, daily
  risk scores, events, incidents, scan runs, and a **hash-chained, append-only audit log**
  ([spec](docs/audit-log.md)).
- **nmap discovery job**: host discovery plus a service scan into the asset inventory, built so it never
  sends a packet to a protected device.
- **Router syslog job**: the router's DHCP messages feed the inventory within a minute or two, with no
  router password stored. Firewall and other router lines are kept as events.
- **Alerts**: plain-English incidents for new devices (after a learning window) and for a protected device
  that shows up somewhere unexpected, plus a macOS banner on the Mac. Push to the iPhone comes in Phase 7.
- **Risk scoring**: CVEs from NVD re-checked against each software version, EPSS exploitation odds,
  and CISA's known-exploited list, combined into a daily 0–100 score per device. Every point is
  explained in plain words ([risk model](docs/risk-model.md)).
- **Pi deployment files**: systemd timers, rsyslog, logrotate, and tmpfiles, rendered from the config
  (`just render-units`, see [`deploy/pi/README.md`](deploy/pi/README.md)).
- **Synthetic data**: a fake household's Pi-hole DNS log and router connection-table snapshots, with
  labeled attack scenarios, for building detections without real traffic.
- **Rust workspace**: Axum API stub (loopback only) and playbook-engine stub.

## Quick start on the Mac

### 1. Tools (one time)

| Tool | Why | Install |
| --- | --- | --- |
| Homebrew | The standard Mac package manager (skip if `brew --version` works) | see [brew.sh](https://brew.sh) |
| uv | Runs Python and keeps this project's packages in `.venv/`, not system-wide | `brew install uv` |
| just | The task runner, so `just scan` works the same on the Mac and the Pi | `brew install just` |
| nmap | The network scanner. Runs natively, never in Docker | `brew install nmap` |
| Rust | For the API and playbook crates. Installs into `~/.rustup` and `~/.cargo` (your user only) | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| cargo-audit | Checks Rust dependencies for known vulnerabilities on every build | `cargo install cargo-audit --locked` |

### 2. Put the code in `~/gnomehome` (next to your Pi-hole folder)

`~/gnomehome` already holds your Pi-hole Docker setup in `pihole/`. These commands turn the folder into a
copy of this repository without touching `pihole/`:

```
cd ~/gnomehome
git init
git remote add origin https://github.com/NickFreberg/GnomeHome.git
git fetch origin
git checkout -b phase-1-foundation --track origin/phase-1-foundation
```

`pihole/etc-pihole/` (Pi-hole's data and DNS logs) is ignored by git. `pihole/docker-compose.yml` shows up
as untracked. It holds no secrets, so commit it if you want it versioned, or leave it.

### 3. Set up and check

```
just setup             # installs Python deps into .venv, creates your config files from the examples
just test              # every test should pass (about 300 Python tests plus Rust)
```

Then edit two files, which git ignores:

- `config/gnomehome.toml`: set `scan_targets` and `lan_cidrs` to your home network (the router's subnet,
  usually a `/24`) and check `interface` (Wi-Fi on a MacBook is usually `en0`; `ifconfig` lists them).
- `config/protected_assets.yaml`: replace the fake values with the work laptop's real MACs (from
  `ipconfig /all` on the laptop: Wi-Fi **and** dock) and its reserved IP. Keep the quotes.

```
just protected-check   # validates the list without printing any MAC or IP
just doctor            # shows the resolved config and which tools are installed
just scan-dry          # prints the exact nmap commands; sends nothing
```

### 4. Before the first real scan

Run the **zero-packet test**: [`docs/runbooks/zero-packet-test.md`](docs/runbooks/zero-packet-test.md).
It captures packets during a scan and proves nothing reaches the work laptop.

## Commands

| Command | What it does |
| --- | --- |
| `just` | List every command |
| `just setup` | Install Python deps into `.venv/`, copy example configs if missing (never overwrites) |
| `just doctor` | Show resolved config and check tools |
| `just protected-check` | Validate the protected list (prints labels and counts, never identifiers) |
| `just protected-filter` | Print the tcpdump filter for the zero-packet test |
| `just scan-dry` | Show exactly what `just scan` would run, without sending anything |
| `just discover` | Host discovery only (quick, for new-device detection). Uses sudo on the Mac |
| `just scan` | Host discovery plus service scan. Uses sudo on the Mac |
| `just syslog` | Read new router syslog lines: DHCP into the inventory, alerts (on the Pi) |
| `just enrich` | Fetch CVEs (NVD), EPSS, and KEV, and match them to scanned software |
| `just score` | Compute today's risk score for every device |
| `just risks` | The riskiest devices and the reasons behind each score |
| `just incidents` | List open incidents: new devices, protected-device drift (`--all`, `--dev`) |
| `just incident-resolve <id>` | Mark an incident resolved |
| `just synth` | Generate synthetic DNS logs, router flows, and router syslog (`--seed`, `--days`) |
| `just synth-load` | Rebuild the **dev** database from synthetic data, through the real collectors |
| `just migrate` | Create the database or apply migrations (`--dev` for the synthetic DB) |
| `just db-status` | Schema version and row counts (`--dev` for the synthetic DB) |
| `just audit-verify` | Recompute the audit log hash chain and report tampering |
| `just test` | All Python and Rust tests |
| `just lint` / `just fmt` | Lint checks / auto-format |
| `just build` | Build Rust and run `cargo audit` |
| `just render-units` | Render the Pi's systemd, rsyslog, logrotate, and tmpfiles files from the config |
| `just serve` | Run the API stub on `127.0.0.1:8787` (try `curl 127.0.0.1:8787/healthz`) |

## How the protected-asset list is enforced

The work laptop must never be probed, captured, spoofed, quarantined, or stored (risk R-12). Each
layer below works on its own:

1. Nothing runs without a valid list, and a real scan refuses the example values.
2. Scan targets must be private home ranges and never a protected IP.
3. Before scanning, the ARP cache (read-only, sends nothing) is checked for the laptop at an unexpected IP.
4. Every nmap call gets `--excludefile` with every protected IP, so nmap drops them before sending anything.
5. Right before each nmap call, the command line and exclude file are re-checked.
6. If discovery still reports a protected device, the job stops before the service scan and stores nothing.
7. The database schema refuses to store services, events, scores, or incidents for a protected device.

Passive collectors follow the same list. The router syslog job records only that the laptop exists,
drops any line that mentions it, and opens a label-only "drift" incident if the laptop's MAC shows up at an
unlisted IP, or an unknown MAC takes its reserved IP.

The audit log names protected devices by label only, never by MAC or IP. A test scans every committed file
for real-looking IPs and MACs.

## Repository layout

| Path | What lives there |
| --- | --- |
| `python/gnomehome/` | Python jobs: config, guard, database, audit log, nmap job, synthetic data |
| `python/tests/` | Python tests (`just test-py`) |
| `crates/` | Rust workspace: `gnomehome-api` (Axum) and `gnomehome-playbook` |
| `config/` | `*.example.*` files with fake values; your real copies are gitignored |
| `testdata/` | Contract vectors shared by Python and Rust (guard cases, audit hashes) |
| `deploy/pi/` | Linux-only pieces for the Pi (systemd, capabilities, LUKS, firewall) |
| `docs/` | Plan, audit log spec, runbooks |
| `data/` | Databases, scan output, synthetic data (gitignored) |
| `pihole/` | Your local Pi-hole Docker setup (not tracked) |
