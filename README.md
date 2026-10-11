# GnomeHome

A hardened home network detection and response (NDR) system. A Raspberry Pi 3B+ is the sensor and first
responder, Azure is the control plane, and Azure Databricks does analytics and ML. It gives one household the core of a
SOC (inventory, risk scoring, detection, and response) on a $35 computer.

The full project plan, which is the source of truth, is in [`docs/PLAN.md`](docs/PLAN.md).

> **Status:** all eight phases are built. Phases 1 to 3 (inventory, alerts, and risk scoring) are the
> minimum complete project; 4 to 8 add behavior monitoring, a plain-English incident log, the cloud and ML
> layer, the automated Blue Team (in dry run until you turn it on), and the dashboard with the AI check-in.
> Everything was developed and tested on synthetic data before the Pi arrived. Nothing has run on the Pi
> or in Azure yet; [`docs/decisions.md`](docs/decisions.md) lists the open decisions. Developed on an M1 MacBook before the Pi
> arrives. The Pi's system files are written but not yet run on hardware.

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
- **DNS log tailer** (Rust, `crates/gnomehome-dnstail`): follows Pi-hole's log all the time and stores every
  query with its outcome, using a Rust port of the guard (`crates/gnomehome-core`) that passes the same
  shared test vectors as the Python one.
- **Behavior detection**: beaconing (steady check-ins that start after the baseline), bursts of
  machine-generated domain names, lookups of domains on free threat-intel lists, and devices that skip
  Pi-hole for DNS. Each finding becomes a plain-English incident with its MITRE ATT&CK technique.
- **Plain-English incident log**: every incident says when, which device, what happened, why it matters,
  and what to do, with its MITRE ATT&CK technique and a confidence. `just incident-report` writes the log as
  Markdown or JSON, with hostile device names escaped and URLs defanged.
- **Cloud and ML (Phase 6, not deployed)**: a nightly export that re-checks every value against the
  protected list, a write-only upload to Azure storage, Bicep for the Azure side with a $25 budget alert
  ([`infra/`](infra/README.md)), and a Databricks pipeline ([`databricks/`](databricks/README.md)) that runs
  anomaly detection and a device-type classifier. The ML logic is plain Python, so `just ml` runs it locally.
- **Automated Blue Team (Phase 7)**: a Rust playbook engine runs YAML playbooks mapped to MITRE ATT&CK
  ([`playbooks/`](playbooks/)): block a known-bad domain in Pi-hole (automatic), quarantine a device at the
  router (only after you approve), and a weekly self-assessment. It checks the protected list before acting
  and again right before an approved action, stays in dry run until you allow each action, and pushes fixed
  messages (never device names) to the Azure mobile app.
- **Dashboard (Phase 8)**: Rust compiled to WebAssembly (Leptos), served by an Axum API with local accounts,
  Argon2id passwords, a TOTP code at every login, viewer, analyst, and admin roles, CSRF protection, and
  every login and action in the audit log. Approving a response needs an admin with a fresh code. HTTPS is
  required anywhere but loopback. It follows the gnome design system and WCAG 2.2 AA basics.
- **Weekly AI check-in (Phase 8)**: an Azure Container Apps job reads only the week's curated summary and
  writes a plain-English check-in. Device-supplied text is fenced as untrusted data, the output follows a
  strict schema, and any suggestion is re-checked on the Pi and waits for your approval.
- **Router connection data**: the router's connection table, read over SSH with a pinned host key and one
  fixed read-only command, becomes per-connection flow events.
- **Pi deployment files**: systemd timers and services, rsyslog, logrotate, and tmpfiles, rendered from the config
  (`just render-units`, see [`deploy/pi/README.md`](deploy/pi/README.md)).
- **Synthetic data**: a fake household's Pi-hole DNS log and router connection-table snapshots, with
  labeled attack scenarios, for building detections without real traffic.
- **Rust workspace**: the shared core (guard, audit log, database), the DNS tailer, an Axum API stub
  (loopback only), and a playbook-engine stub.

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
just test              # every test should pass (about 455 Python tests plus about 90 Rust tests)
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

### 4. Try the dashboard on synthetic data

```
rustup target add wasm32-unknown-unknown                 # once: lets Rust build for the browser
cargo install wasm-bindgen-cli --version 0.2.129 --locked   # once; match the version in Cargo.lock
just synth && just synth-load && just analyze --dev && just playbook --dev
just web-build
just user-add owner admin --dev       # prints a secret: add it to any authenticator app
just serve --dev                      # then open http://127.0.0.1:8787
```

Both installs go into your user's `~/.rustup` and `~/.cargo`, not system-wide.

### 5. Before the first real scan

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
| `just intel` | Refresh the threat-intel domain lists |
| `just analyze` | DNS analytics: beaconing, DGA bursts, threat-intel hits, DNS bypass (`--dev`) |
| `just new-domains` | Domains each device looked up for the first time (`--hours`, `--dev`) |
| `just flows` | Read the router's connection table over SSH (on the Pi, once router SSH is set up) |
| `just playbook` | Run the playbook engine once (`--dev`); dry run unless `[response]` allows more |
| `just approvals` | Responses waiting for your approval |
| `just approve <run>` / `just deny <run>` | Approve (it acts right away) or deny a waiting response |
| `just playbooks-check` | Validate the playbook files |
| `just self-assess` | The weekly self-assessment: new devices, newly exposed ports, new CVEs |
| `just quarantine` | Block or release a device at the router by hand (dry run unless `--live` and allowed) |
| `just notify` | Deliver queued notifications (fixed messages) |
| `just ml` | Device-type guesses and unusual days, computed locally (`--dev`, `--leave-one-out`) |
| `just summary` | The weekly summary the AI check-in reads, as JSON (`--week-end`, `--dev`) |
| `just export` | Write yesterday's data for the cloud, protected rows dropped (`--day`, `--dev`) |
| `just upload` | Upload an exported day to Azure storage: a dry run unless `--send` |
| `just infra-check` | Compile and lint the Bicep templates (deploys nothing) |
| `just dnstail` | Follow Pi-hole's log into the database (`--once`, `--dev`, `--log`, `--clock utc`) |
| `just incidents` | List open incidents in plain English (`--all`, `--dev`) |
| `just incident-report` | Write the incident log as Markdown or JSON (`--since`, `--format json`, `--out -`, `--all`) |
| `just incident-resolve <id>` | Mark an incident resolved |
| `just synth` | Generate synthetic DNS logs, router flows, and router syslog (`--seed`, `--days`) |
| `just synth-load` | Rebuild the **dev** database from synthetic data, through the real collectors |
| `just migrate` | Create the database or apply migrations (`--dev` for the synthetic DB) |
| `just db-status` | Schema version and row counts (`--dev` for the synthetic DB) |
| `just audit-verify` | Recompute the audit log hash chain and report tampering |
| `just test` | All Python and Rust tests |
| `just lint` / `just fmt` | Lint checks / auto-format |
| `just build` | Build Rust and run `cargo audit` |
| `just build-pi` | Cross-compile the Rust services for the Pi (needs `cross` and Docker) |
| `just render-units` | Render the Pi's systemd, rsyslog, logrotate, and tmpfiles files from the config |
| `just web-build` | Build the dashboard (Rust to WebAssembly) into `web/dist` |
| `just user-add <name> <role>` | Create a dashboard account (`viewer`, `analyst`, `admin`) and its authenticator secret |
| `just serve` | Run the dashboard on `127.0.0.1:8787` (`--dev` for the synthetic database) |
| `just web-e2e` | Drive the dashboard in a headless browser (see `crates/gnomehome-web/e2e/dashboard.js`) |
| `just checkin-fetch` | Import the weekly AI check-in and its suggestions |

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
unlisted IP, or an unknown MAC takes its reserved IP. The DNS tailer drops the laptop's queries, reverse
lookups of its address, and names that embed its address or MAC. The router flow pull drops any connection
with the laptop at either end, including through a port forward. The nightly export re-checks every value of
every row before anything leaves the Pi, and the protected list itself never leaves the Pi. The playbook
engine refuses a protected target before asking for approval and again right before acting, the Python
quarantine helper checks once more, and the schema refuses any run or quarantine aimed at one.

The audit log names protected devices by label only, never by MAC or IP. A test scans every committed file
for real-looking IPs and MACs.

## Repository layout

| Path | What lives there |
| --- | --- |
| `python/gnomehome/` | Python jobs: config, guard, database, audit log, nmap job, synthetic data |
| `python/tests/` | Python tests (`just test-py`) |
| `crates/` | Rust workspace: `gnomehome-core` (guard, audit, DB), `gnomehome-dnstail`, `gnomehome-playbook` (the engine), `gnomehome-api` (Axum, accounts), `gnomehome-web` (Leptos dashboard) |
| `playbooks/` | The YAML playbooks, each mapped to MITRE ATT&CK |
| `config/` | `*.example.*` files with fake values; your real copies are gitignored |
| `testdata/` | Contract vectors shared by Python and Rust (guard cases, audit hashes) |
| `deploy/pi/` | Linux-only pieces for the Pi (systemd, capabilities, LUKS, firewall) |
| `deploy/checkin/` | The AI check-in job's container image |
| `web/dist/` | The built dashboard (gitignored; `just web-build`) |
| `infra/` | Bicep for the Azure side (not deployed) |
| `databricks/` | The Databricks bundle: nightly bronze, silver, gold, ML, and summary jobs (not deployed) |
| `docs/` | Plan, decisions, audit log spec, risk model, runbooks |
| `data/` | Databases, scan output, synthetic data (gitignored) |
| `pihole/` | Your local Pi-hole Docker setup (not tracked) |
