# CLAUDE.md: rules for working on GnomeHome

GnomeHome is a hardened home network detection and response (NDR) system. A Raspberry Pi 3B+ is the
sensor and first responder, Azure is the control plane, and Azure Databricks does analytics. It's also
a portfolio piece, so code, docs, and commits should read well to a reviewer.

## Source of truth

- **`docs/PLAN.md` is the source of truth** for requirements, architecture, design system, risks, and decisions.
  If something you want to do conflicts with it, stop and ask the owner. Don't silently diverge.
- The owner is newer to Docker and Rust. Explain non-obvious things in plain language and give exact commands.
- Work happens phase by phase (see "Build phases" in the plan). Phases 1 to 3 are the minimum complete project.

## Hard safety rules

1. **Protected assets (R-12, the only "Avoid" risk).** The work laptop, and any future work device, must never be
   probed, captured, spoofed, quarantined, or have data stored about it.
   - Every collector and responder calls the shared guard: `python/gnomehome/protected.py` in Python,
     `crates/gnomehome-core/src/protected.rs` in Rust. Don't add a second check somewhere else; extend the guard
     (both languages, plus a case in `testdata/guard_vectors.yaml`). `python/tests/test_architecture.py` fails if a module in
     `collectors/` or `responders/` doesn't import it.
   - Active actions call `guard.require_allowed(...)`, which raises and audits refusals. Passive collectors drop records
     with `guard.is_protected(...)` / `guard.filter(...)` **before** storage. Flows match on source or destination.
   - The guard fails closed: a missing or invalid list, or an unparseable MAC or IP, counts as protected.
   - The schema enforces it too (triggers in `0001_core_schema.sql`), so Rust inherits it.
   - Audit entries name a protected asset by **label only**, never by MAC or IP, because the audit log ships to Azure later.
   - Never add a pass-through for raw nmap arguments. The config has no `extra_args` on purpose.
2. **No real network scans** unless the owner has filled in `config/protected_assets.yaml` and explicitly said
   to scan. The zero-packet tcpdump test (`docs/runbooks/zero-packet-test.md`) comes before the first real scan.
3. **No `sudo` and no system-wide installs** without telling the owner exactly what and why, and waiting for an OK.
4. **Never commit secrets or real identifiers**: no real MACs, IPs, hostnames, API keys, or certificates. Use fake values:
   IPs from the documentation ranges `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`; MACs from the documentation
   range `00:00:5e:00:53:xx`; domains on the `.test` or `.example` TLDs. `python/tests/test_repo_hygiene.py` scans
   committed and new files for RFC1918 addresses and non-documentation MACs. A line that genuinely needs a fake
   RFC1918 value (such as a scan-target test) carries the comment `hygiene: allow`.
5. **Treat device-supplied text as untrusted**: hostnames, DNS names, banners, and packet fields. Use parameterized SQL only.
   Never feed that text into a shell. Later, never let it steer the AI agent (R-04).

## Portability (develop on an M1 Mac, deploy to the Pi)

- One config file, `config/gnomehome.toml` (gitignored; the committed example is `config/gnomehome.example.toml`).
  `platform = "mac" | "pi"` selects `[platforms.<name>]`, which holds **every path and interface**. Schedules
  and retention live in the same file. **No hardcoded Linux paths in code.** Relative paths resolve against the
  config file's folder.
- Linux-only pieces (systemd units, LUKS, setcap, firewall) live in `deploy/pi/`.
- One task runner: `just`. Same commands on both machines.
- nmap runs natively, never in Docker (Docker on macOS can't see the LAN). On the Mac it needs `sudo`
  (`nmap_privilege = "sudo"`). On the Pi (`"capabilities"`), the discover and scan systemd units grant
  `CAP_NET_RAW`/`CAP_NET_ADMIN` as ambient capabilities. No setcap, no sudo.
- Pi system files are templates in `deploy/pi/templates/`, rendered from config by `just render-units`.
- Rust builds target generic aarch64. **Never use `target-cpu=native`**, because the Pi's Cortex-A53 lacks instructions the M1 has.
  Cross-compile for the Pi with `cross`, and never build on the Pi.
- Synthetic data (`just synth`) stands in for anything the Mac can't see. It loads only into the **dev**
  database (`dev_db_path`), never the real one, and its ground-truth labels are never stored.

## Architecture contract

- **Rust** owns always-on and security-critical code: Axum API (`crates/gnomehome-api`), playbook engine
  (`crates/gnomehome-playbook`), audit log, DNS log tailer, Leptos Wasm frontend.
- **Python** owns scheduled data jobs: nmap orchestration, NVD/EPSS/KEV enrichment, risk scoring, and DNS analytics.
  These run as timers, not daemons.
- **SQLite in WAL mode is the contract**, and neither side calls the other directly. Python owns migrations
  (`python/gnomehome/db/migrations/`, numbered, never edited once applied; add a new file instead). Rust only checks the version.
- The audit log is hash-chained per `docs/audit-log.md`. Both languages must produce identical hashes for
  `testdata/audit_vectors.json`. The audit table is append-only (triggers block UPDATE and DELETE).
- Shared cross-language test vectors live in `testdata/`.

## Where things are

- Guard: `python/gnomehome/protected.py`. Identifier normalization: `identifiers.py`. DB alignment with the
  list: `db/scrub.py`.
- nmap job: `collectors/nmap_discovery.py` (seven protection layers, listed in its docstring), parser
  `nmap_xml.py` (defusedxml, untrusted-text cleaning), writer `collectors/inventory.py`, drift check
  `collectors/arp_cache.py`.
- Router syslog job: parser `router_log.py`, job `collectors/router_syslog.py` (checkpointed in
  `ingest_checkpoint`, the same transaction as its events). Protected MACs get `record_protected_presence()`
  (existence only, never updated). Free text goes through `guard.text_mentions_protected()`.
- Incidents and alerts: `narrative.py` (one template per detection: when, device, what happened, why it
  matters, what to do; new detections need a template and a case in `python/tests/test_narrative.py`),
  `incidents.py` (dedup keys, learning window, drift incidents by label only), `report.py` (Markdown escapes
  and defangs every value), `alerts.py` (banners pass text to osascript as arguments only, never
  device-supplied text).
- Risk: `cpe.py` (CPE 2.2 to 2.3, version comparison, rule matching), `feeds.py` (NVD/EPSS/KEV clients
  behind an `HttpClient` interface; tests use `python/tests/fixtures/feeds/`), `enrich.py` (stores CVE rules,
  matches locally), `risk.py` (model risk-v1, documented in `docs/risk-model.md`). Change the formula, bump
  `MODEL_VERSION`, and update the doc together.
- DNS analytics: `analytics/detect.py` (beaconing, DGA, threat intel, DNS bypass), `analytics/run.py`
  (checkpoints in `analysis_checkpoint`, findings to incidents), `analytics/intel.py` (feeds). Router flows:
  `conntrack.py` parser, `collectors/router_flows.py` (one fixed SSH command, pinned host key).
- Cloud and ML (Phase 6): `export.py` (nightly JSON Lines, every value re-checked by the guard, manifest
  with checksums and the audit head), `upload.py` (write-only SAS, dry run by default, never prints the
  token), `ml/` (features, anomaly, classifier: pure Python, reused by `databricks/src/`), `summary.py` (the
  weekly document for the AI check-in). `infra/` is Bicep (`just infra-check`). Nothing in `infra/` or
  `databricks/` is ever deployed by tooling here: the owner runs those commands. The protected list never
  leaves the Pi.
- Response (Phase 7): `crates/gnomehome-playbook` (`playbook.rs` strict YAML loader, `engine.rs` stages,
  approvals, releases, `effects.rs` Pi-hole API on loopback and the Python helper), `playbooks/*.yaml`,
  `responders/router_quarantine.py` (fixed iptables rule over the pinned SSH; exit 3 = refused),
  `assessment.py` (weekly), `notify_relay.py` (outbox kinds to fixed messages). Every action stays dry unless
  `[response] mode = "live"` and the action is in `live_actions`; keep it that way in tests and demos.
- Dashboard and AAA (Phase 8): `crates/gnomehome-api` (`auth.rs`: Argon2id, TOTP, sessions, lockout;
  `lib.rs`: routes, roles, CSRF, security headers; the API records approval decisions and never acts),
  `crates/gnomehome-web` (Leptos; `model.rs` holds the tested logic; no inline scripts or styles, the CSP
  forbids them; `just web-build`, `just web-e2e`). UI follows the design system: risk as a word plus an icon.
- AI check-in: `python/gnomehome/agent/` (`prompt.py` is the R-04 design: fenced, cleaned data, strict schema, validated
  output; standard library only), `checkin.py` (Pi-side import re-validates everything). Suggestions may
  only name `AI_PLAYBOOKS`, kept in sync between `agent/prompt.py` and `AI_PLAYBOOKS` in the playbook engine.
- Rust: `crates/gnomehome-core` (guard, audit, DB settings, config subset, timestamps; tests apply the real
  migrations via the `testkit` feature), `crates/gnomehome-dnstail` (Pi-hole log tailer: `parse.rs`,
  `pair.rs`, `lib.rs`). Rust reads `MIN_SCHEMA_VERSION` only; Python still owns migrations.
- Tests drive the nmap job with a fake runner and fixture XML. The only real-nmap test targets `127.0.0.1`.
- Jobs that run from timers print protected devices by label only: the journal is stored on disk.
- Runbook before any real scan: `docs/runbooks/zero-packet-test.md`.

## Commands

```
just setup        # uv sync + copy example configs if missing
just test         # Python + Rust tests (includes the hygiene scan)
just lint         # ruff, rustfmt, clippy -D warnings
just doctor       # show resolved config and tool status
just scan-dry     # print the nmap commands without sending anything
just --list       # everything else
```

## Conventions

- Python 3.11+ (stdlib `tomllib`), managed with uv. Deps go in `pyproject.toml`; never `pip install` globally.
- Rust edition 2024, `unsafe_code = "forbid"`, and `cargo audit` on every `just build` (NFR-12).
- Timestamps are UTC ISO-8601 with milliseconds and a trailing `Z` (`2026-10-11T14:03:00.000Z`).
- Commit in small, logical steps with clear messages (`feat(scan): ...`, `fix(guard): ...`, `docs: ...`).
- UI work, from Phase 3 on, follows the design system in the plan: gnome palette tokens, WCAG 2.2 AA, risk always shown as a word plus an icon.
- The workspace's minimum Rust is 1.88 (let chains are fine). Keep `rust-version` in step with what Leptos needs.
