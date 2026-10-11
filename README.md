# GnomeHome

A hardened home network detection and response (NDR) system. A Raspberry Pi 3B+ is the sensor and first
responder, Azure is the control plane, and Azure Databricks does analytics and ML. It gives one household the core of a
SOC (inventory, risk scoring, detection, and response) on a $35 computer.

The full project plan, which is the source of truth, is in [`docs/PLAN.md`](docs/PLAN.md).

> **Status:** Phase 1 foundation and the start of Phase 2 (asset inventory), developed on an M1 MacBook
> before the Pi arrives.

## Repository layout

| Path | What lives there |
| --- | --- |
| `python/gnomehome/` | Python jobs: config, protected-asset guard, SQLite schema, nmap discovery, synthetic data |
| `python/tests/` | Python tests (`just test-py`) |
| `crates/` | Rust workspace: Axum API stub and playbook engine stub |
| `config/` | `*.example.*` config files with fake values. Your real copies are gitignored |
| `testdata/` | Test vectors shared by Python and Rust |
| `deploy/pi/` | Linux-only pieces for the Pi (systemd, setcap, LUKS, firewall) |
| `docs/` | Plan, specs, and runbooks |
| `pihole/` | Your local Pi-hole Docker setup (not tracked; `pihole/etc-pihole/` is gitignored) |

## Commands

Run `just` to list everything.
