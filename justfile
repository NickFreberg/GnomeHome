# GnomeHome task runner. Same commands on the Mac and the Pi.
# Run `just` with no arguments to list everything.
#
# Every Python job runs through `uv run`, which uses the project's own
# virtual environment in .venv/ (nothing is installed system-wide).

set shell := ["bash", "-euo", "pipefail", "-c"]

gnomehome := "uv run gnomehome"

# List available commands
default:
    @just --list --unsorted

# ---------------------------------------------------------------- setup ----

# Install Python deps into .venv and copy the example configs (never overwrites)
setup:
    uv sync
    @if [ ! -f config/gnomehome.toml ]; then cp config/gnomehome.example.toml config/gnomehome.toml && echo "Created config/gnomehome.toml from the example. Edit scan_targets, lan_cidrs, and interface for your network."; else echo "config/gnomehome.toml already exists, left alone."; fi
    @if [ ! -f config/protected_assets.yaml ]; then cp config/protected_assets.example.yaml config/protected_assets.yaml && echo "Created config/protected_assets.yaml from the example. Swap in your work laptop's real MACs and reserved IP before any scan."; else echo "config/protected_assets.yaml already exists, left alone."; fi

# Show the resolved config and check that required tools are installed
doctor:
    {{gnomehome}} doctor

# ------------------------------------------------------- protected assets --

# Validate config/protected_assets.yaml (prints labels and counts, never values)
protected-check:
    {{gnomehome}} protected-check

# Print the tcpdump capture filter for the zero-packet test
protected-filter:
    {{gnomehome}} protected-filter

# ---------------------------------------------------------------- scanning --
# Real scans send packets on your network. Fill in config/protected_assets.yaml
# and run the zero-packet test (docs/runbooks/zero-packet-test.md) first.

# Host discovery + service scan with nmap (on the Mac: asks for your password for sudo)
scan:
    {{gnomehome}} scan

# Host discovery only (quick; for new-device detection)
discover:
    {{gnomehome}} discover

# Show exactly what `just scan` would run, without sending anything
scan-dry:
    {{gnomehome}} scan --dry-run

# Read new router syslog lines: DHCP into the inventory, new-device and drift alerts (Pi)
syslog:
    {{gnomehome}} syslog

# ------------------------------------------------------------- synthetic --

# Generate synthetic DNS logs and router flows (fake household, reproducible)
synth *args:
    {{gnomehome}} synth {{args}}

# Load the synthetic data into the dev database (never the real one), through the guard
synth-load *args:
    {{gnomehome}} synth-load {{args}}

# -------------------------------------------------------------- database --

# Create the SQLite database or apply pending migrations (--dev for the synthetic DB)
migrate *args:
    {{gnomehome}} migrate {{args}}

# Show schema version and row counts (--dev for the synthetic DB)
db-status *args:
    {{gnomehome}} db-status {{args}}

# List open incidents: new devices, protected-device drift (--all, --dev)
incidents *args:
    {{gnomehome}} incidents {{args}}

# Mark an incident resolved, e.g. `just incident-resolve 3`
incident-resolve id *args:
    {{gnomehome}} incident-resolve {{id}} {{args}}

# Recompute the audit log's hash chain and report any tampering
audit-verify *args:
    {{gnomehome}} audit-verify {{args}}

# ---------------------------------------------------------------- quality --

# Run every test: Python and Rust
test: test-py test-rs

# Python tests only (pass extra pytest args, e.g. `just test-py -k guard`)
test-py *args:
    uv run pytest {{args}}

# Rust tests only
test-rs:
    cargo test --workspace

# Lint and format checks (no changes made)
lint:
    uv run ruff check python
    uv run ruff format --check python
    cargo fmt --all --check
    cargo clippy --workspace --all-targets -- -D warnings

# Auto-format Python and Rust
fmt:
    uv run ruff check --fix python
    uv run ruff format python
    cargo fmt --all

# ------------------------------------------------------------------ rust ---

# Build the Rust workspace, then check dependencies for known vulnerabilities (NFR-12)
build:
    cargo build --workspace
    @command -v cargo-audit >/dev/null || { echo "cargo-audit is not installed. Install it once with: cargo install cargo-audit --locked"; exit 1; }
    cargo audit

# Run the API stub on loopback (address from [api].bind in config/gnomehome.toml)
serve:
    cargo run --package gnomehome-api
