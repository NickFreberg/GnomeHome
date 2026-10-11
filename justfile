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

# Install Python deps into .venv
setup:
    uv sync

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
