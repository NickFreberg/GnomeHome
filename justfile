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

# Run every test
test: test-py

# Python tests only (pass extra pytest args, e.g. `just test-py -k guard`)
test-py *args:
    uv run pytest {{args}}

# Lint and format checks (no changes made)
lint:
    uv run ruff check python
    uv run ruff format --check python

# Auto-format Python
fmt:
    uv run ruff check --fix python
    uv run ruff format python
