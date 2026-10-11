"""Command-line entry point: ``gnomehome <command>``.

The justfile wraps these commands so they are the same on the Mac and the Pi.
"""

from __future__ import annotations

import argparse
import logging
import shutil
import socket
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

from gnomehome import __version__
from gnomehome.config import Config, ConfigError, load_config, platform_mismatch
from gnomehome.db import open_database
from gnomehome.db.migrate import MigrationError, current_version
from gnomehome.protected import ProtectedAssets, ProtectedListError

log = logging.getLogger("gnomehome")


# --------------------------------------------------------------------------
# doctor
# --------------------------------------------------------------------------


def _status(label: str, value: object, status: str = "") -> None:
    # Status is always a word (OK, MISSING, WARN), never color alone.
    suffix = f"  [{status}]" if status else ""
    print(f"  {label:<16} {value}{suffix}")


def _interface_exists(name: str) -> bool:
    try:
        return any(ifname == name for _, ifname in socket.if_nameindex())
    except OSError:
        return False


def _protected_status(config: Config) -> str:
    try:
        assets = ProtectedAssets.load(config.paths.protected_assets)
    except ProtectedListError as exc:
        return "MISSING" if "not found" in str(exc) else "INVALID (run `just protected-check`)"
    if assets.uses_example_values():
        return "EXAMPLE VALUES (fill in your real ones before scanning)"
    return f"OK ({len(assets.entries)} protected device(s))"


def cmd_doctor(config: Config, _args: argparse.Namespace) -> int:
    p = config.paths
    print("GnomeHome doctor")
    _status("config file", config.path)
    _status("platform", config.platform)
    mismatch = platform_mismatch(config)
    if mismatch:
        _status("", mismatch, "WARN")
    _status("data dir", p.data_dir)
    _status("database", p.db_path, "OK" if p.db_path.exists() else "not created yet")
    _status("protected list", p.protected_assets, _protected_status(config))
    _status("interface", p.interface, "OK" if _interface_exists(p.interface) else "NOT FOUND")
    _status("scan targets", ", ".join(config.network.scan_targets))

    nmap_ok = p.nmap_path.exists()
    version = ""
    if nmap_ok:
        # `nmap --version` only prints build info; it sends no packets.
        out = subprocess.run(
            [str(p.nmap_path), "--version"], capture_output=True, text=True, check=False
        )
        version = out.stdout.splitlines()[0] if out.stdout else ""
    _status("nmap", f"{p.nmap_path} {version}".strip(), "OK" if nmap_ok else "MISSING")
    _status("nmap privilege", p.nmap_privilege)
    if p.nmap_privilege == "sudo":
        _status("sudo", p.sudo_path, "OK" if p.sudo_path.exists() else "MISSING")
    arp = p.arp_command[0]
    _status("arp cache cmd", " ".join(p.arp_command), "OK" if shutil.which(arp) else "MISSING")
    for tool in ("uv", "just", "cargo", "cargo-audit"):
        found = shutil.which(tool)
        _status(tool, found or "-", "OK" if found else "MISSING")
    return 0


# --------------------------------------------------------------------------
# protected list
# --------------------------------------------------------------------------


def cmd_protected_check(config: Config, _args: argparse.Namespace) -> int:
    """Validate the list and summarize it without printing any identifiers."""
    try:
        assets = ProtectedAssets.load(config.paths.protected_assets)
    except ProtectedListError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    print(f"Protected-asset list OK: {assets.source}")
    for entry in assets.entries:
        print(f"  - {entry.label}: {len(entry.macs)} MAC(s), {len(entry.networks)} IP/CIDR(s)")
    if assets.uses_example_values():
        print(
            "WARNING: the list still contains example values (documentation ranges). "
            "Real scans are refused until you replace them.",
            file=sys.stderr,
        )
        return 1
    return 0


def cmd_protected_filter(config: Config, _args: argparse.Namespace) -> int:
    """Print the tcpdump filter for the zero-packet test (prints protected identifiers)."""
    try:
        assets = ProtectedAssets.load(config.paths.protected_assets)
    except ProtectedListError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    print(assets.tcpdump_filter())
    return 0


# --------------------------------------------------------------------------
# database
# --------------------------------------------------------------------------

_TABLES = (
    "asset",
    "service",
    "cve",
    "vulnerability",
    "risk_score",
    "event",
    "incident",
    "scan_run",
    "audit_log",
)


def _db_path(config: Config, args: argparse.Namespace) -> Path:
    return config.paths.dev_db_path if getattr(args, "dev", False) else config.paths.db_path


def cmd_migrate(config: Config, args: argparse.Namespace) -> int:
    path = _db_path(config, args)
    try:
        conn = open_database(path)
    except MigrationError as exc:
        print(f"migration error: {exc}", file=sys.stderr)
        return 1
    print(f"{path}: schema version {current_version(conn)}")
    conn.close()
    return 0


def cmd_db_status(config: Config, args: argparse.Namespace) -> int:
    path = _db_path(config, args)
    if not path.exists():
        print(f"{path}: not created yet (run `just migrate`)")
        return 1
    try:
        conn = open_database(path)
    except MigrationError as exc:
        print(f"migration error: {exc}", file=sys.stderr)
        return 1
    mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    print(f"{path}")
    print(f"  journal mode     {mode}")
    print(f"  schema version   {current_version(conn)}")
    for table in _TABLES:
        # Table names come from the fixed tuple above, never from input.
        count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # noqa: S608
        print(f"  {table:<16} {count} row(s)")
    conn.close()
    return 0


# --------------------------------------------------------------------------
# Wiring
# --------------------------------------------------------------------------

Handler = Callable[[Config, argparse.Namespace], int]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="gnomehome", description=__doc__)
    parser.add_argument("--version", action="version", version=f"gnomehome {__version__}")
    parser.add_argument(
        "--config", help="path to gnomehome.toml (default: $GNOMEHOME_CONFIG or config/)"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    doctor = sub.add_parser("doctor", help="show resolved config and check required tools")
    doctor.set_defaults(handler=cmd_doctor)

    check = sub.add_parser("protected-check", help="validate the protected-asset list")
    check.set_defaults(handler=cmd_protected_check)
    tcpdump = sub.add_parser(
        "protected-filter", help="print the tcpdump filter for the zero-packet test"
    )
    tcpdump.set_defaults(handler=cmd_protected_filter)

    migrate = sub.add_parser("migrate", help="create the database or apply pending migrations")
    migrate.add_argument("--dev", action="store_true", help="use the synthetic-data dev database")
    migrate.set_defaults(handler=cmd_migrate)
    status = sub.add_parser("db-status", help="show schema version and row counts")
    status.add_argument("--dev", action="store_true", help="use the synthetic-data dev database")
    status.set_defaults(handler=cmd_db_status)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    if args.command is None:
        parser.print_help()
        return 0
    handler: Handler = args.handler
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    return handler(config, args)


if __name__ == "__main__":
    sys.exit(main())
