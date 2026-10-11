"""Command-line entry point: ``gnomehome <command>``.

The justfile wraps these commands so they are the same on the Mac and the Pi.
"""

from __future__ import annotations

import argparse
import logging
import shlex
import shutil
import socket
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

from gnomehome import __version__
from gnomehome.alerts import notifier_from_config
from gnomehome.audit import AuditLog
from gnomehome.audit import verify as verify_audit
from gnomehome.collectors.nmap_discovery import (
    GuardViolation,
    NmapFailed,
    ScanBusy,
    ScanRefused,
    ScanResult,
    run_scan,
)
from gnomehome.collectors.router_syslog import ACTOR as SYSLOG_ACTOR
from gnomehome.collectors.router_syslog import describe, ingest_router_syslog, send_alerts
from gnomehome.config import Config, ConfigError, load_config, platform_mismatch
from gnomehome.db import open_database, transaction
from gnomehome.db.migrate import MigrationError, current_version
from gnomehome.db.scrub import scrub_protected
from gnomehome.incidents import list_incidents, resolve_incident
from gnomehome.protected import Guard, ProtectedAssets, ProtectedListError, load_guard
from gnomehome.synthetic.generate import generate
from gnomehome.synthetic.load import load_synthetic

log = logging.getLogger("gnomehome")

#: Exit code for "another run holds the lock" (EX_TEMPFAIL). systemd units treat it as success.
EXIT_BUSY = 75


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


def cmd_incidents(config: Config, args: argparse.Namespace) -> int:
    path = _db_path(config, args)
    if not path.exists():
        print(f"{path}: not created yet (run `just migrate`)")
        return 1
    conn = open_database(path)
    rows = list_incidents(conn, include_closed=args.all)
    conn.close()
    if not rows:
        print("All quiet in the garden: no open incidents." if not args.all else "No incidents.")
        return 0
    for row in rows:
        # Severity is always a word, never color alone (design system).
        print(f"#{row['id']}  {row['severity'].upper():<8} {row['status']:<12} {row['created_at']}")
        print(f"    {row['title']}")
        print(f"    {row['summary']}")
    return 0


def cmd_incident_resolve(config: Config, args: argparse.Namespace) -> int:
    path = _db_path(config, args)
    conn = open_database(path)
    with transaction(conn):
        done = resolve_incident(conn, args.id, audit=AuditLog(conn), actor="user:local")
    conn.close()
    print(f"Incident #{args.id} resolved." if done else f"No open incident #{args.id}.")
    return 0 if done else 1


def cmd_audit_verify(config: Config, args: argparse.Namespace) -> int:
    path = _db_path(config, args)
    if not path.exists():
        print(f"{path}: not created yet (run `just migrate`)")
        return 1
    conn = open_database(path)
    result = verify_audit(conn)
    conn.close()
    if result.ok:
        print(
            f"Audit log OK: {result.rows} entr{'y' if result.rows == 1 else 'ies'}, chain intact."
        )
        return 0
    print(f"Audit log BROKEN ({result.rows} entries checked):", file=sys.stderr)
    for problem in result.problems:
        print(f"  {problem}", file=sys.stderr)
    return 1


# --------------------------------------------------------------------------
# scanning
# --------------------------------------------------------------------------


def _print_dry_run(result: ScanResult) -> None:
    print("DRY RUN: nothing will be sent and nothing will be written.\n")
    print(f"Exclude file would list {len(result.excluded)} protected address(es):")
    for line in result.excluded:
        print(f"  {line}")
    print("  (plus any protected MAC the ARP cache shows at another IP)\n")
    print("Phase 1, host discovery:")
    print(f"  {shlex.join(result.commands[0])}")
    if len(result.commands) > 1:
        print("\nPhase 2, service scan (only hosts found up in phase 1, minus protected ones):")
        print(f"  {shlex.join(result.commands[1])}")
    if result.problems:
        print("\nThese would stop a real scan:")
        for problem in result.problems:
            print(f"  - {problem}")
    else:
        print("\nNo problems found. A real scan would be allowed.")


def _scan(config: Config, args: argparse.Namespace, mode: str) -> int:
    if not args.dry_run and config.paths.nmap_privilege == "sudo":
        print(
            "nmap needs administrator rights on macOS to see MAC addresses, so it runs with "
            "sudo. macOS may ask for your login password (nothing shows as you type)."
        )
    try:
        result = run_scan(config, mode=mode, dry_run=args.dry_run)
    except ProtectedListError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    except ScanBusy as exc:
        print(f"Skipped: {exc}.")
        return EXIT_BUSY
    except ScanRefused as exc:
        print(f"REFUSED (nothing was sent): {exc}", file=sys.stderr)
        return 1
    except GuardViolation as exc:
        print(f"STOPPED by the protected-asset guard: {exc}", file=sys.stderr)
        return 3
    except NmapFailed as exc:
        print(f"nmap failed: {exc}", file=sys.stderr)
        return 1
    if result.dry_run:
        _print_dry_run(result)
        return 0
    print(f"\nScan {result.scan_id} done: {result.hosts_up} device(s) up", end="")
    print(f", {result.services_seen} open service(s)." if mode == "service" else ".")
    if result.baseline and result.new_devices:
        print(
            f"Baseline: recorded {len(result.new_devices)} device(s) while the inventory is still "
            f"learning ({config.alerts.learning_minutes} min). Devices that appear after that "
            "raise alerts."
        )
    elif result.new_devices:
        print(f"New device(s) ({len(result.new_devices)}), see `just incidents`:")
        for device in result.new_devices:
            print(f"  {device.ip or '-':<15} {device.mac}  {device.vendor or 'unknown vendor'}")
    else:
        print("No new devices.")
    return 0


def cmd_scan(config: Config, args: argparse.Namespace) -> int:
    return _scan(config, args, "service")


def cmd_discover(config: Config, args: argparse.Namespace) -> int:
    return _scan(config, args, "discovery")


# --------------------------------------------------------------------------
# router syslog
# --------------------------------------------------------------------------


def cmd_syslog(config: Config, _args: argparse.Namespace) -> int:
    path = config.paths.router_syslog_path
    if path is None:
        print(
            f"router_syslog_path is not set for platform {config.platform!r}. The router sends "
            "its syslog to the Pi; on the Mac, `just synth-load` runs the same code on "
            "synthetic router syslog.",
            file=sys.stderr,
        )
        return 1
    if not path.exists():
        print(f"{path} does not exist yet. Is rsyslog set up? See deploy/pi/README.md.",
              file=sys.stderr)  # fmt: skip
        return 1
    try:
        assets = ProtectedAssets.load(config.paths.protected_assets)
    except ProtectedListError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    conn = open_database(config.paths.db_path)
    audit = AuditLog(conn)
    scrub_protected(conn, assets, audit=audit, actor=SYSLOG_ACTOR)
    guard = Guard(assets, audit=audit, actor=SYSLOG_ACTOR)
    result = ingest_router_syslog(
        conn, guard, path, learning_minutes=config.alerts.learning_minutes
    )
    conn.close()
    send_alerts(result, notifier_from_config(config))
    describe(result, print)
    return 0


# --------------------------------------------------------------------------
# synthetic data
# --------------------------------------------------------------------------


def _synth_dir(config: Config, args: argparse.Namespace) -> Path:
    if args.dir:
        return Path(args.dir)
    return (
        config.paths.synthetic_dir
        / f"seed-{args.seed if args.seed is not None else config.synthetic.seed}"
    )


def cmd_synth(config: Config, args: argparse.Namespace) -> int:
    seed = args.seed if args.seed is not None else config.synthetic.seed
    days = args.days if args.days is not None else config.synthetic.days
    out = _synth_dir(config, args)
    result = generate(out, seed=seed, start_date=config.synthetic.start_date, hours=days * 24)
    print(f"Synthetic data (seed {seed}, {days} day(s)) written to {out}")
    print(
        f"  {result.devices} devices, {result.queries} DNS queries, {result.flows} flows, "
        f"{result.snapshots} conntrack snapshots"
    )
    print("  Ground truth: labels.json. Load it with `just synth-load`.")
    return 0


def cmd_synth_load(config: Config, args: argparse.Namespace) -> int:
    data_dir = _synth_dir(config, args)
    if not (data_dir / "household.json").exists():
        print(f"No synthetic data in {data_dir}. Run `just synth` first.", file=sys.stderr)
        return 1
    try:
        assets = ProtectedAssets.load(config.paths.protected_assets)
    except ProtectedListError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    conn = open_database(config.paths.dev_db_path)
    audit = AuditLog(conn)
    scrub_protected(conn, assets, audit=audit, actor="system:synthetic")
    guard = load_guard(config.paths.protected_assets, audit=audit, actor="system:synthetic")
    result = load_synthetic(conn, guard, data_dir)
    audit.append(
        actor="system:synthetic",
        action="synthetic.load",
        target=None,
        result="success",
        details={
            "assets": result.assets,
            "dns_events": result.dns_events,
            "flow_events": result.flow_events,
            "dropped_protected": result.dropped_protected,
        },
    )
    conn.close()
    print(f"Loaded into the dev database {config.paths.dev_db_path}:")
    print(f"  {result.assets} assets, {result.dns_events} DNS events, {result.flow_events} flows")
    print(f"  {result.dropped_protected} record(s) dropped by the protected-asset guard")
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
    audit = sub.add_parser("audit-verify", help="recompute and check the audit log hash chain")
    audit.add_argument("--dev", action="store_true", help="use the synthetic-data dev database")
    audit.set_defaults(handler=cmd_audit_verify)
    incidents = sub.add_parser("incidents", help="list open incidents (alerts)")
    incidents.add_argument("--all", action="store_true", help="include resolved incidents")
    incidents.add_argument("--dev", action="store_true", help="use the synthetic-data dev database")
    incidents.set_defaults(handler=cmd_incidents)
    resolve = sub.add_parser("incident-resolve", help="mark an incident resolved")
    resolve.add_argument("id", type=int)
    resolve.add_argument("--dev", action="store_true", help="use the synthetic-data dev database")
    resolve.set_defaults(handler=cmd_incident_resolve)

    for name, handler, text in (
        ("scan", cmd_scan, "host discovery plus service scan (nmap)"),
        ("discover", cmd_discover, "host discovery only (nmap -sn)"),
    ):
        cmd = sub.add_parser(name, help=text)
        cmd.add_argument(
            "--dry-run", action="store_true", help="print the nmap commands; send nothing"
        )
        cmd.set_defaults(handler=handler)

    syslog = sub.add_parser("syslog", help="read new router syslog lines (DHCP, firewall, ...)")
    syslog.set_defaults(handler=cmd_syslog)

    synth = sub.add_parser("synth", help="generate synthetic DNS logs and flows")
    synth_load = sub.add_parser("synth-load", help="load synthetic data into the dev database")
    for cmd in (synth, synth_load):
        cmd.add_argument("--seed", type=int, help="random seed (default: [synthetic].seed)")
        cmd.add_argument("--dir", help="dataset folder (default: <synthetic_dir>/seed-<seed>)")
    synth.add_argument("--days", type=int, help="days of data (default: [synthetic].days)")
    synth.set_defaults(handler=cmd_synth)
    synth_load.set_defaults(handler=cmd_synth_load)
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
