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

from gnomehome import __version__
from gnomehome.config import Config, ConfigError, load_config, platform_mismatch

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
    _status(
        "protected list",
        p.protected_assets,
        "OK" if p.protected_assets.exists() else "MISSING (run `just setup`, then fill it in)",
    )
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
