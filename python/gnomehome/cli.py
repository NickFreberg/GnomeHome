"""Command-line entry point: ``gnomehome <command>``.

The justfile wraps these commands so they are the same on the Mac and the Pi.
"""

from __future__ import annotations

import argparse
import sys

from gnomehome import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="gnomehome", description=__doc__)
    parser.add_argument("--version", action="version", version=f"gnomehome {__version__}")
    parser.add_subparsers(dest="command", metavar="<command>")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
