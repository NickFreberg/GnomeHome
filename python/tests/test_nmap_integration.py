"""Real nmap, loopback only: proof that nmap honors our exclude file.

This targets 127.0.0.1 and nothing else. Loopback traffic never leaves the
machine, so this isn't a network scan. It runs nmap unprivileged (no sudo)
and is skipped when nmap isn't installed.

* With 127.0.0.1 in the exclude file, nmap must scan 0 hosts.
* Without it (the control), nmap finds 1 host, which shows the test can
  tell the difference.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from gnomehome.nmap_xml import parse_nmap_xml

NMAP = shutil.which("nmap")
LOOPBACK = "127.0.0.1"

pytestmark = [
    pytest.mark.nmap,
    pytest.mark.skipif(NMAP is None, reason="nmap is not installed"),
]


def _run(tmp_path: Path, exclude: list[str]):
    exclude_file = tmp_path / "exclude.txt"
    exclude_file.write_text("".join(f"{line}\n" for line in exclude))
    proc = subprocess.run(
        [
            NMAP,
            "--unprivileged",
            "-sn",
            "-n",
            "--excludefile",
            str(exclude_file),
            "-oX",
            "-",
            LOOPBACK,
        ],
        capture_output=True,
        check=True,
        timeout=60,
    )
    return parse_nmap_xml(proc.stdout)


def test_nmap_scans_nothing_when_the_only_target_is_excluded(tmp_path: Path):
    run = _run(tmp_path, [LOOPBACK])
    assert run.hosts_total == 0
    assert run.hosts == ()


def test_control_without_exclusion_finds_the_host(tmp_path: Path):
    run = _run(tmp_path, [])
    assert run.hosts_total == 1
    assert run.hosts_up == 1
