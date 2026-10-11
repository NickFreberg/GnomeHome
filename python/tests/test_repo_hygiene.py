"""Fail if a committed (or about-to-be-committed) file has a real-looking identifier.

The plan: "Never commit secrets, real MAC addresses, IPs, or hostnames." Fake
values in this repo come only from the documentation ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24 and MACs 00:00:5e:00:53:xx). RFC1918
addresses and other MACs are what a real home network uses, so they're flagged.

A line that genuinely needs a fake RFC1918 value (for example, a test that
the scan job accepts private targets) can carry the marker ``hygiene: allow``.
"""

from __future__ import annotations

import re
import subprocess

import pytest
from helpers import REPO_ROOT

RFC1918 = re.compile(
    r"(?<![\d.])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3})(?:/\d{1,2})?(?![\d.])"
)
# The RFC1918 range definitions themselves are fine.
ALLOWED_RANGES = {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

MAC = re.compile(r"(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])")
ALLOWED_MAC_PREFIXES = ("00:00:5e:00:53:", "02:00:5e:00:53:")
# The all-zero and obvious placeholder MACs are fine, and so are multicast MACs
# (first octet odd), which never identify a single device.
ALLOWED_MACS = {"00:00:00:00:00:00", "aa:bb:cc:dd:ee:ff"}

SKIP_SUFFIXES = (".lock",)
MARKER = "hygiene: allow"


def _mac_flagged(hit: str) -> bool:
    mac = hit.lower().replace("-", ":")
    if mac.startswith(ALLOWED_MAC_PREFIXES) or mac in ALLOWED_MACS:
        return False
    return not int(mac[:2], 16) & 0x01  # multicast is allowed


def _tracked_files() -> list[str]:
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=REPO_ROOT,
            capture_output=True,
            check=True,
        ).stdout
    except (FileNotFoundError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout")
    return [name for name in out.decode().split("\0") if name]


def test_no_real_looking_ips_or_macs_in_tracked_files():
    findings = []
    for name in _tracked_files():
        if name.endswith(SKIP_SUFFIXES):
            continue
        path = REPO_ROOT / name
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if MARKER in line:
                continue
            for hit in RFC1918.findall(line):
                if hit not in ALLOWED_RANGES:
                    findings.append(f"{name}:{lineno}: private IP {hit}")
            for hit in MAC.findall(line):
                if _mac_flagged(hit):
                    findings.append(f"{name}:{lineno}: MAC {hit}")
    assert not findings, "Replace with documentation-range fake values:\n" + "\n".join(findings)


@pytest.mark.parametrize(
    ("line", "flagged"),
    [
        ("scan_targets = [192.168.50.0/24]", True),  # hygiene: allow
        ("gateway 10.1.2.3", True),  # hygiene: allow
        ("172.20.0.5", True),  # hygiene: allow
        ("172.15.0.5 is public", False),
        ("RFC1918 includes 192.168.0.0/16", False),
        ("fake 192.0.2.10", False),
        ("version 1.10.0.4", False),
    ],
)
def test_ip_detector(line: str, flagged: bool):
    hits = [h for h in RFC1918.findall(line) if h not in ALLOWED_RANGES]
    assert bool(hits) is flagged


@pytest.mark.parametrize(
    ("line", "flagged"),
    [
        ("laptop 12-34-56-78-9A-BC", True),  # hygiene: allow
        ("mac 12:34:56:78:9a:bc", True),  # hygiene: allow
        ("placeholder aa:bb:cc:dd:ee:ff", False),
        ("mdns multicast 01:00:5e:00:00:fb", False),
        ("fake 00:00:5e:00:53:01", False),
        ("sha 0123456789abcdef0123", False),
    ],
)
def test_mac_detector(line: str, flagged: bool):
    assert any(_mac_flagged(h) for h in MAC.findall(line)) is flagged
