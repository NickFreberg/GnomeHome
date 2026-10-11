"""Passive drift check against the local ARP cache.

The ARP cache is the operating system's own table of "which MAC is at which
IP" for devices this machine has recently talked to. Reading it sends no
packets. On the Mac the command is ``arp -an``; on the Pi it's
``ip neigh show`` (both set in config).

nmap can only exclude protected devices by IP, so if the work laptop ends up
at a different IP (a lost DHCP reservation, say), the exclude file alone
wouldn't cover it. Before every scan we look for (plan, "Protected
assets", step 8):

* a protected MAC at an unlisted IP: that IP is added to this run's
  exclusions, and you get a warning to fix the reservation;
* an unknown MAC at a protected IP: the laptop's MAC may have changed (a
  randomized MAC?) or another device took its IP. That IP stays excluded
  either way.

The ARP cache only knows devices this machine has talked to recently, so this
is an extra layer, not a replacement for the DHCP reservation.
"""

from __future__ import annotations

import logging
import re
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field

from gnomehome.identifiers import InvalidIdentifier, is_multicast, normalize_ip, normalize_mac
from gnomehome.protected import ProtectedAssets

log = logging.getLogger(__name__)

# macOS and BSD `arp -an`, and Linux net-tools `arp -an`:
#   ? (192.0.2.1) at 0:0:5e:0:53:1 on en0 ifscope [ethernet]
#   ? (192.0.2.1) at 00:00:5e:00:53:01 [ether] on eth0
_ARP_LINE = re.compile(
    r"^\S+ \((?P<ip>[0-9.]+)\) at (?P<mac>[0-9A-Fa-f:]+)(?: \[\w+\])? on (?P<iface>[\w.-]+)"
)
# Linux iproute2 `ip neigh show`:
#   192.0.2.1 dev eth0 lladdr 00:00:5e:00:53:01 REACHABLE
_NEIGH_LINE = re.compile(r"^(?P<ip>[0-9.]+) dev (?P<iface>[\w.-]+) lladdr (?P<mac>[0-9A-Fa-f:]+)")


@dataclass(frozen=True)
class ArpEntry:
    ip: str
    mac: str
    interface: str


def parse_arp_output(text: str) -> list[ArpEntry]:
    """Parse either format. Incomplete, multicast, and broadcast entries are skipped."""
    entries = []
    for line in text.splitlines():
        match = _ARP_LINE.match(line.strip()) or _NEIGH_LINE.match(line.strip())
        if not match:
            continue
        try:
            mac = normalize_mac(match["mac"])
            ip = str(normalize_ip(match["ip"]))
        except InvalidIdentifier:
            continue
        if is_multicast(mac) or mac == "00:00:00:00:00:00":
            continue
        entries.append(ArpEntry(ip=ip, mac=mac, interface=match["iface"]))
    return entries


def read_arp_cache(command: Sequence[str], interface: str) -> list[ArpEntry]:
    """Run the configured command and return entries on ``interface``. Best effort."""
    try:
        proc = subprocess.run(
            list(command), capture_output=True, text=True, timeout=10, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.warning("could not read the ARP cache with %s: %s", command[0], exc)
        return []
    if proc.returncode != 0:
        log.warning("ARP cache command exited with %s: %s", proc.returncode, proc.stderr.strip())
        return []
    return [e for e in parse_arp_output(proc.stdout) if e.interface == interface]


@dataclass
class DriftReport:
    #: IPs to add to this run's nmap exclusions.
    extra_excludes: list[str] = field(default_factory=list)
    #: Console messages for the operator (these may include identifiers; never stored).
    warnings: list[str] = field(default_factory=list)
    #: (label, kind) pairs for the audit log (no identifiers).
    findings: list[tuple[str, str]] = field(default_factory=list)


def check_drift(entries: Sequence[ArpEntry], assets: ProtectedAssets) -> DriftReport:
    report = DriftReport()
    for entry in entries:
        by_mac = assets.match(mac=entry.mac)
        by_ip = assets.match(ip=entry.ip)
        if by_mac and not by_ip:
            report.extra_excludes.append(entry.ip)
            report.findings.append((by_mac.label, "protected_mac_at_unlisted_ip"))
            report.warnings.append(
                f"Protected device {by_mac.label!r} (MAC {entry.mac}) is at {entry.ip}, which is "
                "not its reserved IP. That IP is excluded from this scan. Check the DHCP "
                "reservation in the router."
            )
        elif by_ip and not by_mac:
            report.findings.append((by_ip.label, "unknown_mac_at_protected_ip"))
            report.warnings.append(
                f"The reserved IP {entry.ip} of protected device {by_ip.label!r} is held by an "
                f"unlisted MAC {entry.mac}. The laptop's MAC may have changed (randomized MAC?), "
                "or another device took the IP. The IP stays excluded. If it's the laptop, add "
                "the MAC to config/protected_assets.yaml."
            )
    return report
