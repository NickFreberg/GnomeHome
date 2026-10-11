"""Synthetic router syslog, as rsyslog on the Pi will write it.

* DHCP: every device's join (DISCOVER, OFFER, REQUEST, ACK with its name),
  then renewals about every 12 hours (a 24-hour lease). The unknown device
  joins a few seconds before its first DNS lookups.
* ``protected_drift``: partway through, the work laptop docks and its Ethernet
  adapter (the second protected MAC) is given a non-reserved IP. Expected
  result: one drift incident naming only the label.
* Noise: internet scanners hitting the router's WAN side (kernel DROP lines),
  NTP updates, and one firewall line about the laptop, which must be dropped.

Fake values only: documentation-range MACs and IPs, the router called "router".
"""

from __future__ import annotations

import random
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta

from gnomehome.synthetic.household import ROUTER_WAN_IP, Device
from gnomehome.timeutil import format_ts

RENEW_SECONDS = 12 * 3600
DRIFT_MAC = "00:00:5e:00:53:02"  # the laptop's dock adapter in protected_assets.example.yaml
DRIFT_IP = "192.0.2.88"
WAN_MACS = "00:00:5e:00:53:f0:00:00:5e:00:53:f1:08:00"  # iptables MAC=dst:src:type, fake
SCANNED_PORTS = (22, 23, 445, 3389, 8080, 5555)
_DHCP_PID = 402


@dataclass(frozen=True)
class RouterLine:
    ts: datetime
    program: str
    pid: int | None
    message: str
    label: str


def generate_router_log(
    rng: random.Random, devices: Iterable[Device], start: datetime, hours: int
) -> tuple[list[RouterLine], dict]:
    end = start + timedelta(hours=hours)
    span = end - start
    lines: list[RouterLine] = []

    for device in devices:
        if device.joins_at > 0:
            joined = start + span * device.joins_at - timedelta(seconds=rng.uniform(2, 5))
            label = "new_device"
        else:
            joined = start + timedelta(seconds=rng.uniform(1, 30))
            label = "normal"
        if device.protected:
            label = "protected"
        name = "WORK-LAPTOP" if device.protected else device.name
        lines += _join(joined, device.ip, device.mac, name, label)
        renew = joined + timedelta(seconds=RENEW_SECONDS * rng.uniform(0.98, 1.02))
        while renew < end:
            lines += _renew(renew, device.ip, device.mac, name, label)
            renew += timedelta(seconds=RENEW_SECONDS * rng.uniform(0.98, 1.02))

    drift_at = start + span * 0.60
    lines += _join(drift_at, DRIFT_IP, DRIFT_MAC, "WORK-LAPTOP", "protected_drift")

    # The laptop's own traffic in a firewall line: must never be stored.
    lines.append(
        RouterLine(
            start + span * 0.30,
            "kernel",
            None,
            "DROP IN=br0 OUT=eth0 SRC=192.0.2.10 DST=203.0.113.77 LEN=60 PROTO=UDP SPT=500 DPT=500",
            "protected",
        )
    )

    t = start
    while True:
        t += timedelta(seconds=rng.expovariate(1 / 300))
        if t >= end:
            break
        src = f"203.0.113.{rng.randint(2, 254)}"
        lines.append(
            RouterLine(
                t,
                "kernel",
                None,
                f"DROP IN=eth0 OUT= MAC={WAN_MACS} SRC={src} DST={ROUTER_WAN_IP} "
                f"LEN=44 TTL=242 PROTO=TCP SPT={rng.randint(1024, 65535)} "
                f"DPT={rng.choice(SCANNED_PORTS)} SYN",
                "normal",
            )
        )
    t = start + timedelta(minutes=5)
    while t < end:
        lines.append(RouterLine(t, "ntp", None, "start NTP update", "normal"))
        t += timedelta(hours=12)

    lines.sort(key=lambda line: (line.ts, line.program, line.message))
    scenarios = {
        "protected_drift": {
            "device": "work-laptop",
            "mac": DRIFT_MAC,
            "ip": DRIFT_IP,
            "at": format_ts(drift_at),
            "expect": "one guard.protected_drift incident that names only the label",
        }
    }
    return lines, scenarios


def _join(at: datetime, ip: str, mac: str, name: str, label: str) -> list[RouterLine]:
    def step(seconds: float, message: str) -> RouterLine:
        return RouterLine(
            at + timedelta(seconds=seconds), "dnsmasq-dhcp", _DHCP_PID, message, label
        )

    return [
        step(0.0, f"DHCPDISCOVER(br0) {mac}"),
        step(0.1, f"DHCPOFFER(br0) {ip} {mac}"),
        step(0.3, f"DHCPREQUEST(br0) {ip} {mac}"),
        step(0.4, f"DHCPACK(br0) {ip} {mac} {name}"),
    ]


def _renew(at: datetime, ip: str, mac: str, name: str, label: str) -> list[RouterLine]:
    return [
        RouterLine(at, "dnsmasq-dhcp", _DHCP_PID, f"DHCPREQUEST(br0) {ip} {mac}", label),
        RouterLine(
            at + timedelta(seconds=0.1),
            "dnsmasq-dhcp",
            _DHCP_PID,
            f"DHCPACK(br0) {ip} {mac} {name}",
            label,
        ),
    ]


def router_log_lines(lines: Iterable[RouterLine]) -> Iterator[str]:
    """rsyslog's file format: RFC3339 time, host, tag, message."""
    for line in lines:
        tag = f"{line.program}[{line.pid}]" if line.pid is not None else line.program
        yield f"{line.ts.isoformat(timespec='microseconds')} router {tag}: {line.message}"
