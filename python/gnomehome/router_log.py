"""Parse router syslog lines, including the router's DHCP messages.

On the Pi, rsyslog receives the router's syslog and writes one line per
message with an RFC3339 timestamp (the template is in
``deploy/pi/templates/rsyslog-gnomehome.conf.in``)::

    2026-10-11T14:03:12.123456+00:00 router dnsmasq-dhcp[1234]: DHCPACK(br0) 192.0.2.21 ...

Lines in the router's own format (RFC3164, no year, as shown on its System
Log page) are accepted too, with the year inferred and the time taken as UTC.

The router's DHCP server is dnsmasq. Its messages give the plan's "Router
DHCP leases" source (MAC, IP, hostname) as they happen. Everything in a line
comes from the network, so callers treat hostnames and messages as untrusted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

_MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1
)}  # fmt: skip

_RFC3339 = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+(?P<rest>.*)$"
)
_RFC3164 = re.compile(
    r"^(?:<\d{1,3}>)?(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +"
    r"(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2})\s+(?P<rest>.*)$"
)
_TAG = re.compile(r"^(?P<program>[A-Za-z0-9_./-]{1,64})(?:\[(?P<pid>\d{1,10})\])?: ?(?P<msg>.*)$")
_DHCP = re.compile(
    r"^(?P<kind>DHCP[A-Z]{3,12})\((?P<iface>[^)\s]{0,32})\)"
    r"(?: (?P<ip>\d{1,3}(?:\.\d{1,3}){3}))?"
    r" (?P<mac>[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})"
    r"(?: (?P<rest>.*))?$"
)
DHCP_PROGRAM = "dnsmasq-dhcp"


@dataclass(frozen=True)
class SyslogLine:
    ts: datetime
    program: str
    message: str


@dataclass(frozen=True)
class DhcpMessage:
    kind: str
    interface: str
    ip: str | None
    mac: str
    #: Only DHCPACK carries the client's hostname. Untrusted.
    hostname: str | None


def parse_syslog_line(line: str, *, now: datetime | None = None) -> SyslogLine | None:
    """Parse one line, or return None if it isn't a syslog line we understand."""
    line = line.rstrip("\r\n")
    match = _RFC3339.match(line)
    if match:
        try:
            ts = datetime.fromisoformat(match["ts"].replace("Z", "+00:00")).astimezone(UTC)
        except ValueError:
            return None
    else:
        match = _RFC3164.match(line)
        if not match:
            return None
        ts = _rfc3164_time(match["mon"], int(match["day"]), match["time"], now or datetime.now(UTC))
        if ts is None:
            return None
    tagged = _split_tag(match["rest"])
    if tagged is None:
        return None
    program, message = tagged
    return SyslogLine(ts=ts, program=program, message=message)


def parse_dhcp(line: SyslogLine) -> DhcpMessage | None:
    if line.program != DHCP_PROGRAM:
        return None
    match = _DHCP.match(line.message)
    if not match:
        return None
    kind = match["kind"]
    return DhcpMessage(
        kind=kind,
        interface=match["iface"],
        ip=match["ip"],
        mac=match["mac"],
        hostname=match["rest"] if kind == "DHCPACK" and match["rest"] else None,
    )


def _split_tag(rest: str) -> tuple[str, str] | None:
    """``program[pid]: message``, optionally preceded by a host name."""
    match = _TAG.match(rest)
    if match is None and " " in rest:
        match = _TAG.match(rest.split(" ", 1)[1])  # drop the host field
    if match is None:
        return None
    return match["program"], match["msg"]


def _rfc3164_time(mon: str, day: int, clock: str, now: datetime) -> datetime | None:
    hour, minute, second = (int(x) for x in clock.split(":"))
    try:
        ts = datetime(now.year, _MONTHS[mon], day, hour, minute, second, tzinfo=UTC)
    except ValueError:
        return None
    if ts > now + timedelta(days=1):  # a December line read in January
        ts = ts.replace(year=now.year - 1)
    return ts
