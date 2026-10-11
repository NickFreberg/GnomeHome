"""Router syslog job: ``just syslog`` (every minute on the Pi).

Reads the lines rsyslog has written since the last run (checkpointed in the
same transaction as the stored events), and for each one:

* **DHCP from a protected MAC**: record that the device exists (existence only,
  never updated) and store nothing else. If it was given an IP that isn't on
  its list, open a drift incident (label only) and alert.
* **DHCP for a protected IP from an unlisted MAC**: open a drift incident and
  store nothing about that device (fail closed).
* **Other DHCPACK**: update the inventory and store a ``dhcp`` event. A device
  never seen before, outside the learning window, opens a new-device incident
  (FR-03). A hostname that mentions a protected identifier is dropped, but the
  record is kept, so a device can't hide by naming itself after the laptop.
* **Any other line**: stored as a ``syslog`` event, unless the text mentions a
  protected device, in which case it's dropped.

Output names protected devices by label only. On the Pi this output goes to
the system journal, which is stored on disk.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from gnomehome.alerts import DRIFT_MESSAGE, NEW_DEVICE_MESSAGE, Notifier
from gnomehome.collectors.inventory import Observation, observe_asset, record_protected_presence
from gnomehome.db import transaction
from gnomehome.identifiers import normalize_mac
from gnomehome.incidents import NewDevice, drift_incident, in_learning_window, new_device_incident
from gnomehome.nmap_xml import clean_text
from gnomehome.protected import Guard
from gnomehome.router_log import DhcpMessage, SyslogLine, parse_dhcp, parse_syslog_line
from gnomehome.timeutil import format_ts, utc_now

ACTOR = "system:syslog"
#: Read at most this much per run, so a huge backlog can't exhaust the Pi's memory.
MAX_BYTES_PER_RUN = 16 * 1024 * 1024
MAX_MESSAGE = 1000


@dataclass
class IngestResult:
    lines: int = 0
    syslog_events: int = 0
    dhcp_events: int = 0
    dropped_protected: int = 0
    unparsed: int = 0
    new_devices: list[NewDevice] = field(default_factory=list)
    drift: list[tuple[str, str]] = field(default_factory=list)
    new_device_incidents: int = 0
    drift_incidents: int = 0
    more_pending: bool = False


def ingest_router_syslog(
    conn: sqlite3.Connection,
    guard: Guard,
    path: Path,
    *,
    learning_minutes: int,
    checkpoint: str = "router_syslog",
    source: str = "router",
    synthetic: bool = False,
    now: datetime | None = None,
) -> IngestResult:
    """Ingest new lines from ``path``. Call outside a transaction.

    The checkpoint is read and written inside one write transaction, so two
    overlapping runs can't both read the same lines.
    """
    result = IngestResult()
    with transaction(conn):
        stat = path.stat()
        row = conn.execute(
            "SELECT inode, byte_offset FROM ingest_checkpoint WHERE source = ?", (checkpoint,)
        ).fetchone()
        offset = 0
        if row is not None and row[0] == stat.st_ino and row[1] <= stat.st_size:
            offset = row[1]  # same file, not truncated: continue where we left off
        with open(path, "rb") as handle:
            handle.seek(offset)
            data = handle.read(MAX_BYTES_PER_RUN)
        end = data.rfind(b"\n")
        if end < 0:
            return result  # nothing new, or only a line that's still being written
        result.more_pending = offset + end + 1 < stat.st_size
        for raw in data[: end + 1].decode("utf-8", errors="replace").splitlines():
            if not raw.strip():
                continue
            result.lines += 1
            parsed = parse_syslog_line(raw, now=now)
            if parsed is None:
                result.unparsed += 1
                continue
            dhcp = parse_dhcp(parsed)
            if dhcp is not None:
                _handle_dhcp(conn, guard, parsed, dhcp, result, learning_minutes, source, synthetic)
            else:
                _handle_line(conn, guard, parsed, result, source, synthetic)
        conn.execute(
            "INSERT INTO ingest_checkpoint (source, path, inode, byte_offset, updated_at) "
            "VALUES (?, ?, ?, ?, ?) ON CONFLICT (source) DO UPDATE SET path = excluded.path, "
            "inode = excluded.inode, byte_offset = excluded.byte_offset, "
            "updated_at = excluded.updated_at",
            (checkpoint, str(path), stat.st_ino, offset + end + 1, utc_now()),
        )
    return result


def _handle_dhcp(
    conn: sqlite3.Connection,
    guard: Guard,
    line: SyslogLine,
    dhcp: DhcpMessage,
    result: IngestResult,
    learning_minutes: int,
    source: str,
    synthetic: bool,
) -> None:
    ts = format_ts(line.ts)
    assets = guard.assets
    by_mac = assets.match(mac=dhcp.mac)
    by_ip = assets.match(ip=dhcp.ip) if dhcp.ip else None

    if by_mac is not None:
        record_protected_presence(conn, dhcp.mac, ts)
        if dhcp.kind == "DHCPACK" and dhcp.ip and by_ip is None:
            _drift(conn, guard, by_mac.label, "protected_mac_at_unlisted_ip", result)
        result.dropped_protected += 1
        return
    if by_ip is not None:
        if dhcp.kind == "DHCPACK":
            _drift(conn, guard, by_ip.label, "unknown_mac_at_protected_ip", result)
        result.dropped_protected += 1
        return

    mac = normalize_mac(dhcp.mac)
    hostname = clean_text(dhcp.hostname)
    if hostname and guard.text_mentions_protected(hostname):
        hostname = None
    if dhcp.kind == "DHCPACK" and dhcp.ip:
        learning = in_learning_window(conn, ts, learning_minutes)
        asset_id, is_new = observe_asset(
            conn, Observation(mac=mac, ip=dhcp.ip, hostname=hostname), seen_at=ts
        )
        if is_new:
            device = NewDevice(asset_id, dhcp.ip, mac, None, hostname, ts)
            result.new_devices.append(device)
            if not learning and new_device_incident(conn, device, source="router DHCP"):
                result.new_device_incidents += 1
    else:
        found = conn.execute("SELECT id FROM asset WHERE mac = ?", (mac,)).fetchone()
        asset_id = found[0] if found else None
    conn.execute(
        "INSERT INTO event (ts, kind, source, synthetic, asset_id, src_ip, status, attrs) "
        "VALUES (?, 'dhcp', ?, ?, ?, ?, ?, ?)",
        (
            ts,
            source,
            int(synthetic),
            asset_id,
            dhcp.ip,
            dhcp.kind,
            json.dumps({"mac": mac, "hostname": hostname, "interface": dhcp.interface}),
        ),
    )
    result.dhcp_events += 1


def _handle_line(
    conn: sqlite3.Connection,
    guard: Guard,
    line: SyslogLine,
    result: IngestResult,
    source: str,
    synthetic: bool,
) -> None:
    if guard.text_mentions_protected(line.message):
        result.dropped_protected += 1
        return
    message = clean_text(line.message, MAX_MESSAGE) or "-"
    conn.execute(
        "INSERT INTO event (ts, kind, source, synthetic, message, attrs) "
        "VALUES (?, 'syslog', ?, ?, ?, ?)",
        (format_ts(line.ts), source, int(synthetic), message,
         json.dumps({"program": clean_text(line.program, 64)})),
    )  # fmt: skip
    result.syslog_events += 1


def _drift(
    conn: sqlite3.Connection, guard: Guard, label: str, kind: str, result: IngestResult
) -> None:
    result.drift.append((label, kind))
    opened = drift_incident(
        conn, label=label, kind=kind, source="router DHCP", audit=guard.audit, actor=guard.actor
    )
    if opened is not None:
        result.drift_incidents += 1


def send_alerts(result: IngestResult, notifier: Notifier) -> None:
    """At most one banner per kind per run, sent after the data is committed."""
    if result.new_device_incidents:
        notifier.notify(NEW_DEVICE_MESSAGE)
    if result.drift_incidents:
        notifier.notify(DRIFT_MESSAGE)


def describe(result: IngestResult, say: Callable[[str], None]) -> None:
    say(
        f"Router syslog: {result.lines} line(s), {result.dhcp_events} DHCP and "
        f"{result.syslog_events} other event(s) stored, {result.dropped_protected} dropped by "
        f"the protected-asset guard, {result.unparsed} unparsed."
    )
    for label, kind in sorted(set(result.drift)):
        say(f"WARNING: protected device {label!r}: {kind.replace('_', ' ')} (see `just incidents`)")
    if result.more_pending:
        say("More lines are waiting; the next run continues from here.")
