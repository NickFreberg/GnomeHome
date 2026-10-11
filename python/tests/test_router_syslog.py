"""The router syslog job: DHCP into the inventory, alerts, and the protected-asset rules."""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest
from helpers import EXAMPLE_PROTECTED

from gnomehome.audit import AuditLog, verify
from gnomehome.collectors.router_syslog import ingest_router_syslog, send_alerts
from gnomehome.db import open_database
from gnomehome.protected import load_guard

# The example protected list: laptop MACs 00:00:5e:00:53:01 and :02, reserved IP 192.0.2.10.


def ack(ts: str, ip: str, mac: str, host: str = "") -> str:
    tail = f" {host}" if host else ""
    return f"{ts} router dnsmasq-dhcp[100]: DHCPACK(br0) {ip} {mac}{tail}\n"


BASELINE = [
    ack("2026-10-11T08:00:00Z", "192.0.2.20", "00:00:5e:00:53:20", "living-room-tv"),
    ack("2026-10-11T08:00:05Z", "192.0.2.21", "02:00:5e:00:53:21", "parent-phone"),
]


class Recorder:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def notify(self, message: str, **_: object) -> None:
        self.messages.append(message)


@pytest.fixture
def env(tmp_path: Path):
    conn = open_database(tmp_path / "x.sqlite3")
    guard = load_guard(EXAMPLE_PROTECTED, audit=AuditLog(conn), actor="system:syslog")
    log = tmp_path / "router.log"
    log.write_text("")
    yield conn, guard, log
    conn.close()


def run(env, *lines: str, learning: int = 60):
    conn, guard, log = env
    with open(log, "a") as handle:
        handle.writelines(lines)
    return ingest_router_syslog(conn, guard, log, learning_minutes=learning)


def rows(conn: sqlite3.Connection, sql: str) -> list[sqlite3.Row]:
    return conn.execute(sql).fetchall()


def test_dhcp_builds_the_inventory_and_events(env):
    conn = env[0]
    result = run(env, *BASELINE, "2026-10-11T08:01:00Z router ntp: start NTP update\n")
    assert result.dhcp_events == 2 and result.syslog_events == 1
    assets = {r["mac"]: r for r in rows(conn, "SELECT * FROM asset")}
    assert assets["00:00:5e:00:53:20"]["last_ip"] == "192.0.2.20"
    assert assets["00:00:5e:00:53:20"]["hostname"] == "living-room-tv"
    assert assets["02:00:5e:00:53:21"]["mac_randomized"] == 1
    events = rows(conn, "SELECT kind, status, attrs FROM event ORDER BY id")
    assert events[0]["status"] == "DHCPACK"
    assert json.loads(events[0]["attrs"])["mac"] == "00:00:5e:00:53:20"


def test_baseline_devices_raise_no_alert_but_a_later_device_does(env):
    conn = env[0]
    first = run(env, *BASELINE)
    assert first.new_device_incidents == 0 and len(first.new_devices) == 2
    later = run(env, ack("2026-10-11T14:00:00Z", "192.0.2.99", "02:00:5e:00:53:99", "Galaxy"))
    assert later.new_device_incidents == 1
    incident = rows(conn, "SELECT * FROM incident")[0]
    assert incident["detection"] == "inventory.new_device"
    assert '"Galaxy" (a device-supplied name' in incident["summary"]
    notifier = Recorder()
    send_alerts(later, notifier)
    assert notifier.messages == ["New device on your network. Run `just incidents` for details."]


def test_reruns_never_duplicate_and_partial_lines_wait(env):
    conn, _, log = env
    run(env, *BASELINE)
    assert run(env).lines == 0  # nothing new
    with open(log, "a") as handle:
        handle.write("2026-10-11T09:00:00Z router ntp: half a li")  # still being written
    assert run(env).lines == 0
    with open(log, "a") as handle:
        handle.write("ne\n")
    assert run(env).syslog_events == 1
    assert rows(conn, "SELECT COUNT(*) FROM event")[0][0] == 3


def test_rotation_restarts_at_the_new_file(env):
    _, _, log = env
    run(env, *BASELINE)
    log.rename(log.with_suffix(".log.1"))  # logrotate moves the file away
    log.write_text("2026-10-11T10:00:00Z router ntp: after rotation\n")
    assert os.stat(log).st_size > 0
    assert run(env).syslog_events == 1


# ------------------------------------------------------------------ protected devices


def test_protected_laptop_is_recorded_as_existence_only(env):
    conn = env[0]
    result = run(
        env,
        ack("2026-10-11T08:00:00Z", "192.0.2.10", "00:00:5e:00:53:01", "WORK-LAPTOP-123"),
        ack("2026-10-11T20:00:00Z", "192.0.2.10", "00:00:5e:00:53:01", "WORK-LAPTOP-123"),
    )
    assert result.dropped_protected == 2 and result.dhcp_events == 0 and not result.drift
    laptop = rows(conn, "SELECT * FROM asset WHERE mac = '00:00:5e:00:53:01'")[0]
    assert laptop["protected"] == 1
    assert laptop["first_seen"] == laptop["last_seen"] == "2026-10-11T08:00:00.000Z"
    assert laptop["hostname"] is None and laptop["last_ip"] is None
    assert rows(conn, "SELECT COUNT(*) FROM event")[0][0] == 0
    stored = json.dumps([tuple(r) for r in rows(conn, "SELECT * FROM audit_log")])
    assert "WORK-LAPTOP" not in stored


def test_protected_mac_at_unlisted_ip_opens_one_drift_incident(env):
    conn = env[0]
    dock = ack("2026-10-11T09:00:00Z", "192.0.2.88", "00:00:5e:00:53:02")
    result = run(env, dock, dock.replace("09:00:00", "21:00:00"))
    assert result.drift_incidents == 1  # deduplicated while open
    incident = rows(conn, "SELECT * FROM incident")[0]
    assert incident["detection"] == "guard.protected_drift" and incident["asset_id"] is None
    everything = json.dumps(
        [
            tuple(r)
            for t in ("incident", "audit_log", "event")
            for r in rows(conn, f"SELECT * FROM {t}")
        ]
    )
    assert "192.0.2.88" not in everything and "00:00:5e:00:53:02" not in everything
    assert "Work laptop" in incident["summary"]
    notifier = Recorder()
    send_alerts(result, notifier)
    assert notifier.messages == [
        "A protected device needs attention. Run `just incidents` for details."
    ]
    assert verify(conn).ok


def test_unknown_mac_on_the_protected_ip_stores_nothing_about_it(env):
    conn = env[0]
    result = run(env, ack("2026-10-11T09:00:00Z", "192.0.2.10", "00:00:5e:00:53:66", "who"))
    assert result.drift == [("Work laptop", "unknown_mac_at_protected_ip")]
    assert rows(conn, "SELECT COUNT(*) FROM asset")[0][0] == 0
    assert rows(conn, "SELECT COUNT(*) FROM event")[0][0] == 0


def test_syslog_lines_mentioning_the_laptop_are_dropped(env):
    conn = env[0]
    result = run(
        env,
        "2026-10-11T09:00:00Z router kernel: DROP IN=br0 OUT=eth0 "
        "SRC=192.0.2.10 DST=203.0.113.77\n",
        "2026-10-11T09:00:01Z router kernel: DROP IN=br0 "
        "MAC=ff:ff:ff:ff:ff:ff:00:00:5e:00:53:01:08:00 SRC=198.51.100.9\n",
        "2026-10-11T09:00:02Z router kernel: DROP IN=eth0 "
        "SRC=203.0.113.9 DST=198.51.100.1 DPT=23\n",
    )
    assert result.dropped_protected == 2 and result.syslog_events == 1
    assert "203.0.113.9" in rows(conn, "SELECT message FROM event")[0][0]


def test_a_device_cannot_hide_by_naming_itself_after_the_laptop(env):
    conn = env[0]
    result = run(env, ack("2026-10-11T09:00:00Z", "192.0.2.50", "00:00:5e:00:53:50", "192.0.2.10"))
    assert result.dhcp_events == 1  # the record is kept
    asset = rows(conn, "SELECT * FROM asset")[0]
    assert asset["mac"] == "00:00:5e:00:53:50" and asset["hostname"] is None  # the name isn't
