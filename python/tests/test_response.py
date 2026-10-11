"""Phase 7 Python responders: router quarantine and the weekly self-assessment."""

from __future__ import annotations

import sqlite3
from datetime import date
from pathlib import Path

import pytest
from helpers import EXAMPLE_PROTECTED

from gnomehome import cli
from gnomehome.assessment import assess_week
from gnomehome.audit import AuditLog, verify
from gnomehome.db import open_database
from gnomehome.protected import ProtectedTargetError, load_guard
from gnomehome.responders.router_quarantine import block_command, quarantine, release_command

DEVICE = "00:00:5e:00:53:51"
LAPTOP = "00-00-5E-00-53-01"  # in config/protected_assets.example.yaml


@pytest.fixture
def db(tmp_path: Path) -> sqlite3.Connection:
    conn = open_database(tmp_path / "x.sqlite3")
    yield conn
    conn.close()


def test_commands_are_fixed_and_built_only_from_a_valid_mac():
    assert block_command("00-00-5E-00-53-51") == (
        "iptables -C FORWARD -m mac --mac-source 00:00:5E:00:53:51 -j DROP 2>/dev/null || "
        "iptables -I FORWARD 1 -m mac --mac-source 00:00:5E:00:53:51 -j DROP"
    )
    assert "iptables -D FORWARD -m mac --mac-source 00:00:5E:00:53:51 -j DROP" in release_command(
        DEVICE
    )
    for hostile in ("00:00:5e:00:53:51; reboot", "$(reboot)", "00:00:5e:00:53:51 -j ACCEPT", ""):
        with pytest.raises(ValueError):
            block_command(hostile)


def test_a_protected_device_is_refused_before_anything_is_sent(db):
    audit = AuditLog(db)
    sent = []
    guard = load_guard(EXAMPLE_PROTECTED, audit=audit, actor="system:playbook")
    with pytest.raises(ProtectedTargetError):
        quarantine(guard, audit, LAPTOP, block=True, run=sent.append, live=True)
    assert sent == []
    row = db.execute("SELECT action, target, result, details FROM audit_log").fetchone()
    assert (row["action"], row["target"], row["result"]) == (
        "guard.refused",
        "protected:Work laptop",
        "refused",
    )
    assert "00:00:5e" not in row["details"].lower()  # label only, never the MAC
    assert verify(db).ok


def test_dry_run_sends_nothing_and_live_sends_one_command(db):
    audit = AuditLog(db)
    guard = load_guard(EXAMPLE_PROTECTED, audit=audit)
    sent = []
    dry = quarantine(guard, audit, DEVICE, block=True, run=sent.append, live=False, run_id="r1")
    assert dry.dry_run and sent == []
    live = quarantine(guard, audit, DEVICE, block=False, run=sent.append, live=True, run_id="r1")
    assert not live.dry_run and sent == [release_command(DEVICE)]
    results = [r[0] for r in db.execute("SELECT details FROM audit_log ORDER BY seq")]
    assert '"dry_run":true' in results[0] and '"dry_run":false' in results[1]


def test_cli_stays_dry_unless_config_allows_and_refuses_the_laptop(config_path, capsys):
    config = config_path
    assert cli.main(["--config", str(config), "migrate"]) == 0
    capsys.readouterr()
    assert (
        cli.main(["--config", str(config), "quarantine", "--mac", DEVICE, "--block", "--live"]) == 0
    )
    out = capsys.readouterr().out
    assert "Dry run" in out and "mode isn't" in out
    code = cli.main(["--config", str(config), "quarantine", "--mac", LAPTOP, "--block"])
    assert code == cli.EXIT_REFUSED
    err = capsys.readouterr().err
    assert "Work laptop" in err and "00:00:5e" not in err.lower()


# ------------------------------------------------------------------ self-assessment

WEEK_END = date(2026, 10, 11)
BEFORE = "2026-09-20T10:00:00.000Z"
DURING = "2026-10-08T10:00:00.000Z"


def seed(conn: sqlite3.Connection) -> None:
    conn.execute(
        "INSERT INTO asset (id, mac, first_seen, last_seen, last_ip, vendor) "
        "VALUES (1, '00:00:5e:00:53:51', ?, ?, '192.0.2.51', 'Example Camera Co')",
        (BEFORE, DURING),
    )
    conn.execute(
        "INSERT INTO asset (id, mac, first_seen, last_seen, last_ip) "
        "VALUES (2, '00:00:5e:00:53:99', ?, ?, '192.0.2.99')",
        (DURING, DURING),
    )
    conn.execute(
        "INSERT INTO service (id, asset_id, port, protocol, state, name, first_seen, last_seen) "
        "VALUES (1, 1, 22, 'tcp', 'open', 'ssh', ?, ?), (2, 1, 23, 'tcp', 'open', 'telnet', ?, ?),"
        " (3, 2, 443, 'tcp', 'open', 'https', ?, ?)",
        (BEFORE, DURING, DURING, DURING, DURING, DURING),
    )
    conn.execute(
        "INSERT INTO cve (cve_id, cvss_score, kev, updated_at) VALUES "
        "('CVE-2099-0001', 9.8, 1, ?), ('CVE-2099-0002', 5.0, 0, ?)",
        (DURING, DURING),
    )
    conn.execute(
        "INSERT INTO vulnerability (service_id, cve_id, match_method, first_seen, last_seen) "
        "VALUES (2, 'CVE-2099-0001', 'cpe_exact', ?, ?), (1, 'CVE-2099-0002', 'cpe_exact', ?, ?)",
        (DURING, DURING, BEFORE, DURING),
    )


def test_self_assessment_finds_what_changed_this_week(db):
    seed(db)
    result = assess_week(db, WEEK_END)
    assert result.week_start == "2026-10-05"
    assert len(result.new_devices) == 1 and "192.0.2.99" in result.new_devices[0]
    # Telnet is new on a known device; the new device's own port isn't counted twice.
    assert result.new_ports == [
        "tcp/23 (telnet) on the device at 192.0.2.51 (made by Example Camera Co)"
    ]
    assert result.new_cves == ["CVE-2099-0001, CVSS 9.8, known exploited"]
    assert result.kev_cves == 1
    incident = db.execute("SELECT * FROM incident").fetchone()
    assert incident["detection"] == "assessment.weekly" and incident["severity"] == "high"
    assert db.execute("SELECT kind FROM notification_outbox").fetchone()[0] == "weekly_assessment"
    assert assess_week(db, WEEK_END).incident_id is None  # once per week


def test_quiet_week_is_low_and_says_so(db):
    result = assess_week(db, WEEK_END)
    incident = db.execute("SELECT severity, title, next_steps FROM incident").fetchone()
    assert result.incident_id is not None
    assert incident["severity"] == "low" and incident["title"].endswith("nothing new")
    assert incident["next_steps"] == "Nothing to do this week."
