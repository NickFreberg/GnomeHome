"""The plain-English incident log (FR-11): templates, the report, and protected devices."""

from __future__ import annotations

import json
import re
import stat
from pathlib import Path

import pytest
from helpers import EXAMPLE_PROTECTED

from gnomehome import cli, narrative, risk
from gnomehome.analytics.detect import Settings
from gnomehome.analytics.run import run_analysis
from gnomehome.db import open_database
from gnomehome.incidents import open_incident
from gnomehome.protected import load_guard
from gnomehome.report import ReportOptions, fetch, md_escape, to_json, to_markdown
from gnomehome.synthetic.generate import generate
from gnomehome.synthetic.load import load_synthetic

T1 = "2026-10-11T14:00:00.000Z"
T2 = "2026-10-11T15:30:00.000Z"
TS = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")
IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
MAC = re.compile(r"\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b", re.IGNORECASE)
DEVICE = narrative.describe_device("192.0.2.30", "Example Co", "den-pc")


def every_template() -> list[narrative.Narrative]:
    return [
        narrative.new_device(
            ip="192.0.2.99",
            mac="02:00:5e:00:53:99",
            vendor=None,
            hostname="Galaxy",
            seen_at=T1,
            source="router DHCP",
        ),
        narrative.protected_drift(
            label="Work laptop",
            kind="protected_mac_at_unlisted_ip",
            source="router DHCP",
            seen_at=T1,
        ),
        narrative.protected_drift(
            label="Work laptop",
            kind="unknown_mac_at_protected_ip",
            source="router DHCP",
            seen_at=T1,
        ),
        narrative.beaconing(
            device=DEVICE,
            domain="c2.evil.test",
            count=40,
            first_ts=T1,
            last_ts=T2,
            details={"period_seconds": 300.0, "jitter": 0.02, "first_seen": T1},
        ),
        narrative.dga(
            device=DEVICE,
            first_ts=T1,
            last_ts=T2,
            details={
                "distinct_names": 30,
                "nxdomain_share": 0.9,
                "examples": ["x1k2j3.test", "q9w8e7.test"],
                "mean_score": 0.7,
            },
        ),
        narrative.threat_intel(
            device=DEVICE,
            domain="cdn.malware-drop.test",
            count=1,
            first_ts=T1,
            last_ts=T1,
            details={
                "indicator": "malware-drop.test",
                "sources": ["urlhaus"],
                "resolved": 1,
                "blocked": 0,
            },
        ),
        narrative.dns_bypass(
            device=DEVICE,
            count=12,
            first_ts=T1,
            last_ts=T2,
            details={"resolvers": ["8.8.8.8"], "methods": {"plain DNS": 12}},
        ),
        narrative.risk_increase(
            device=DEVICE,
            old_level="medium",
            new_level="critical",
            score=86,
            reasons=["CVE-2099-0001 (known exploited)", "Telnet open"],
            scored_at=T1,
        ),
        narrative.weekly_assessment(
            week_start="2026-10-05",
            week_end="2026-10-11",
            new_devices=[DEVICE],
            new_ports=[],
            new_cves=["CVE-2099-0001, CVSS 9.8, known exploited"],
            kev_cves=1,
            high_risk_devices=1,
        ),
    ]


@pytest.mark.parametrize("story", every_template(), ids=lambda s: s.detection)
def test_every_template_answers_every_question(story):
    assert story.severity in ("low", "medium", "high", "critical")
    assert TS.match(story.occurred_at)
    for part in (story.title, story.device, story.what_happened, story.why_it_matters,
                 story.next_steps):  # fmt: skip
        assert part and part.strip() == part
    assert story.summary.startswith("What happened: ")
    assert "Why it matters: " in story.summary and "What to do: " in story.summary
    assert story.confidence is None or 0 <= story.confidence <= 1
    assert story.mitre_technique is None or re.match(r"^T\d{4}(\.\d{3})?$", story.mitre_technique)


def test_drift_names_the_laptop_by_label_only():
    guard = load_guard(EXAMPLE_PROTECTED)
    for story in every_template()[1:3]:
        text = " ".join((story.title, story.device, story.summary))
        assert "Work laptop" in text
        assert not IPV4.search(text) and not MAC.search(text)
        assert not guard.text_mentions_protected(text)


def test_device_supplied_text_is_quoted_cleaned_and_labeled():
    assert narrative.quote_untrusted('evil"\x1b[31mname') == "evil'?[31mname"
    assert narrative.quote_untrusted("x" * 100).endswith("…")
    assert narrative.quote_untrusted("  \n ") is None
    assert DEVICE == (
        'the device at 192.0.2.30 (made by Example Co, calls itself "den-pc", '
        "a name the device chose)"
    )
    story = every_template()[0]
    assert '"Galaxy" (a device-supplied name, which can be false)' in story.what_happened
    assert "randomized" in story.what_happened


def test_single_events_read_naturally():
    intel = every_template()[5]
    assert "once, at 2026-10-11T14:00:00.000Z" in intel.what_happened
    assert "it was answered, so the device could reach it" in intel.what_happened


# ------------------------------------------------------------------ report


@pytest.fixture
def db(tmp_path: Path):
    conn = open_database(tmp_path / "x.sqlite3")
    yield conn
    conn.close()


def test_markdown_report_neutralizes_hostile_names(db):
    hostile = "[click me](https://evil.test) <img src=x>"
    story = narrative.beaconing(
        device=narrative.describe_device("192.0.2.31", None, hostile),
        domain="`code`*bold*|pipe.www.evil.test",
        count=20,
        first_ts=T1,
        last_ts=T2,
        details={"period_seconds": 60.0, "jitter": 0.01, "first_seen": T1},
    )
    open_incident(db, story, dedup_key="x")
    text = to_markdown(fetch(db, ReportOptions()), ReportOptions(generated_at=T2))
    assert "[T1071.004](https://attack.mitre.org/techniques/T1071/004/)" in text
    body = text.split("**What happened.**", 1)[1].split("\n", 1)[0]
    assert not re.search(r"(?<!\\)[<\[\]`*|]", body)  # every special character is escaped
    assert "\\](hxxps://evil.test)" in body and "https://" not in body
    assert "www.evil" not in body and "www\\[.\\]evil.test" in body
    assert "\\`code\\`\\*bold\\*\\|pipe" in body
    title = text.split("## #1", 1)[1].split("\n", 1)[0]
    assert "\\`code\\`" in title and "www\\[.\\]" in title


def test_json_report_and_filters(db):
    for story in every_template():
        open_incident(db, story)
    db.execute("UPDATE incident SET status = 'resolved' WHERE detection = 'dns.dga'")
    db.execute(
        "UPDATE incident SET occurred_at = '2026-10-01T00:00:00.000Z' "
        "WHERE detection = 'dns.bypass'"
    )
    # An incident from before the structured log has only a summary.
    db.execute(
        "INSERT INTO incident (created_at, updated_at, detection, severity, title, summary) "
        "VALUES (?, ?, 'legacy', 'low', 'Old one', 'An older summary.')",
        (T1, T1),
    )
    open_only = fetch(db, ReportOptions())
    assert "dns.dga" not in {i["detection"] for i in open_only}
    assert len(fetch(db, ReportOptions(include_closed=True))) == len(every_template()) + 1
    recent = fetch(db, ReportOptions(since="2026-10-10T00:00:00.000Z"))
    assert "dns.bypass" not in {i["detection"] for i in recent}
    data = json.loads(to_json(open_only, ReportOptions(generated_at=T2)))
    legacy = next(i for i in data["incidents"] if i["detection"] == "legacy")
    assert legacy["what_happened"] == "An older summary."
    assert all({"device", "why_it_matters", "next_steps"} <= set(i) for i in data["incidents"])


def test_empty_report_is_calm(db):
    text = to_markdown([], ReportOptions(generated_at=T2))
    assert "All quiet in the garden" in text


def test_md_escape_keeps_prose_readable():
    assert md_escape("Pi-hole blocked it (twice).") == "Pi-hole blocked it (twice)."
    assert md_escape("a\nb\tc") == "a b c"


def test_cli_writes_a_private_report(config_path, tmp_path, capsys):
    assert cli.main(["--config", str(config_path), "migrate"]) == 0
    out = tmp_path / "reports" / "log.md"
    assert cli.main(["--config", str(config_path), "incident-report", "--out", str(out)]) == 0
    assert "All quiet in the garden" in out.read_text()
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    capsys.readouterr()
    assert cli.main(["--config", str(config_path), "incident-report", "--format", "json",
                     "--out", "-"]) == 0  # fmt: skip
    assert json.loads(capsys.readouterr().out)["incidents"] == []


# ------------------------------------------------------------------ risk and synthetic ground truth


def test_risk_rising_to_high_opens_one_incident(db, monkeypatch):
    db.execute(
        "INSERT INTO asset (mac, first_seen, last_seen, last_ip, vendor) "
        "VALUES ('00:00:5e:00:53:44', ?, ?, '192.0.2.44', 'Example Co')",
        (T1, T1),
    )
    level = {"value": "medium"}

    def fake_score(conn, asset):
        factor = risk.Factor("vulnerability", "CVE-2099-0001 (known exploited)", 70.0, "why")
        return risk.AssetScore(asset["id"], 70.0, level["value"], (factor,), "summary")

    monkeypatch.setattr(risk, "score_asset", fake_score)
    risk.run_scoring(db, score_date="2026-10-10")
    assert db.execute("SELECT COUNT(*) FROM incident").fetchone()[0] == 0
    level["value"] = "high"
    risk.run_scoring(db, score_date="2026-10-11")
    risk.run_scoring(db, score_date="2026-10-11")  # a rerun the same day adds nothing
    rows = db.execute("SELECT * FROM incident").fetchall()
    assert len(rows) == 1
    assert rows[0]["detection"] == "risk.increase"
    assert "rose from medium to high" in rows[0]["what_happened"]
    assert "CVE-2099-0001" in rows[0]["what_happened"]


@pytest.fixture(scope="module")
def synthetic_incidents(tmp_path_factory):
    out = tmp_path_factory.mktemp("synth") / "seed-11"
    generate(out, seed=11, start_date="2026-10-05", hours=24)
    conn = open_database(out.parent / "dev.sqlite3")
    load_synthetic(conn, load_guard(EXAMPLE_PROTECTED), out)
    run_analysis(conn, Settings())
    rows = conn.execute("SELECT * FROM incident").fetchall()
    conn.close()
    return rows


def test_synthetic_incidents_are_complete_and_never_mention_the_laptop(synthetic_incidents):
    guard = load_guard(EXAMPLE_PROTECTED)
    detections = sorted(r["detection"] for r in synthetic_incidents)
    assert detections == [
        "dns.beaconing", "dns.bypass", "dns.dga", "dns.threat_intel", "dns.threat_intel",
        "dns.threat_intel", "guard.protected_drift", "inventory.new_device",
    ]  # fmt: skip
    for row in synthetic_incidents:
        for column in ("occurred_at", "device", "what_happened", "why_it_matters", "next_steps"):
            assert row[column], (row["detection"], column)
        text = " ".join(str(row[c]) for c in ("title", "device", "summary", "evidence"))
        assert not guard.text_mentions_protected(text), row["detection"]
