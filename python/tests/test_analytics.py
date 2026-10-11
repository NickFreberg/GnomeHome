"""DNS analytics: domain helpers, feeds, detectors, and a ground-truth run on synthetic data."""

from __future__ import annotations

import random
import string
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from helpers import EXAMPLE_PROTECTED

from gnomehome.analytics.detect import Settings
from gnomehome.analytics.domains import dga_score, parents, registered_domain
from gnomehome.analytics.intel import FeedSpec, parse_feed, refresh_feeds
from gnomehome.analytics.run import run_analysis
from gnomehome.db import open_database
from gnomehome.feeds import FeedError
from gnomehome.protected import load_guard
from gnomehome.synthetic.generate import generate
from gnomehome.synthetic.load import load_synthetic
from gnomehome.timeutil import format_ts

T0 = datetime(2026, 10, 5, tzinfo=UTC)


# ------------------------------------------------------------------ domains


@pytest.mark.parametrize(
    ("domain", "want"),
    [
        ("a.b.example.com", "example.com"),
        ("example.co.uk", "example.co.uk"),
        ("x.example.co.uk", "example.co.uk"),
        ("WWW.Example.COM.", "example.com"),
        ("localhost", "localhost"),
    ],
)
def test_registered_domain(domain, want):
    assert registered_domain(domain) == want


def test_parents_stop_at_the_registered_domain():
    assert parents("a.b.example.com") == ["a.b.example.com", "b.example.com", "example.com"]


def test_dga_score_separates_human_and_generated_names():
    benign = [
        "googlesyndication.com",
        "connectivitycheck.gstatic.com",
        "scontent.cdninstagram.com",
        "ipv4-c001.1.nflxvideo.net",
        "settings-win.data.microsoft.com",
        "wikipedia.org",
    ]
    assert max(dga_score(d) for d in benign) < 0.5
    rng = random.Random(7)
    generated = [
        "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(16)) + ".test"
        for _ in range(100)
    ]
    assert sum(dga_score(d) >= 0.45 for d in generated) >= 95
    assert dga_score("short.com") == 0.0


# ------------------------------------------------------------------ feeds


def test_parse_hosts_and_domains_formats():
    hosts = (
        "# comment\n127.0.0.1\tbad.example.com\n0.0.0.0 evil.test # trailing\n127.0.0.1 localhost\n"
    )
    assert parse_feed(hosts, "hosts") == {"bad.example.com", "evil.test"}
    plain = "bad.example.com\n\nnot a domain\nEVIL.TEST.\n-bad-.com\n"
    assert parse_feed(plain, "domains") == {"bad.example.com", "evil.test"}


class TextClient:
    def __init__(self, text: str | None) -> None:
        self.text = text

    def get_text(self, url, *, headers=None):
        if self.text is None:
            raise FeedError("simulated outage")
        return self.text


def test_refresh_replaces_a_feed_and_keeps_it_on_failure(tmp_path: Path):
    conn = open_database(tmp_path / "x.sqlite3")
    spec = FeedSpec("urlhaus", "hosts", url="https://feed.example/hosts")
    assert refresh_feeds(conn, TextClient("0.0.0.0 a.test\n0.0.0.0 b.test\n"), [spec]) == {
        "urlhaus": 2
    }
    refresh_feeds(conn, TextClient("0.0.0.0 b.test\n"), [spec])
    assert [r[0] for r in conn.execute("SELECT indicator FROM threat_indicator")] == ["b.test"]
    outcome = refresh_feeds(conn, TextClient(None), [spec])["urlhaus"]
    assert outcome.startswith("error")
    assert conn.execute("SELECT COUNT(*) FROM threat_indicator").fetchone()[0] == 1  # kept
    local = tmp_path / "list.txt"
    local.write_text("c.test\n")
    assert refresh_feeds(conn, TextClient(None), [FeedSpec("mine", "domains", path=local)]) == {
        "mine": 1
    }


# ------------------------------------------------------------------ detectors on hand-made events


def add_dns(conn, ts: datetime, ip: str, domain: str, status: str = "forwarded") -> None:
    conn.execute(
        "INSERT INTO event (ts, kind, source, src_ip, domain, status) "
        "VALUES (?, 'dns', 'test', ?, ?, ?)",
        (format_ts(ts), ip, domain, status),
    )


@pytest.fixture
def db(tmp_path: Path):
    conn = open_database(tmp_path / "x.sqlite3")
    yield conn
    conn.close()


def detections(result) -> list[str]:
    return sorted(f.detection for f in result.findings)


def test_new_periodic_behavior_is_a_beacon_but_baseline_behavior_is_not(db):
    add_dns(db, T0, "192.0.2.5", "warmup.example")
    for i in range(40):  # an IoT device checking in since the start: baseline
        add_dns(db, T0 + timedelta(seconds=60 * i), "192.0.2.20", "iot.vendor.example")
    for i in range(40):  # something new, starting three hours later
        add_dns(
            db, T0 + timedelta(hours=3, seconds=300 * i + (i % 3)), "192.0.2.21", "c2.evil.test"
        )
    result = run_analysis(db, Settings())
    beacons = [f for f in result.findings if f.detection == "dns.beaconing"]
    assert [(f.src_ip, f.domain) for f in beacons] == [("192.0.2.21", "c2.evil.test")]
    assert beacons[0].details["period_seconds"] == pytest.approx(300, abs=2)


def test_irregular_lookups_are_not_beacons(db):
    rng = random.Random(3)
    add_dns(db, T0, "192.0.2.5", "warmup.example")
    t = T0 + timedelta(hours=2)
    for _ in range(40):
        t += timedelta(seconds=rng.uniform(30, 900))
        add_dns(db, t, "192.0.2.21", "www.example.com")
    assert detections(run_analysis(db, Settings())) == []


def test_dga_burst_needs_nxdomain_and_volume(db):
    rng = random.Random(5)
    names = [
        "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(16)) + ".test"
        for _ in range(12)
    ]
    for i, name in enumerate(names):  # resolving: not a DGA burst
        add_dns(db, T0 + timedelta(seconds=i), "192.0.2.30", name, "forwarded")
    assert "dns.dga" not in detections(run_analysis(db, Settings()))
    for i, name in enumerate(names):
        add_dns(db, T0 + timedelta(minutes=30, seconds=i), "192.0.2.31", "x" + name, "nxdomain")
    result = run_analysis(db, Settings())
    assert [f.src_ip for f in result.findings if f.detection == "dns.dga"] == ["192.0.2.31"]


def test_threat_intel_matches_parent_domains_and_reports_blocking(db):
    db.execute(
        "INSERT INTO threat_indicator (indicator, kind, source, added_at) VALUES "
        "('evil.test', 'domain', 'feed', '2026-10-05T00:00:00.000Z')"
    )
    add_dns(db, T0, "192.0.2.23", "cdn.evil.test", "blocked")
    add_dns(db, T0 + timedelta(seconds=5), "192.0.2.23", "evil.test", "forwarded")
    result = run_analysis(db, Settings())
    intel = [f for f in result.findings if f.detection == "dns.threat_intel"]
    assert len(intel) == 1 and intel[0].details == {
        "indicator": "evil.test",
        "sources": ["feed"],
        "resolved": 1,
        "blocked": 1,
    }
    incident = db.execute("SELECT severity, summary FROM incident").fetchone()
    assert incident["severity"] == "high"  # one lookup got through


def test_rerunning_never_duplicates_incidents(db):
    add_dns(db, T0, "192.0.2.5", "warmup.example")
    for i in range(40):
        add_dns(db, T0 + timedelta(hours=3, seconds=300 * i), "192.0.2.21", "c2.evil.test")
    assert run_analysis(db, Settings()).incidents_opened == 1
    assert run_analysis(db, Settings()).incidents_opened == 0


# ------------------------------------------------------------------ ground truth on synthetic data


@pytest.fixture(scope="module")
def synthetic_day(tmp_path_factory):
    out = tmp_path_factory.mktemp("synth") / "seed-11"
    generate(out, seed=11, start_date="2026-10-05", hours=24)
    conn = open_database(out.parent / "dev.sqlite3")
    load_synthetic(conn, load_guard(EXAMPLE_PROTECTED), out)
    result = run_analysis(conn, Settings())
    yield conn, result, out
    conn.close()


def test_synthetic_scenarios_are_found_with_no_false_positives(synthetic_day):
    _, result, _ = synthetic_day
    found = sorted((f.detection, f.src_ip, f.domain) for f in result.findings)
    assert found == [
        ("dns.beaconing", "192.0.2.51", "status.cloudsync-update.test"),  # the camera
        ("dns.dga", "192.0.2.30", found[1][2]),  # the family laptop
        ("dns.threat_intel", "192.0.2.23", "coinminer-pool.test"),  # the kid's tablet
        ("dns.threat_intel", "192.0.2.23", "malware-drop.test"),
        ("dns.threat_intel", "192.0.2.23", "phish-login-verify.test"),
    ]


def test_iot_check_ins_and_the_protected_laptop_never_appear(synthetic_day):
    conn, result, _ = synthetic_day
    assert all(f.src_ip != "192.0.2.10" for f in result.findings)
    assert all("vendor.example" not in f.domain for f in result.findings)
    assert (
        conn.execute("SELECT COUNT(*) FROM device_domain WHERE src_ip = '192.0.2.10'").fetchone()[0]
        == 0
    )
