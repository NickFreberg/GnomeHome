"""Enrichment end to end with recorded feeds (no network) and the risk model on top."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from helpers import FIXTURES

from gnomehome.db import open_database
from gnomehome.enrich import run_enrichment
from gnomehome.feeds import FeedError, parse_nvd_page, pick_cvss
from gnomehome.risk import cve_points, level_for, run_scoring

FEEDS = FIXTURES / "feeds"
NOW = datetime(2026, 10, 11, 4, 0, tzinfo=UTC)
TS = "2026-10-11T03:00:00.000Z"


class FakeHttp:
    """Answers feed URLs with recorded files and remembers every request."""

    def __init__(self, fail: set[str] | None = None) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.fail = fail or set()

    def get_json(self, url: str, *, headers: dict | None = None):
        self.calls.append((url, headers or {}))
        for marker in self.fail:
            if marker in url:
                raise FeedError(f"simulated outage for {marker}")
        if "services.nvd.nist.gov" in url:
            name = "nvd_openssh_7.4.json" if "openssh" in url else "nvd_dnsmasq_2.85.json"
        elif "api.first.org" in url:
            name = "epss.json"
        elif "known_exploited" in url:
            name = "kev.json"
        else:
            raise AssertionError(f"unexpected URL {url}")
        return json.loads((FEEDS / name).read_text())


def add_asset(conn, mac, ip, *, vendor=None, device_type=None, protected=0):
    if protected:
        return conn.execute(
            "INSERT INTO asset (mac, protected, first_seen, last_seen) VALUES (?, 1, ?, ?)",
            (mac, TS, TS),
        ).lastrowid
    return conn.execute(
        "INSERT INTO asset (mac, last_ip, vendor, device_type, first_seen, last_seen) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (mac, ip, vendor, device_type, TS, TS),
    ).lastrowid


def add_service(conn, asset_id, port, product=None, version=None, cpe=None, last_seen=TS):
    conn.execute(
        "INSERT INTO service (asset_id, port, protocol, state, product, version, cpe, "
        "first_seen, last_seen) VALUES (?, ?, 'tcp', 'open', ?, ?, ?, ?, ?)",
        (asset_id, port, product, version, cpe, last_seen, last_seen),
    )


@pytest.fixture
def db(tmp_path: Path) -> sqlite3.Connection:
    conn = open_database(tmp_path / "x.sqlite3")
    router = add_asset(conn, "00:00:5e:00:53:a1", "192.0.2.1", vendor="Example Router Co",
                       device_type="WAP")  # fmt: skip
    add_service(conn, router, 53, "dnsmasq", "2.85", "cpe:/a:thekelleys:dnsmasq:2.85")
    camera = add_asset(conn, "00:00:5e:00:53:51", "192.0.2.51", device_type="webcam")
    add_service(conn, camera, 22, "OpenSSH", "7.4", "cpe:/a:openbsd:openssh:7.4")
    add_service(conn, camera, 23, "BusyBox telnetd")
    tv = add_asset(conn, "00:00:5e:00:53:40", "192.0.2.40", vendor="Example TV Inc")
    add_service(conn, tv, 8008, "http", None, "cpe:/a:example:tv_api")  # no version
    add_asset(conn, "00:00:5e:00:53:01", None, protected=1)
    yield conn
    conn.close()


def enrich(db, http=None, **kwargs):
    http = http or FakeHttp()
    pauses: list[float] = []
    result = run_enrichment(db, http, sleep=pauses.append, now=kwargs.pop("now", NOW), **kwargs)
    return result, http, pauses


def vulns(db) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for row in db.execute(
        "SELECT s.product, v.cve_id FROM vulnerability v JOIN service s ON s.id = v.service_id"
    ):
        out.setdefault(row[0], set()).add(row[1])
    return out


# ------------------------------------------------------------------ parsing


def test_parse_real_nvd_records_and_skip_rejected():
    records, _ = parse_nvd_page(json.loads((FEEDS / "nvd_dnsmasq_2.85.json").read_text()))
    ids = {r.cve_id for r in records}
    assert "CVE-2099-0003" not in ids  # rejected
    assert {"CVE-2022-0934", "CVE-2023-50387"} <= ids
    keytrap = next(r for r in records if r.cve_id == "CVE-2023-50387")
    assert keytrap.cvss_score == 7.5 and keytrap.cvss_version == "3.1"
    assert len(keytrap.rules) > 5  # one CVE, many products


def test_pick_cvss_prefers_primary_and_survives_odd_entries():
    metrics = {
        "ssvcV203": [{"source": "x"}],  # no type, no cvssData
        "cvssMetricV31": [
            {"type": "Secondary", "cvssData": {"version": "3.1", "baseScore": 9.0}},
            {"type": "Primary", "cvssData": {"version": "3.1", "baseScore": 7.5}},
        ],
    }
    assert pick_cvss(metrics)[0] == 7.5
    assert pick_cvss({}) == (None, None, None)


# ------------------------------------------------------------------ the job


def test_enrichment_matches_only_what_really_applies(db):
    result, http, pauses = enrich(db)
    assert result.errors == []
    assert result.services_mapped == 2  # the TV's CPE has no version
    assert vulns(db) == {
        "dnsmasq": {"CVE-2022-0934", "CVE-2023-28450", "CVE-2023-50387", "CVE-2099-0001"},
        "OpenSSH": {"CVE-2099-0101"},
    }
    methods = dict(db.execute("SELECT cve_id, match_method FROM vulnerability"))
    assert methods["CVE-2099-0001"] == "cpe_exact"
    assert methods["CVE-2022-0934"] == "cpe_version_range"
    assert pauses == [6.5, 6.5]  # NVD's rate limit without a key
    assert all("apiKey" not in headers for _, headers in http.calls)


def test_kev_and_epss_are_applied(db):
    enrich(db)
    row = db.execute("SELECT * FROM cve WHERE cve_id = 'CVE-2099-0101'").fetchone()
    assert row["kev"] == 1 and row["kev_ransomware"] == 1 and row["kev_due_date"] == "2099-01-23"
    assert row["epss_percentile"] == pytest.approx(0.98)
    assert db.execute("SELECT kev FROM cve WHERE cve_id = 'CVE-2022-0934'").fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM kev_entry").fetchone()[0] == 2


def test_api_key_is_sent_and_pauses_are_short(db):
    _, http, pauses = enrich(db, api_key="k-123")
    nvd_calls = [h for url, h in http.calls if "nvd.nist.gov" in url]
    assert nvd_calls and all(h == {"apiKey": "k-123"} for h in nvd_calls)
    assert pauses == [0.7, 0.7]


def test_fresh_lookups_are_not_repeated(db):
    enrich(db)
    result, http, _ = enrich(db, now=NOW + timedelta(hours=2))
    assert result.cpes_fresh == 2 and result.cpes_looked_up == 0
    assert not any("nvd.nist.gov" in url or "known_exploited" in url for url, _ in http.calls)
    later, _, _ = enrich(db, now=NOW + timedelta(hours=25))
    assert later.cpes_looked_up == 2


def test_upgraded_software_drops_stale_vulnerabilities(db):
    enrich(db)
    db.execute(
        "UPDATE service SET version = '2.90', cpe = 'cpe:/a:thekelleys:dnsmasq:2.90' "
        "WHERE product = 'dnsmasq'"
    )
    enrich(db, now=NOW + timedelta(hours=1))
    # 2.90 is past every fixed range; only the "2.86 and later" fake CVE applies.
    assert vulns(db)["dnsmasq"] == {"CVE-2099-0004"}


def test_an_nvd_outage_is_reported_but_other_feeds_still_run(db):
    result, _, _ = enrich(db, http=FakeHttp(fail={"nvd.nist.gov"}))
    assert len(result.errors) == 2 and all("NVD" in e for e in result.errors)
    assert result.kev_entries == 2


def test_protected_assets_never_get_services_or_scores(db):
    enrich(db)
    run_scoring(db)
    protected = db.execute("SELECT id FROM asset WHERE protected = 1").fetchone()[0]
    assert (
        db.execute("SELECT COUNT(*) FROM risk_score WHERE asset_id = ?", (protected,)).fetchone()[0]
        == 0
    )


# ------------------------------------------------------------------ risk model


def test_cve_points():
    assert cve_points(8.1, 0.2, True)[0] == 81.0  # KEV: full weight
    assert cve_points(10.0, 1.0, False)[0] == 100.0
    assert cve_points(10.0, 0.0, False)[0] == 25.0
    points, why = cve_points(None, None, False)
    assert points == 31.2 and "assumed 5.0" in why and "no EPSS" in why


@pytest.mark.parametrize(
    ("score", "kev", "want"),
    [(10, False, "low"), (30, False, "medium"), (59.9, False, "medium"), (60, False, "high"),
     (80, False, "critical"), (10, True, "high"), (90, True, "critical")],
)  # fmt: skip
def test_levels(score, kev, want):
    assert level_for(score, has_kev=kev) == want


def test_every_asset_gets_an_explained_score(db):
    enrich(db)
    scores = {s.asset_id: s for s in run_scoring(db)}
    assert len(scores) == 3  # all non-protected assets
    by_mac = {r["mac"]: r["id"] for r in db.execute("SELECT id, mac FROM asset")}
    camera = scores[by_mac["00:00:5e:00:53:51"]]
    assert camera.level == "critical"
    titles = [f.title for f in camera.factors]
    assert titles[0].startswith("CVE-2099-0101 in OpenSSH 7.4")
    assert "Telnet open (tcp/23)" in titles
    assert "CISA KEV" in camera.factors[0].why
    assert camera.score == pytest.approx(min(100, sum(f.points for f in camera.factors)))
    tv = scores[by_mac["00:00:5e:00:53:40"]]
    assert tv.level == "low"
    stored = json.loads(db.execute(
        "SELECT factors FROM risk_score WHERE asset_id = ?", (camera.asset_id,)
    ).fetchone()[0])  # fmt: skip
    assert stored["model"] == "risk-v1" and stored["summary"].startswith("Critical risk")


def test_closed_ports_stop_counting(db):
    camera = db.execute("SELECT id FROM asset WHERE mac = '00:00:5e:00:53:51'").fetchone()[0]
    db.execute("UPDATE service SET last_seen = '2026-10-08T00:00:00.000Z' WHERE port = 23")
    db.execute("UPDATE service SET last_seen = '2026-10-11T03:00:00.000Z' WHERE port = 22")
    titles = [f.title for s in run_scoring(db) if s.asset_id == camera for f in s.factors]
    assert not any("Telnet" in t for t in titles)
