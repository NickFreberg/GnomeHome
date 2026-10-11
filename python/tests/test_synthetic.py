"""Synthetic data: reproducible, realistic formats, labeled scenarios, protected device dropped."""

from __future__ import annotations

import hashlib
import ipaddress
import itertools
import json
import re
import statistics
from datetime import datetime
from pathlib import Path

import pytest
from helpers import EXAMPLE_PROTECTED

from gnomehome.db import open_database
from gnomehome.protected import load_guard
from gnomehome.router_log import parse_dhcp, parse_syslog_line
from gnomehome.synthetic.generate import generate
from gnomehome.synthetic.load import load_synthetic

HOURS = 6  # enough for every scenario; fast in tests

PIHOLE_LINE = re.compile(
    r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [ \d]\d \d\d:\d\d:\d\d dnsmasq\[\d+\]: "
    r"(query\[(A|AAAA|HTTPS)\] \S+ from [\d.]+"
    r"|forwarded \S+ to [\d.]+"
    r"|reply \S+ is \S+"
    r"|cached \S+ is \S+"
    r"|gravity blocked \S+ is \S+)$"
)
CONNTRACK_LINE = re.compile(
    r"^ipv4 +2 (tcp +6 \d+ ESTABLISHED|udp +17 \d+) "
    r"src=(?P<src>[\d.]+) dst=(?P<dst>[\d.]+) sport=(?P<sport>\d+) dport=\d+ "
    r"packets=\d+ bytes=(?P<bytes>\d+) "
    r"src=[\d.]+ dst=[\d.]+ sport=\d+ dport=\d+ packets=\d+ bytes=\d+ "
    r"\[ASSURED\] mark=0 zone=0 use=2$"
)


@pytest.fixture(scope="module")
def dataset(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("synth") / "seed-7"
    generate(out, seed=7, start_date="2026-10-05", hours=HOURS)
    return out


def _jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def _digest(folder: Path) -> str:
    h = hashlib.sha256()
    for path in sorted(p for p in folder.rglob("*") if p.is_file()):
        h.update(path.relative_to(folder).as_posix().encode())
        h.update(path.read_bytes())
    return h.hexdigest()


# ------------------------------------------------------------------ reproducibility


def test_same_seed_gives_identical_bytes(tmp_path: Path, dataset: Path):
    again = tmp_path / "again"
    generate(again, seed=7, start_date="2026-10-05", hours=HOURS)
    assert _digest(again) == _digest(dataset)


def test_different_seed_gives_different_data(tmp_path: Path, dataset: Path):
    other = tmp_path / "other"
    generate(other, seed=8, start_date="2026-10-05", hours=HOURS)
    assert _digest(other) != _digest(dataset)


# ------------------------------------------------------------------ formats


def test_pihole_log_lines_match_dnsmasq_format(dataset: Path):
    lines = (dataset / "dns" / "pihole.log").read_text().splitlines()
    assert lines
    bad = [line for line in lines if not PIHOLE_LINE.match(line)]
    assert bad == []


def test_conntrack_snapshots_match_proc_format_and_counters_grow(dataset: Path):
    lines = (dataset / "flows" / "conntrack_snapshots.txt").read_text().splitlines()
    assert sum(line.startswith("# snapshot ") for line in lines) == HOURS * 60
    seen: dict[tuple[str, str], int] = {}
    for line in lines:
        if line.startswith("#"):
            continue
        match = CONNTRACK_LINE.match(line)
        assert match, line
        key = (match["src"], match["sport"])
        assert int(match["bytes"]) >= seen.get(key, 0)  # counters never go backwards
        seen[key] = int(match["bytes"])


def test_every_address_is_fake_or_a_public_resolver(dataset: Path):
    allowed = [
        ipaddress.ip_network(n)
        for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
    ]
    # Pi-hole's upstream and the bypass resolvers, plus Pi-hole's "blocked" answers.
    public_resolvers = {"1.1.1.1", "8.8.8.8", "0.0.0.0", "::"}  # noqa: S104
    text = "\n".join(p.read_text() for p in dataset.rglob("*") if p.is_file())
    for raw in set(re.findall(r"(?<![\w.:])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])", text)):
        addr = ipaddress.ip_address(raw)
        assert raw in public_resolvers or any(addr in net for net in allowed), raw


# ------------------------------------------------------------------ scenarios (ground truth)


def test_beacon_is_periodic_within_jitter(dataset: Path):
    labels = json.loads((dataset / "labels.json").read_text())["scenarios"]["beacon"]
    times = [
        datetime.fromisoformat(q["ts"].replace("Z", "+00:00"))
        for q in _jsonl(dataset / "dns" / "queries.jsonl")
        if q["label"] == "beacon"
    ]
    gaps = [(b - a).total_seconds() for a, b in itertools.pairwise(times)]
    assert len(gaps) > 10
    period, jitter = labels["period_seconds"], labels["jitter"]
    assert all(period * (1 - jitter) - 1 <= g <= period * (1 + jitter) + 1 for g in gaps)
    assert statistics.pstdev(gaps) < period * jitter


def test_dga_burst_is_mostly_nxdomain(dataset: Path):
    dga = [q for q in _jsonl(dataset / "dns" / "queries.jsonl") if q["label"] == "dga"]
    assert len(dga) == 40
    assert sum(q["status"] == "nxdomain" for q in dga) == 38
    assert all(q["domain"].endswith(".test") for q in dga)


def test_known_bad_lookups_are_blocked_and_in_the_feed(dataset: Path):
    feed = {
        line
        for line in (dataset / "threat_feed.txt").read_text().splitlines()
        if line and not line.startswith("#")
    }
    bad = [q for q in _jsonl(dataset / "dns" / "queries.jsonl") if q["label"] == "known_bad"]
    assert len(bad) == 3
    assert all(q["status"] == "blocked" and q["domain"] in feed for q in bad)


def test_new_device_appears_only_after_it_joins(dataset: Path):
    labels = json.loads((dataset / "labels.json").read_text())["scenarios"]["new_device"]
    queries = [
        q for q in _jsonl(dataset / "dns" / "queries.jsonl") if q["device"] == labels["device"]
    ]
    assert queries
    assert min(q["ts"] for q in queries) >= labels["first_seen"]


def test_dns_bypass_device_never_asks_pihole_but_talks_to_public_resolvers(dataset: Path):
    queries = _jsonl(dataset / "dns" / "queries.jsonl")
    assert not any(q["device"] == "streaming-stick" for q in queries)
    flows = [f for f in _jsonl(dataset / "flows" / "flows.jsonl") if f["label"] == "dns_bypass"]
    assert any(f["dst_ip"] == "8.8.8.8" and f["dst_port"] == 53 for f in flows)
    assert any(f["dst_ip"] == "1.1.1.1" and f["dst_port"] == 443 for f in flows)


def test_exfil_flow_is_large_and_outbound(dataset: Path):
    exfil = [f for f in _jsonl(dataset / "flows" / "flows.jsonl") if f["label"] == "exfil"]
    assert len(exfil) == 1
    assert exfil[0]["bytes_out"] > 1_000_000_000 > exfil[0]["bytes_in"]


def test_protected_laptop_traffic_exists_in_raw_data(dataset: Path):
    # It must be present in the raw files, so the loader's drop is a real test.
    queries = _jsonl(dataset / "dns" / "queries.jsonl")
    assert any(q["client_ip"] == "192.0.2.10" for q in queries)


# ------------------------------------------------------------------ loading through the guard


LAPTOP_IDS = ("00:00:5e:00:53:01", "00:00:5e:00:53:02", "192.0.2.10")


def test_load_drops_every_protected_record(tmp_path: Path, dataset: Path):
    conn = open_database(tmp_path / "dev.sqlite3")
    guard = load_guard(EXAMPLE_PROTECTED)
    result = load_synthetic(conn, guard, dataset)

    queries = _jsonl(dataset / "dns" / "queries.jsonl")
    flows = _jsonl(dataset / "flows" / "flows.jsonl")
    router_lines = (dataset / "router" / "syslog.log").read_text().splitlines()
    protected_dns = sum(q["label"] == "protected" for q in queries)
    protected_flows = sum(f["label"] == "protected" for f in flows)
    protected_router = sum(any(i in line for i in LAPTOP_IDS) for line in router_lines)
    assert result.dropped_protected == protected_dns + protected_flows + protected_router
    assert result.dns_events == len(queries) - protected_dns
    assert result.flow_events == len(flows) - protected_flows

    every_row = " ".join(
        str(value)
        for table in ("event", "incident", "audit_log")
        for row in conn.execute(f"SELECT * FROM {table}")
        for value in tuple(row)
    )
    for identifier in (*LAPTOP_IDS, "192.0.2.88", "WORK-LAPTOP"):
        assert identifier not in every_row

    # The inventory comes from router DHCP (12 devices) plus the scan (the router itself),
    # and the laptop's two adapters are recorded as existence only.
    normal = conn.execute("SELECT COUNT(*) FROM asset WHERE protected = 0").fetchone()[0]
    assert normal == result.assets == 13
    assert result.services > 0
    protected = conn.execute("SELECT * FROM asset WHERE protected = 1").fetchall()
    assert sorted(r["mac"] for r in protected) == ["00:00:5e:00:53:01", "00:00:5e:00:53:02"]
    assert all(r["last_ip"] is None and r["hostname"] is None for r in protected)
    assert conn.execute("SELECT COUNT(*) FROM event WHERE synthetic = 0").fetchone()[0] == 0


def test_load_raises_the_expected_incidents(tmp_path: Path, dataset: Path):
    conn = open_database(tmp_path / "dev.sqlite3")
    result = load_synthetic(conn, load_guard(EXAMPLE_PROTECTED), dataset)
    labels = json.loads((dataset / "labels.json").read_text())["scenarios"]
    assert result.syslog.new_device_incidents == 1
    assert result.syslog.drift_incidents == 1
    incidents = {r["detection"]: r for r in conn.execute("SELECT * FROM incident")}
    new_device = json.loads(incidents["inventory.new_device"]["evidence"])
    assert new_device["mac"] == labels["new_device"]["mac"]
    drift = json.loads(incidents["guard.protected_drift"]["evidence"])
    assert drift["label"] == "Work laptop"
    assert drift["kind"] == "protected_mac_at_unlisted_ip"


def test_router_log_lines_all_parse(dataset: Path):
    lines = (dataset / "router" / "syslog.log").read_text().splitlines()
    assert lines
    assert all(parse_syslog_line(line) is not None for line in lines)
    dhcp = [parse_dhcp(parse_syslog_line(line)) for line in lines]
    assert sum(d is not None and d.kind == "DHCPACK" for d in dhcp) >= 13


def test_labels_are_never_stored(tmp_path: Path, dataset: Path):
    conn = open_database(tmp_path / "dev.sqlite3")
    load_synthetic(conn, load_guard(EXAMPLE_PROTECTED), dataset)
    attrs = " ".join(r[0] or "" for r in conn.execute("SELECT attrs FROM event"))
    assert "label" not in attrs and "beacon" not in attrs


def test_synthetic_scan_adds_vendors_and_services_but_never_the_laptop(
    tmp_path: Path, dataset: Path
):
    assert b"00:00:5E:00:53:01" not in (dataset / "nmap" / "services.xml").read_bytes()
    conn = open_database(tmp_path / "dev.sqlite3")
    load_synthetic(conn, load_guard(EXAMPLE_PROTECTED), dataset)
    camera = conn.execute(
        "SELECT a.vendor, a.device_type, COUNT(s.id) AS n FROM asset a "
        "JOIN service s ON s.asset_id = a.id WHERE a.last_ip = '192.0.2.51'"
    ).fetchone()
    assert camera["vendor"] == "Example Camera Co" and camera["device_type"] == "webcam"
    assert camera["n"] == 4
    assert conn.execute("SELECT COUNT(*) FROM incident").fetchone()[0] == 2  # scan is baseline
