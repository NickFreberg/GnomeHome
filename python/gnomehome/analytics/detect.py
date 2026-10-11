"""The DNS detectors (FR-09, FR-10): beaconing, DGA bursts, and threat-intel matches.

Each detector reads DNS events from SQLite and returns findings. The job in
``analytics/run.py`` turns findings into incidents.

* **Beaconing (T1071.004).** A device looks up the same domain at a steady
  rhythm. Many benign apps and IoT devices do this too, so a finding needs the
  rhythm to be regular *and* new: the device started talking to that domain
  after the baseline period. Periodic behavior present from the start is
  treated as how that device normally works.
* **DGA bursts (T1568.002).** Malware that generates domain names tries many
  of them quickly, and most don't exist. A finding needs at least
  ``dga_burst`` machine-looking names from one device within
  ``dga_window_minutes``, and at least half of them answered NXDOMAIN.
* **Threat intel.** A lookup of a domain, or any parent domain, on a
  known-bad list.
"""

from __future__ import annotations

import itertools
import sqlite3
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta

from gnomehome.analytics.domains import dga_score, normalize_domain, parents, registered_domain
from gnomehome.timeutil import format_ts, parse_ts


@dataclass(frozen=True)
class Settings:
    beacon_min_events: int = 12
    beacon_max_jitter: float = 0.15
    beacon_min_period_s: float = 30.0
    beacon_max_period_s: float = 6 * 3600.0
    beacon_window_hours: int = 24
    dga_threshold: float = 0.45
    dga_burst: int = 8
    dga_window_minutes: int = 10
    baseline_minutes: int = 60


@dataclass
class Finding:
    detection: str
    src_ip: str
    asset_id: int | None
    domain: str
    first_ts: str
    last_ts: str
    count: int
    details: dict = field(default_factory=dict)


# --------------------------------------------------------------------------
# Per-device domain history
# --------------------------------------------------------------------------


def update_device_domains(conn: sqlite3.Connection, since: str | None) -> int:
    """Fold DNS events newer than ``since`` into ``device_domain``. Returns rows touched."""
    rows = conn.execute(
        """
        SELECT src_ip, lower(rtrim(domain, '.')) AS d, MAX(asset_id), MIN(ts), MAX(ts), COUNT(*)
          FROM event
         WHERE kind = 'dns' AND (? IS NULL OR ts > ?)
         GROUP BY src_ip, d
        """,
        (since, since),
    ).fetchall()
    for src_ip, domain, asset_id, first, last, count in rows:
        conn.execute(
            """
            INSERT INTO device_domain (src_ip, domain, asset_id, first_seen, last_seen, queries)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (src_ip, domain) DO UPDATE SET
                asset_id = COALESCE(excluded.asset_id, device_domain.asset_id),
                first_seen = MIN(device_domain.first_seen, excluded.first_seen),
                last_seen = MAX(device_domain.last_seen, excluded.last_seen),
                queries = device_domain.queries + excluded.queries
            """,
            (src_ip, domain, asset_id, first, last, count),
        )
    return len(rows)


def data_start(conn: sqlite3.Connection) -> str | None:
    return conn.execute("SELECT MIN(ts) FROM event WHERE kind = 'dns'").fetchone()[0]


def data_end(conn: sqlite3.Connection) -> str | None:
    return conn.execute("SELECT MAX(ts) FROM event WHERE kind = 'dns'").fetchone()[0]


# --------------------------------------------------------------------------
# Beaconing
# --------------------------------------------------------------------------


def detect_beacons(conn: sqlite3.Connection, end: str, s: Settings) -> list[Finding]:
    start = data_start(conn)
    if start is None:
        return []
    baseline_end = parse_ts(start) + timedelta(minutes=s.baseline_minutes)
    window_start = format_ts(parse_ts(end) - timedelta(hours=s.beacon_window_hours))
    series: dict[tuple[str, str], list[str]] = defaultdict(list)
    assets: dict[str, int | None] = {}
    for src_ip, domain, ts, asset_id in conn.execute(
        "SELECT src_ip, lower(rtrim(domain, '.')), ts, asset_id FROM event "
        "WHERE kind = 'dns' AND ts > ? AND ts <= ? ORDER BY ts",
        (window_start, end),
    ):
        series[(src_ip, domain)].append(ts)
        assets.setdefault(src_ip, asset_id)

    findings = []
    for (src_ip, domain), stamps in series.items():
        if len(stamps) < s.beacon_min_events:
            continue
        times = [parse_ts(t) for t in stamps]
        gaps = [(b - a).total_seconds() for a, b in itertools.pairwise(times) if b > a]
        if len(gaps) < s.beacon_min_events - 1:
            continue
        period = statistics.median(gaps)
        if not s.beacon_min_period_s <= period <= s.beacon_max_period_s:
            continue
        # Robust jitter: the median distance from the period, as a share of it.
        jitter = statistics.median(abs(g - period) for g in gaps) / period
        steady = sum(abs(g - period) <= 0.25 * period for g in gaps) / len(gaps)
        if jitter > s.beacon_max_jitter or steady < 0.9:
            continue
        first = conn.execute(
            "SELECT first_seen FROM device_domain WHERE src_ip = ? AND domain = ?",
            (src_ip, domain),
        ).fetchone()
        first_seen = parse_ts(first[0]) if first else times[0]
        if first_seen < baseline_end:
            continue  # periodic since the baseline: this device's normal behavior
        findings.append(
            Finding(
                "dns.beaconing",
                src_ip,
                assets.get(src_ip),
                domain,
                stamps[0],
                stamps[-1],
                len(stamps),
                {
                    "period_seconds": round(period, 1),
                    "jitter": round(jitter, 3),
                    "steady_share": round(steady, 3),
                    "first_seen": format_ts(first_seen),
                },
            )
        )
    return findings


# --------------------------------------------------------------------------
# DGA bursts
# --------------------------------------------------------------------------


def detect_dga(conn: sqlite3.Connection, since: str | None, end: str, s: Settings) -> list[Finding]:
    rows = conn.execute(
        "SELECT src_ip, asset_id, domain, status, ts FROM event "
        "WHERE kind = 'dns' AND (? IS NULL OR ts > ?) AND ts <= ? ORDER BY src_ip, ts",
        (since, since, end),
    ).fetchall()
    by_device: dict[str, list[tuple]] = defaultdict(list)
    for src_ip, asset_id, domain, status, ts in rows:
        score = dga_score(domain)
        if score >= s.dga_threshold:
            by_device[src_ip].append(
                (parse_ts(ts), ts, normalize_domain(domain), status, asset_id, score)
            )

    findings = []
    window = timedelta(minutes=s.dga_window_minutes)
    for src_ip, hits in by_device.items():
        left = 0
        best: list[tuple] = []
        for right in range(len(hits)):
            while hits[right][0] - hits[left][0] > window:
                left += 1
            current = hits[left : right + 1]
            if len({registered_domain(h[2]) for h in current}) > len(
                {registered_domain(h[2]) for h in best}
            ):
                best = current
        names = {registered_domain(h[2]) for h in best}
        if len(names) < s.dga_burst:
            continue
        nxdomain = sum(h[3] == "nxdomain" for h in best) / len(best)
        if nxdomain < 0.5:
            continue
        findings.append(
            Finding(
                "dns.dga",
                src_ip,
                best[0][4],
                best[0][2],
                best[0][1],
                best[-1][1],
                len(best),
                {
                    "distinct_names": len(names),
                    "nxdomain_share": round(nxdomain, 2),
                    "examples": sorted(names)[:5],
                    "mean_score": round(sum(h[5] for h in best) / len(best), 2),
                },
            )
        )
    return findings


# --------------------------------------------------------------------------
# Threat intel
# --------------------------------------------------------------------------


def detect_threat_intel(conn: sqlite3.Connection, since: str | None, end: str) -> list[Finding]:
    indicators: dict[str, list[str]] = defaultdict(list)
    for indicator, source in conn.execute("SELECT indicator, source FROM threat_indicator"):
        indicators[indicator].append(source)
    if not indicators:
        return []
    grouped: dict[tuple[str, str], Finding] = {}
    for src_ip, asset_id, domain, status, ts in conn.execute(
        "SELECT src_ip, asset_id, domain, status, ts FROM event "
        "WHERE kind = 'dns' AND (? IS NULL OR ts > ?) AND ts <= ? ORDER BY ts",
        (since, since, end),
    ):
        hit = next((p for p in parents(domain) if p in indicators), None)
        if hit is None:
            continue
        key = (src_ip, hit)
        if key not in grouped:
            grouped[key] = Finding(
                "dns.threat_intel",
                src_ip,
                asset_id,
                normalize_domain(domain),
                ts,
                ts,
                0,
                {"indicator": hit, "sources": sorted(indicators[hit]), "resolved": 0, "blocked": 0},
            )
        finding = grouped[key]
        finding.count += 1
        finding.last_ts = ts
        finding.details["blocked" if status == "blocked" else "resolved"] += 1
    return list(grouped.values())
