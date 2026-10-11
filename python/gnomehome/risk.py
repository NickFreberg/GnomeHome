"""Per-asset daily risk scores (FR-05). Model ``risk-v1``, documented in docs/risk-model.md.

Every point in a score comes from a named factor with a plain-English reason, so
the top risks are always explainable (Phase 3's "done when").

    score = min(100, vulnerabilities + exposure + context)

* **Vulnerabilities**: each matched CVE on a currently open service is worth
  ``CVSS x 10 x likelihood``. Likelihood is 1.0 when the CVE is in CISA KEV
  (known exploited), otherwise ``0.25 + 0.75 x EPSS percentile``. The worst CVE
  counts in full, and each other serious one (40 points or more) adds 5, up to 20.
* **Exposure**: risky open ports (Telnet, SMB, RDP, ...) add fixed points, and
  every other open port adds 1 (up to 10).
* **Context**: network gear and IoT device types, and unknown manufacturers,
  add a few points.

Levels follow the design system's risk scale: low under 30, medium under 60,
high under 80, critical from 80. A KEV CVE makes an asset at least high.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, dataclass
from datetime import timedelta

from gnomehome.db import transaction
from gnomehome.timeutil import parse_ts, utc_now

MODEL_VERSION = "risk-v1"
UNKNOWN_CVSS = 5.0
UNKNOWN_PERCENTILE = 0.5
SERIOUS_CVE = 40.0
MAX_EXTRA_CVE_POINTS = 20.0
MAX_OTHER_PORT_POINTS = 10.0
#: A service counts as currently open if seen within this long of the asset's latest scan.
OPEN_WINDOW = timedelta(hours=24)

#: tcp port -> (name, points, why)
RISKY_PORTS: dict[int, tuple[str, float, str]] = {
    23: ("Telnet", 15, "sends logins unencrypted and is a favorite target of IoT botnets"),
    2323: ("Telnet (alternate port)", 15, "sends logins unencrypted; common on IoT devices"),
    21: ("FTP", 8, "sends logins and files unencrypted"),
    445: ("SMB file sharing", 10, "a frequent target of worms and ransomware"),
    139: ("NetBIOS", 6, "legacy Windows file sharing, rarely needed today"),
    3389: ("Remote Desktop", 10, "a frequent target of password-guessing attacks"),
    5900: ("VNC remote screen", 10, "often weakly protected remote control"),
    1883: ("MQTT", 6, "IoT messaging that is often left without a password"),
    554: ("RTSP video stream", 6, "camera streams are often viewable without a password"),
    5000: ("UPnP", 5, "lets devices open router ports on their own"),
    8291: ("MikroTik Winbox", 8, "router management port often targeted"),
}
NETWORK_GEAR_TYPES = {"WAP", "router", "switch", "firewall", "broadband router"}
IOT_TYPES = {"webcam", "media device", "printer", "power-device", "specialized", "storage-misc"}
LEVELS = (("low", 30.0), ("medium", 60.0), ("high", 80.0))


@dataclass(frozen=True)
class Factor:
    kind: str  # vulnerability, exposure, context
    title: str
    points: float
    why: str


@dataclass(frozen=True)
class AssetScore:
    asset_id: int
    score: float
    level: str
    factors: tuple[Factor, ...]
    summary: str


def level_for(score: float, *, has_kev: bool = False) -> str:
    level = "critical"
    for name, upper in LEVELS:
        if score < upper:
            level = name
            break
    if has_kev and level in ("low", "medium"):
        return "high"
    return level


def cve_points(cvss: float | None, percentile: float | None, kev: bool) -> tuple[float, str]:
    base = cvss if cvss is not None else UNKNOWN_CVSS
    if kev:
        likelihood, how = 1.0, "listed in CISA KEV (known to be exploited)"
    else:
        pct = percentile if percentile is not None else UNKNOWN_PERCENTILE
        likelihood = 0.25 + 0.75 * pct
        how = f"EPSS {pct:.0%} percentile" if percentile is not None else "no EPSS score yet"
    cvss_text = f"CVSS {cvss:.1f}" if cvss is not None else "no CVSS score (assumed 5.0)"
    return round(base * 10 * likelihood, 1), f"{cvss_text}, {how}"


def score_asset(conn: sqlite3.Connection, asset: sqlite3.Row) -> AssetScore:
    services = _open_services(conn, asset["id"])
    factors: list[Factor] = []

    # Vulnerabilities.
    vuln_rows = conn.execute(
        """
        SELECT v.cve_id, c.cvss_score, c.epss_percentile, c.kev, s.port, s.protocol,
               s.product, s.version
          FROM vulnerability v
          JOIN cve c ON c.cve_id = v.cve_id
          JOIN service s ON s.id = v.service_id
         WHERE s.asset_id = ?
        """,
        (asset["id"],),
    ).fetchall()
    open_ids = {(s["port"], s["protocol"]) for s in services}
    cve_factors = []
    has_kev = False
    for row in vuln_rows:
        if (row["port"], row["protocol"]) not in open_ids:
            continue
        points, why = cve_points(row["cvss_score"], row["epss_percentile"], bool(row["kev"]))
        has_kev = has_kev or bool(row["kev"])
        software = " ".join(x for x in (row["product"], row["version"]) if x) or "service"
        cve_factors.append(
            Factor(
                "vulnerability",
                f"{row['cve_id']} in {software} ({row['protocol']}/{row['port']})",
                points,
                why,
            )
        )
    cve_factors.sort(key=lambda f: f.points, reverse=True)
    if cve_factors:
        factors.append(cve_factors[0])
        extra = 0.0
        for f in cve_factors[1:]:
            if f.points >= SERIOUS_CVE and extra < MAX_EXTRA_CVE_POINTS:
                extra += 5.0
                factors.append(
                    Factor("vulnerability", f.title, 5.0, f"another serious CVE: {f.why}")
                )

    # Exposure.
    other_ports = 0
    for s in services:
        risky = RISKY_PORTS.get(s["port"]) if s["protocol"] == "tcp" else None
        if risky:
            name, points, why = risky
            factors.append(Factor("exposure", f"{name} open (tcp/{s['port']})", points, why))
        else:
            other_ports += 1
    if other_ports:
        factors.append(
            Factor(
                "exposure",
                f"{other_ports} other open port(s)",
                float(min(other_ports, MAX_OTHER_PORT_POINTS)),
                "every listening service is reachable by an attacker",
            )
        )

    # Context.
    device_type = asset["device_type"]
    if device_type in NETWORK_GEAR_TYPES:
        factors.append(
            Factor(
                "context",
                f"Network equipment ({device_type})",
                5.0,
                "it routes everyone's traffic, so a compromise matters more",
            )
        )
    elif device_type in IOT_TYPES:
        factors.append(
            Factor(
                "context",
                f"IoT device ({device_type})",
                5.0,
                "IoT devices are rarely updated and widely targeted",
            )
        )
    if not asset["vendor"]:
        factors.append(
            Factor(
                "context",
                "Unknown manufacturer",
                3.0,
                "hard to tell who maintains it or if updates exist",
            )
        )

    score = round(min(100.0, sum(f.points for f in factors)), 1)
    level = level_for(score, has_kev=has_kev)
    factors.sort(key=lambda f: f.points, reverse=True)
    return AssetScore(asset["id"], score, level, tuple(factors), _summary(level, score, factors))


def _summary(level: str, score: float, factors: list[Factor]) -> str:
    if not factors:
        return (
            f"{level.capitalize()} risk ({score:.0f}): no open services or known "
            "vulnerabilities found."
        )
    top = factors[0]
    return f"{level.capitalize()} risk ({score:.0f}), mostly from {top.title}: {top.why}."


def _open_services(conn: sqlite3.Connection, asset_id: int) -> list[sqlite3.Row]:
    rows = conn.execute(
        "SELECT * FROM service WHERE asset_id = ? AND state LIKE 'open%'", (asset_id,)
    ).fetchall()
    if not rows:
        return []
    latest = max(parse_ts(r["last_seen"]) for r in rows)
    return [r for r in rows if latest - parse_ts(r["last_seen"]) <= OPEN_WINDOW]


def run_scoring(conn: sqlite3.Connection, *, score_date: str | None = None) -> list[AssetScore]:
    """Score every non-protected asset for ``score_date`` (default: today, UTC)."""
    now = utc_now()
    day = score_date or now[:10]
    scores = []
    assets = conn.execute("SELECT * FROM asset WHERE protected = 0 ORDER BY id").fetchall()
    with transaction(conn):
        for asset in assets:
            result = score_asset(conn, asset)
            scores.append(result)
            factors = {
                "model": MODEL_VERSION,
                "summary": result.summary,
                "factors": [asdict(f) for f in result.factors],
            }
            conn.execute(
                """
                INSERT INTO risk_score (asset_id, score_date, score, level, factors, model_version,
                                        computed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (asset_id, score_date) DO UPDATE SET
                    score = excluded.score, level = excluded.level, factors = excluded.factors,
                    model_version = excluded.model_version, computed_at = excluded.computed_at
                """,
                (
                    asset["id"],
                    day,
                    result.score,
                    result.level,
                    json.dumps(factors),
                    MODEL_VERSION,
                    now,
                ),
            )
    return scores
