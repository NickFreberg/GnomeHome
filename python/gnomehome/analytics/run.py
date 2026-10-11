"""The DNS analytics job: ``just analyze`` (hourly on the Pi).

Folds new DNS events into each device's domain history, runs the detectors,
and turns findings into deduplicated, plain-English incidents. The analysis
window is anchored to the newest DNS event in the database rather than the
wall clock, so the same code works on live data and on synthetic data.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import timedelta

from gnomehome.analytics.detect import (
    Finding,
    Settings,
    data_end,
    detect_beacons,
    detect_dga,
    detect_threat_intel,
    update_device_domains,
)
from gnomehome.config import Config
from gnomehome.db import transaction
from gnomehome.incidents import open_incident
from gnomehome.timeutil import format_ts, parse_ts


@dataclass
class AnalysisResult:
    end: str | None = None
    domains_updated: int = 0
    findings: list[Finding] = field(default_factory=list)
    incidents_opened: int = 0


def settings_from_config(config: Config) -> Settings:
    a = config.analytics
    return Settings(
        beacon_min_events=a.beacon_min_events,
        beacon_max_jitter=a.beacon_max_jitter,
        dga_threshold=a.dga_threshold,
        dga_burst=a.dga_burst,
        dga_window_minutes=a.dga_window_minutes,
        baseline_minutes=config.alerts.learning_minutes,
    )


def run_analysis(conn: sqlite3.Connection, settings: Settings) -> AnalysisResult:
    result = AnalysisResult(end=data_end(conn))
    if result.end is None:
        return result
    end = result.end
    with transaction(conn):
        result.domains_updated = update_device_domains(conn, _checkpoint(conn, "device_domain"))
        _set_checkpoint(conn, "device_domain", end)

        dga_since = _checkpoint(conn, "dga")
        if dga_since is not None:  # look back one window so a burst split across runs is seen
            dga_since = format_ts(
                parse_ts(dga_since) - timedelta(minutes=settings.dga_window_minutes)
            )
        findings = [
            *detect_beacons(conn, end, settings),
            *detect_dga(conn, dga_since, end, settings),
            *detect_threat_intel(conn, _checkpoint(conn, "threat_intel"), end),
        ]
        for finding in findings:
            if _open(conn, finding) is not None:
                result.incidents_opened += 1
        for detector in ("dga", "threat_intel"):
            _set_checkpoint(conn, detector, end)
    result.findings = findings
    return result


def _device_name(conn: sqlite3.Connection, finding: Finding) -> str:
    row = None
    if finding.asset_id is not None:
        row = conn.execute(
            "SELECT hostname, vendor FROM asset WHERE id = ?", (finding.asset_id,)
        ).fetchone()
    label = (row["hostname"] or row["vendor"]) if row else None
    return f"the device at {finding.src_ip}" + (f' ("{label}")' if label else "")


def _every(seconds: float) -> str:
    if seconds < 120:
        return f"{seconds:.0f} seconds"
    if seconds < 7200:
        return f"{seconds / 60:.0f} minutes"
    return f"{seconds / 3600:.1f} hours"


def _open(conn: sqlite3.Connection, f: Finding) -> int | None:
    device = _device_name(conn, f)
    d = f.details
    if f.detection == "dns.beaconing":
        return open_incident(
            conn,
            detection=f.detection,
            severity="medium",
            title=f'Regular check-ins to "{f.domain}"',
            summary=(
                f'What happened: {device} looked up "{f.domain}" {f.count} times between '
                f"{f.first_ts} and {f.last_ts}, about every {_every(d['period_seconds'])}, "
                f"varying by only {d['jitter']:.0%}. It first contacted this domain at "
                f"{d['first_seen']}, after the baseline period. Why it matters: malware often "
                "checks in with its command server on a steady timer (MITRE ATT&CK T1071.004). "
                "Some legitimate apps do too, so check whether you recognize the domain."
            ),
            asset_id=f.asset_id,
            evidence={"src_ip": f.src_ip, "domain": f.domain, **d},
            dedup_key=f"beacon:{f.src_ip}:{f.domain}",
            mitre_technique="T1071.004",
            confidence=round(max(0.5, 1 - d["jitter"] / 0.15 * 0.5), 2),
        )
    if f.detection == "dns.dga":
        examples = ", ".join(f'"{x}"' for x in d["examples"][:3])
        return open_incident(
            conn,
            detection=f.detection,
            severity="high",
            title="Burst of machine-generated domain lookups",
            summary=(
                f"What happened: between {f.first_ts} and {f.last_ts}, {device} looked up "
                f"{d['distinct_names']} random-looking domains (for example {examples}), and "
                f"{d['nxdomain_share']:.0%} of them don't exist. Why it matters: malware that "
                "generates domain names tries many quickly to find its command server (MITRE "
                "ATT&CK T1568.002). Check the device for unwanted software."
            ),
            asset_id=f.asset_id,
            evidence={"src_ip": f.src_ip, **d},
            dedup_key=f"dga:{f.src_ip}:{f.first_ts[:13]}",
            mitre_technique="T1568.002",
            confidence=round(min(1.0, d["mean_score"] + 0.2), 2),
        )
    if f.detection == "dns.threat_intel":
        resolved, blocked = d["resolved"], d["blocked"]
        outcome = (
            f"Pi-hole blocked all {blocked} lookup(s)."
            if resolved == 0
            else f"{resolved} lookup(s) were answered, so the device could reach it."
        )
        return open_incident(
            conn,
            detection=f.detection,
            severity="medium" if resolved == 0 else "high",
            title=f'Lookup of a known-bad domain: "{d["indicator"]}"',
            summary=(
                f'What happened: {device} looked up "{f.domain}", which is on the '
                f"{', '.join(d['sources'])} threat list, {f.count} time(s) between {f.first_ts} "
                f"and {f.last_ts}. {outcome} Why it matters: these lists track domains used for "
                "malware, phishing, and scams."
            ),
            asset_id=f.asset_id,
            evidence={"src_ip": f.src_ip, "domain": f.domain, **d},
            dedup_key=f"intel:{f.src_ip}:{d['indicator']}",
            confidence=0.9,
        )
    raise ValueError(f"unknown detection {f.detection}")


def _checkpoint(conn: sqlite3.Connection, detector: str) -> str | None:
    row = conn.execute(
        "SELECT last_ts FROM analysis_checkpoint WHERE detector = ?", (detector,)
    ).fetchone()
    return row[0] if row else None


def _set_checkpoint(conn: sqlite3.Connection, detector: str, ts: str) -> None:
    conn.execute(
        "INSERT INTO analysis_checkpoint (detector, last_ts) VALUES (?, ?) "
        "ON CONFLICT (detector) DO UPDATE SET last_ts = excluded.last_ts",
        (detector, ts),
    )
