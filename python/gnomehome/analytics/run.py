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

from gnomehome import narrative
from gnomehome.analytics.detect import (
    Finding,
    Settings,
    data_end,
    detect_beacons,
    detect_dga,
    detect_dns_bypass,
    detect_threat_intel,
    update_device_domains,
)
from gnomehome.config import Config
from gnomehome.db import transaction
from gnomehome.incidents import open_incident
from gnomehome.narrative import Narrative, describe_device
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
        allowed_dns_servers=a.allowed_dns_servers,
        lan_cidrs=config.network.lan_cidrs,
        pihole_ip=config.network.pihole_ip,
    )


def run_analysis(conn: sqlite3.Connection, settings: Settings) -> AnalysisResult:
    result = AnalysisResult(end=data_end(conn))
    with transaction(conn):
        flow_end = conn.execute("SELECT MAX(ts) FROM event WHERE kind = 'flow'").fetchone()[0]
        if flow_end is not None:
            findings = detect_dns_bypass(conn, _checkpoint(conn, "dns_bypass"), flow_end, settings)
            result.incidents_opened += sum(_open(conn, f) is not None for f in findings)
            result.findings.extend(findings)
            _set_checkpoint(conn, "dns_bypass", flow_end)
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
    result.findings.extend(findings)
    return result


def _device(conn: sqlite3.Connection, finding: Finding) -> str:
    row = None
    if finding.asset_id is not None:
        row = conn.execute(
            "SELECT hostname, vendor FROM asset WHERE id = ?", (finding.asset_id,)
        ).fetchone()
    if row is None:
        return describe_device(finding.src_ip)
    return describe_device(finding.src_ip, row["vendor"], row["hostname"])


def _story(conn: sqlite3.Connection, f: Finding) -> tuple[Narrative, str]:
    """The incident text and its dedup key."""
    device = _device(conn, f)
    d = f.details
    span = {"first_ts": f.first_ts, "last_ts": f.last_ts}
    if f.detection == "dns.beaconing":
        story = narrative.beaconing(
            device=device, domain=f.domain, count=f.count, details=d, **span
        )
        return story, f"beacon:{f.src_ip}:{f.domain}"
    if f.detection == "dns.dga":
        return narrative.dga(device=device, details=d, **span), f"dga:{f.src_ip}:{f.first_ts[:13]}"
    if f.detection == "dns.threat_intel":
        story = narrative.threat_intel(
            device=device, domain=f.domain, count=f.count, details=d, **span
        )
        return story, f"intel:{f.src_ip}:{d['indicator']}"
    if f.detection == "dns.bypass":
        return narrative.dns_bypass(device=device, count=f.count, details=d, **span), (
            f"bypass:{f.src_ip}"
        )
    raise ValueError(f"unknown detection {f.detection}")


def _open(conn: sqlite3.Connection, f: Finding) -> int | None:
    story, dedup_key = _story(conn, f)
    evidence = {"src_ip": f.src_ip, "count": f.count, **f.details}
    if f.detection != "dns.dga":
        evidence["domain"] = f.domain
    return open_incident(conn, story, asset_id=f.asset_id, evidence=evidence, dedup_key=dedup_key)


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
