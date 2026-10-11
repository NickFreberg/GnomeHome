"""Incidents: detections written down in plain English (groundwork for FR-11).

Phase 2 raises two kinds:

* ``inventory.new_device`` (FR-03): a MAC the inventory has never seen.
* ``guard.protected_drift``: a protected device isn't where its list entry says,
  so IP-based exclusion might not cover it (plan, "Protected assets", step 8).
  These name the device by **label only**. They have no ``asset_id``, and their
  evidence holds no MAC or IP, because incidents ship to Azure later.

Text is factual, per the design system's voice rules. Device-supplied names
are quoted and labeled as such, never presented as fact.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from gnomehome.identifiers import is_locally_administered
from gnomehome.protected import AuditSink
from gnomehome.timeutil import parse_ts, utc_now

SEVERITIES = ("low", "medium", "high", "critical")
OPEN_STATUSES = ("open", "pending_approval", "acknowledged")

NEW_DEVICE = "inventory.new_device"
PROTECTED_DRIFT = "guard.protected_drift"


@dataclass(frozen=True)
class NewDevice:
    asset_id: int
    ip: str | None
    mac: str
    vendor: str | None
    hostname: str | None
    seen_at: str


def open_incident(
    conn: sqlite3.Connection,
    *,
    detection: str,
    severity: str,
    title: str,
    summary: str,
    asset_id: int | None = None,
    evidence: dict[str, Any] | None = None,
    dedup_key: str | None = None,
    mitre_technique: str | None = None,
    confidence: float | None = None,
) -> int | None:
    """Create an incident. Returns None when an open one with the same key already exists."""
    if severity not in SEVERITIES:
        raise ValueError(f"severity must be one of {SEVERITIES}")
    evidence = dict(evidence or {})
    if dedup_key is not None:
        evidence["dedup_key"] = dedup_key
        marks = ", ".join("?" for _ in OPEN_STATUSES)
        existing = conn.execute(
            f"SELECT id FROM incident WHERE detection = ? AND status IN ({marks}) "  # noqa: S608
            "AND json_extract(evidence, '$.dedup_key') = ?",
            (detection, *OPEN_STATUSES, dedup_key),
        ).fetchone()
        if existing:
            return None
    now = utc_now()
    cursor = conn.execute(
        "INSERT INTO incident (created_at, updated_at, asset_id, detection, severity, title, "
        "summary, evidence, mitre_technique, confidence) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            now,
            now,
            asset_id,
            detection,
            severity,
            title,
            summary,
            json.dumps(evidence, sort_keys=True),
            mitre_technique,
            confidence,
        ),
    )
    return int(cursor.lastrowid)


def in_learning_window(conn: sqlite3.Connection, seen_at: str, learning_minutes: int) -> bool:
    """True while the inventory is still learning its baseline (no new-device alerts yet).

    The window starts at the earliest ``first_seen`` in the inventory. Call this
    *before* recording the observation: with an empty inventory, the first
    device is part of the baseline.
    """
    if learning_minutes <= 0:
        return False
    start = conn.execute("SELECT MIN(first_seen) FROM asset").fetchone()[0]
    if start is None:
        return True
    return parse_ts(seen_at) - parse_ts(start) < timedelta(minutes=learning_minutes)


def new_device_incident(conn: sqlite3.Connection, device: NewDevice, *, source: str) -> int | None:
    vendor = device.vendor or "unknown vendor"
    parts = [
        f"A device GnomeHome has not seen before joined the network (first seen "
        f"{device.seen_at}, via {source}). IP {device.ip or 'unknown'}, MAC {device.mac}, "
        f"vendor {device.vendor or 'unknown'}."
    ]
    if device.hostname:
        parts.append(
            f'It calls itself "{device.hostname}" (a device-supplied name, which can be false).'
        )
    if is_locally_administered(device.mac):
        parts.append(
            "Its MAC is randomized (a phone's private Wi-Fi address), so it may be a known device "
            "using a new address."
        )
    parts.append(
        "Why it matters: every device on the network should be one you recognize. If you don't "
        "recognize it, find it in the ASUS app's device list."
    )
    return open_incident(
        conn,
        detection=NEW_DEVICE,
        severity="low",
        title=f"New device on the network ({vendor})",
        summary=" ".join(parts),
        asset_id=device.asset_id,
        evidence={"source": source, "mac": device.mac, "ip": device.ip},
        dedup_key=f"new_device:{device.mac}",
    )


_DRIFT_TEXT = {
    "protected_mac_at_unlisted_ip": (
        "Protected device {label!r} was given an IP address that is not on its protected list. "
        "Scans exclude protected devices by IP, so if it keeps that address, a scan could reach "
        "it. Fix the DHCP reservation for {label!r} in the router, then rerun the zero-packet "
        "test (docs/runbooks/zero-packet-test.md)."
    ),
    "unknown_mac_at_protected_ip": (
        "The reserved IP address of protected device {label!r} was given to a MAC address that is "
        "not on the list. Either the laptop's MAC changed (for example, a randomized Wi-Fi "
        "address) or another device took its address. Nothing about that device was stored. If "
        "it is the laptop, add the new MAC to config/protected_assets.yaml."
    ),
}


def drift_incident(
    conn: sqlite3.Connection,
    *,
    label: str,
    kind: str,
    source: str,
    audit: AuditSink | None = None,
    actor: str = "system",
) -> int | None:
    """Open (or skip, if already open) a drift incident. Label only: no MAC, no IP."""
    incident_id = open_incident(
        conn,
        detection=PROTECTED_DRIFT,
        severity="medium",
        title=f"Protected device {label!r} is not where its list entry says",
        summary=_DRIFT_TEXT[kind].format(label=label),
        evidence={"label": label, "kind": kind, "source": source},
        dedup_key=f"drift:{label}:{kind}",
    )
    if audit is not None:
        audit.append(
            actor=actor,
            action="guard.drift_detected",
            target=f"protected:{label}",
            result="success",
            details={"kind": kind, "source": source, "incident_opened": incident_id is not None},
        )
    return incident_id


def list_incidents(conn: sqlite3.Connection, *, include_closed: bool = False) -> list[sqlite3.Row]:
    if include_closed:
        return conn.execute("SELECT * FROM incident ORDER BY created_at, id").fetchall()
    marks = ", ".join("?" for _ in OPEN_STATUSES)
    return conn.execute(
        f"SELECT * FROM incident WHERE status IN ({marks}) ORDER BY created_at, id",  # noqa: S608
        OPEN_STATUSES,
    ).fetchall()


def resolve_incident(
    conn: sqlite3.Connection, incident_id: int, *, audit: AuditSink, actor: str
) -> bool:
    cursor = conn.execute(
        "UPDATE incident SET status = 'resolved', updated_at = ? "
        "WHERE id = ? AND status <> 'resolved'",
        (utc_now(), incident_id),
    )
    if cursor.rowcount == 0:
        return False
    audit.append(
        actor=actor,
        action="incident.resolve",
        target=f"incident:{incident_id}",
        result="success",
    )
    return True
