"""Incidents: the plain-English incident log (FR-11).

Every detection becomes one incident, written by a template in
``narrative.py``: when, which device, what happened, why it matters, and what
to do. Incidents are deduplicated by a key in their evidence, so a detection
that keeps firing doesn't pile up while its incident is open.

Two kinds come from the inventory and the guard:

* ``inventory.new_device`` (FR-03): a MAC the inventory has never seen.
* ``guard.protected_drift``: a protected device isn't where its list entry says,
  so IP-based exclusion might not cover it (plan, "Protected assets", step 8).
  These name the device by **label only**. They have no ``asset_id``, and their
  evidence holds no MAC or IP, because incidents ship to Azure later.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from gnomehome import narrative
from gnomehome.narrative import Narrative
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
    story: Narrative,
    *,
    asset_id: int | None = None,
    evidence: dict[str, Any] | None = None,
    dedup_key: str | None = None,
) -> int | None:
    """Record an incident. Returns None when an open one with the same key already exists."""
    if story.severity not in SEVERITIES:
        raise ValueError(f"severity must be one of {SEVERITIES}")
    evidence = dict(evidence or {})
    if dedup_key is not None:
        evidence["dedup_key"] = dedup_key
        marks = ", ".join("?" for _ in OPEN_STATUSES)
        existing = conn.execute(
            f"SELECT id FROM incident WHERE detection = ? AND status IN ({marks}) "  # noqa: S608
            "AND json_extract(evidence, '$.dedup_key') = ?",
            (story.detection, *OPEN_STATUSES, dedup_key),
        ).fetchone()
        if existing:
            return None
    now = utc_now()
    cursor = conn.execute(
        "INSERT INTO incident (created_at, updated_at, asset_id, detection, severity, title, "
        "summary, evidence, mitre_technique, confidence, occurred_at, device, what_happened, "
        "why_it_matters, next_steps) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            now,
            now,
            asset_id,
            story.detection,
            story.severity,
            story.title,
            story.summary,
            json.dumps(evidence, sort_keys=True),
            story.mitre_technique,
            story.confidence,
            story.occurred_at,
            story.device,
            story.what_happened,
            story.why_it_matters,
            story.next_steps,
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
    story = narrative.new_device(
        ip=device.ip,
        mac=device.mac,
        vendor=device.vendor,
        hostname=device.hostname,
        seen_at=device.seen_at,
        source=source,
    )
    return open_incident(
        conn,
        story,
        asset_id=device.asset_id,
        evidence={"source": source, "mac": device.mac, "ip": device.ip},
        dedup_key=f"new_device:{device.mac}",
    )


def drift_incident(
    conn: sqlite3.Connection,
    *,
    label: str,
    kind: str,
    source: str,
    seen_at: str | None = None,
    audit: AuditSink | None = None,
    actor: str = "system",
) -> int | None:
    """Open (or skip, if already open) a drift incident. Label only: no MAC, no IP."""
    story = narrative.protected_drift(
        label=label, kind=kind, source=source, seen_at=seen_at or utc_now()
    )
    incident_id = open_incident(
        conn,
        story,
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
