"""The weekly summary: the gold-layer document the AI check-in reads (FR-18).

Built from plain rows, so the same function runs on the Pi's SQLite database
(``just summary``) and in the Databricks gold job on rows collected from the
silver tables. It holds curated facts only, never raw logs (plan, "AI
check-in agent"): device counts, new devices, risk levels and changes,
incidents, anomalies, and DNS totals.

Device names, domains, and incident titles inside it can come from devices,
so whoever reads it must treat its text as untrusted data (R-04). The agent
does: see ``agent/``.
"""

from __future__ import annotations

import sqlite3
from collections import Counter
from collections.abc import Iterable, Mapping
from datetime import date, timedelta
from typing import Any

from gnomehome.ml.local import run_local
from gnomehome.narrative import describe_device

SCHEMA = "gnomehome-weekly-v1"
LEVEL_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def week_bounds(week_end: date) -> tuple[str, str]:
    """The seven days ending on ``week_end`` (inclusive), as UTC timestamp bounds."""
    start = week_end - timedelta(days=6)
    return f"{start}T00:00:00.000Z", f"{week_end + timedelta(days=1)}T00:00:00.000Z"


def build_weekly_summary(
    *,
    week_end: date,
    assets: Iterable[Mapping[str, Any]],
    incidents: Iterable[Mapping[str, Any]],
    risk_scores: Iterable[Mapping[str, Any]],
    dns_totals: Mapping[str, Any] | None = None,
    anomalies: Iterable[Mapping[str, Any]] = (),
    device_types: Mapping[str, str] | None = None,
    playbook_runs: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    start, end = week_bounds(week_end)
    assets = [a for a in assets if not a.get("protected")]
    names = {a["id"]: _name(a) for a in assets}
    types = device_types or {}

    new_devices = [
        {
            "device": names[a["id"]],
            "first_seen": a["first_seen"],
            "type_guess": types.get(a.get("last_ip") or "", "unknown"),
        }
        for a in sorted(assets, key=lambda a: a["first_seen"])
        if start <= a["first_seen"] < end
    ]

    latest: dict[int, Mapping[str, Any]] = {}
    week_start_level: dict[int, str] = {}
    for r in sorted(risk_scores, key=lambda r: r["score_date"]):
        if r["asset_id"] not in names:
            continue
        if r["score_date"] < start[:10]:
            week_start_level[r["asset_id"]] = r["level"]
        elif r["score_date"] < end[:10]:
            latest[r["asset_id"]] = r
    changes = [
        {
            "device": names[asset_id],
            "from": week_start_level[asset_id],
            "to": r["level"],
            "score": round(r["score"]),
        }
        for asset_id, r in latest.items()
        if asset_id in week_start_level and r["level"] != week_start_level[asset_id]
    ]
    top = sorted(latest.values(), key=lambda r: -r["score"])[:5]

    week_incidents = [
        i for i in incidents if start <= (i.get("occurred_at") or i["created_at"]) < end
    ]
    return {
        "schema": SCHEMA,
        "week_start": start[:10],
        "week_end": week_end.isoformat(),
        "devices": {"total": len(assets), "new": new_devices},
        "risk": {
            "levels": dict(Counter(r["level"] for r in latest.values())),
            "changes": sorted(changes, key=lambda c: -LEVEL_RANK[c["to"]]),
            "top": [
                {
                    "device": names[r["asset_id"]],
                    "score": round(r["score"]),
                    "level": r["level"],
                    "summary": r.get("summary"),
                }
                for r in top
            ],
        },
        "incidents": {
            "opened": len(week_incidents),
            "by_severity": dict(Counter(i["severity"] for i in week_incidents)),
            "still_open": sum(i["status"] != "resolved" for i in week_incidents),
            "items": [
                {
                    "id": i["id"],
                    "severity": i["severity"],
                    "detection": i["detection"],
                    "title": i["title"],
                    "status": i["status"],
                    "occurred_at": i.get("occurred_at") or i["created_at"],
                }
                for i in sorted(week_incidents, key=lambda i: -LEVEL_RANK[i["severity"]])[:20]
            ],
        },
        "anomalies": [dict(a) for a in anomalies][:20],
        "dns": dict(dns_totals or {}),
        "playbooks": [dict(p) for p in playbook_runs][:20],
    }


def _name(asset: Mapping[str, Any]) -> str:
    return describe_device(asset.get("last_ip"), asset.get("vendor"), asset.get("hostname"))


def from_sqlite(conn: sqlite3.Connection, week_end: date) -> dict[str, Any]:
    """Build the summary from the local database."""
    start, end = week_bounds(week_end)

    def rows(sql: str, *params: object) -> list[dict[str, Any]]:
        return [dict(r) for r in conn.execute(sql, params)]

    risk = rows(
        "SELECT asset_id, score_date, score, level, json_extract(factors, '$.summary') AS summary "
        "FROM risk_score WHERE score_date >= ? AND score_date < ?",
        (week_end - timedelta(days=13)).isoformat(),
        end[:10],
    )
    totals = conn.execute(
        "SELECT COUNT(*), SUM(status = 'blocked'), COUNT(DISTINCT src_ip) FROM event "
        "WHERE kind = 'dns' AND ts >= ? AND ts < ?",
        (start, end),
    ).fetchone()
    has_runs = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'playbook_run'"
    ).fetchone()
    runs = (
        rows(
            "SELECT playbook, tier, status, started_at FROM playbook_run "
            "WHERE started_at >= ? AND started_at < ? ORDER BY started_at",
            start,
            end,
        )
        if has_runs
        else []
    )
    ml = run_local(conn)
    anomalies = [
        {"device": a.device, "day": a.day, "severity": a.severity, "reason": a.reason}
        for a in ml.anomalies
        if start[:10] <= a.day < end[:10]
    ]
    return build_weekly_summary(
        week_end=week_end,
        assets=rows("SELECT * FROM asset WHERE protected = 0"),
        device_types={c.device: c.label for c in ml.classifications},
        anomalies=anomalies,
        incidents=rows("SELECT * FROM incident"),
        risk_scores=risk,
        dns_totals={
            "queries": totals[0] or 0,
            "blocked": totals[1] or 0,
            "devices": totals[2] or 0,
        },
        playbook_runs=runs,
    )
