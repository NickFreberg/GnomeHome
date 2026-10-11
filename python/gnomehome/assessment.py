"""The weekly self-assessment (FR-17): what changed on the network this week.

Compares the week ending on a given day with everything before it:

* **new devices**: assets first seen this week
* **newly exposed ports**: open services first seen this week on devices that
  were already known (a brand-new device's ports are part of "new device")
* **new CVEs**: vulnerabilities first matched this week, and how many are on
  CISA's known-exploited list

It writes one ``assessment.weekly`` incident (deduplicated per week) and
queues a ``weekly_assessment`` push. The scheduled playbook runs it every
week; ``just self-assess`` runs it by hand.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import date

from gnomehome import narrative
from gnomehome.db import transaction
from gnomehome.incidents import open_incident
from gnomehome.summary import week_bounds
from gnomehome.timeutil import utc_now


@dataclass
class Assessment:
    week_start: str
    week_end: str
    new_devices: list[str] = field(default_factory=list)
    new_ports: list[str] = field(default_factory=list)
    new_cves: list[str] = field(default_factory=list)
    kev_cves: int = 0
    high_risk_devices: int = 0
    incident_id: int | None = None


def assess_week(conn: sqlite3.Connection, week_end: date) -> Assessment:
    start, end = week_bounds(week_end)
    result = Assessment(start[:10], week_end.isoformat())

    for row in conn.execute(
        "SELECT last_ip, vendor, hostname FROM asset WHERE protected = 0 "
        "AND first_seen >= ? AND first_seen < ? ORDER BY first_seen",
        (start, end),
    ):
        result.new_devices.append(narrative.describe_device(*row))

    for row in conn.execute(
        """
        SELECT a.last_ip, a.vendor, a.hostname, s.port, s.protocol, s.name
          FROM service s JOIN asset a ON a.id = s.asset_id
         WHERE a.protected = 0 AND s.state = 'open'
           AND s.first_seen >= ? AND s.first_seen < ? AND a.first_seen < ?
         ORDER BY s.first_seen
        """,
        (start, end, start),
    ):
        service = f" ({row['name']})" if row["name"] else ""
        device = narrative.describe_device(row["last_ip"], row["vendor"], row["hostname"])
        result.new_ports.append(f"{row['protocol']}/{row['port']}{service} on {device}")

    for row in conn.execute(
        """
        SELECT DISTINCT c.cve_id, c.kev, c.cvss_score
          FROM vulnerability v JOIN cve c ON c.cve_id = v.cve_id
          JOIN service s ON s.id = v.service_id JOIN asset a ON a.id = s.asset_id
         WHERE a.protected = 0 AND v.first_seen >= ? AND v.first_seen < ?
         ORDER BY c.kev DESC, c.cvss_score DESC
        """,
        (start, end),
    ):
        score = f", CVSS {row['cvss_score']:.1f}" if row["cvss_score"] is not None else ""
        known = ", known exploited" if row["kev"] else ""
        result.new_cves.append(f"{row['cve_id']}{score}{known}")
        result.kev_cves += row["kev"]

    result.high_risk_devices = conn.execute(
        "SELECT COUNT(*) FROM risk_score r JOIN asset a ON a.id = r.asset_id "
        "WHERE a.protected = 0 AND r.level IN ('high', 'critical') "
        "AND r.score_date = (SELECT MAX(score_date) FROM risk_score WHERE score_date < ?)",
        (end[:10],),
    ).fetchone()[0]

    story = narrative.weekly_assessment(
        week_start=result.week_start,
        week_end=result.week_end,
        new_devices=result.new_devices,
        new_ports=result.new_ports,
        new_cves=result.new_cves,
        kev_cves=result.kev_cves,
        high_risk_devices=result.high_risk_devices,
    )
    with transaction(conn):
        result.incident_id = open_incident(
            conn,
            story,
            evidence={
                "new_devices": len(result.new_devices),
                "new_ports": len(result.new_ports),
                "new_cves": len(result.new_cves),
                "kev_cves": result.kev_cves,
            },
            dedup_key=f"assessment:{result.week_end}",
        )
        if result.incident_id is not None:
            conn.execute(
                "INSERT INTO notification_outbox (kind, incident_id, created_at) "
                "VALUES ('weekly_assessment', ?, ?)",
                (result.incident_id, utc_now()),
            )
    return result
