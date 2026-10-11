"""Make the database agree with the current protected-asset list.

Collectors drop protected data before storage, but the list can change: you
might add a second work device after it has already been scanned. Every job
calls :func:`scrub_protected` at startup, so stored data about a device is
gone as soon as the device is on the list.

* Assets whose MAC is protected, or whose last IP is protected, are marked
  protected. The schema's CHECK clears their details, and its trigger deletes
  their services, events, risk scores, and incidents.
* Events, per-device domain history, and open router connections whose source
  or destination IP is protected are deleted.

Scrubbing never un-protects a row. If a device comes off the list, the
inventory writer clears the flag the next time a guarded scan sees it.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from gnomehome.db import transaction
from gnomehome.protected import AuditSink, ProtectedAssets


@dataclass(frozen=True)
class ScrubResult:
    assets_marked: int
    events_deleted: int


def scrub_protected(
    conn: sqlite3.Connection,
    assets: ProtectedAssets,
    *,
    audit: AuditSink | None = None,
    actor: str = "system",
) -> ScrubResult:
    def ip_protected(value: str | None) -> int:
        return int(value is not None and assets.match(ip=value) is not None)

    def mac_protected(value: str | None) -> int:
        return int(value is not None and assets.match(mac=value) is not None)

    # Python functions callable from SQL, so CIDRs and MAC formats use the guard's exact rules.
    conn.create_function("gnomehome_ip_protected", 1, ip_protected, deterministic=True)
    conn.create_function("gnomehome_mac_protected", 1, mac_protected, deterministic=True)
    with transaction(conn):
        marked = conn.execute(
            """
            UPDATE asset
               SET protected = 1, device_type = NULL, vendor = NULL, hostname = NULL,
                   last_ip = NULL, os_guess = NULL, os_accuracy = NULL, last_scan_id = NULL
             WHERE protected = 0
               AND (gnomehome_mac_protected(mac) OR gnomehome_ip_protected(last_ip))
            """
        ).rowcount
        deleted = conn.execute(
            "DELETE FROM event "
            "WHERE gnomehome_ip_protected(src_ip) OR gnomehome_ip_protected(dst_ip)"
        ).rowcount
        # Tables added in later migrations that also hold per-device data.
        if _has_table(conn, "device_domain"):
            deleted += conn.execute(
                "DELETE FROM device_domain WHERE gnomehome_ip_protected(src_ip)"
            ).rowcount
        if _has_table(conn, "conntrack_open"):
            deleted += conn.execute(
                "DELETE FROM conntrack_open "
                "WHERE gnomehome_ip_protected(src_ip) OR gnomehome_ip_protected(dst_ip)"
            ).rowcount
        if (marked or deleted) and audit is not None:
            audit.append(
                actor=actor,
                action="guard.scrub",
                target=None,
                result="success",
                details={"assets_marked_protected": marked, "events_deleted": deleted},
            )
    return ScrubResult(assets_marked=marked, events_deleted=deleted)


def _has_table(conn: sqlite3.Connection, name: str) -> bool:
    return (
        conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)
        ).fetchone()
        is not None
    )
