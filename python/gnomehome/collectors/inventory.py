"""Write discovered hosts and services into the asset inventory.

This is the last layer of protected-asset defense before storage. The scan
job has already excluded protected IPs and re-checked the results. If a
protected host still reaches this point, :func:`record_hosts` raises, and the
caller's transaction rolls back so nothing from the run is stored.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass, field

from gnomehome.identifiers import InvalidIdentifier, is_locally_administered, normalize_mac
from gnomehome.nmap_xml import NmapHost
from gnomehome.protected import Guard


class ProtectedHostInResults(Exception):
    """A protected host reached the inventory writer. Nothing is stored."""


@dataclass
class InventoryResult:
    hosts_seen: int = 0
    services_seen: int = 0
    skipped_without_mac: int = 0
    #: Devices seen for the first time: (ip, mac, vendor). For the console summary.
    new_devices: list[tuple[str | None, str, str | None]] = field(default_factory=list)


def record_hosts(
    conn: sqlite3.Connection,
    guard: Guard,
    hosts: Iterable[NmapHost],
    *,
    scan_id: int,
    now: str,
    with_services: bool,
) -> InventoryResult:
    """Upsert assets (and optionally services). Call inside a transaction."""
    result = InventoryResult()
    for host in hosts:
        if host.status != "up":
            continue
        if host.mac is None:
            # nmap reports no MAC for the scanning machine itself or for hosts
            # beyond the router. An asset is one per MAC, so these are skipped.
            result.skipped_without_mac += 1
            continue
        if guard.touches_protected(ips=[host.ip], macs=[host.mac]):
            raise ProtectedHostInResults(
                "a protected host reached the inventory writer; nothing from this run is stored"
            )
        try:
            mac = normalize_mac(host.mac)
        except InvalidIdentifier:
            result.skipped_without_mac += 1
            continue
        asset_id, is_new = _upsert_asset(conn, host, mac, scan_id=scan_id, now=now)
        result.hosts_seen += 1
        if is_new:
            result.new_devices.append((host.ip, mac, host.vendor))
        if with_services:
            for service in host.services:
                _upsert_service(conn, asset_id, service, scan_id=scan_id, now=now)
                result.services_seen += 1
    return result


def _upsert_asset(
    conn: sqlite3.Connection, host: NmapHost, mac: str, *, scan_id: int, now: str
) -> tuple[int, bool]:
    row = conn.execute("SELECT id FROM asset WHERE mac = ?", (mac,)).fetchone()
    if row is None:
        cursor = conn.execute(
            """
            INSERT INTO asset (mac, mac_randomized, device_type, vendor, hostname, last_ip,
                               os_guess, os_accuracy, first_seen, last_seen, last_scan_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                mac,
                int(is_locally_administered(mac)),
                host.device_type,
                host.vendor,
                host.hostname,
                host.ip,
                host.os_name,
                host.os_accuracy,
                now,
                now,
                scan_id,
            ),
        )
        return int(cursor.lastrowid), True
    # Seen before. The guard allowed this host, so clear any protected flag
    # (the device came off the list). Keep earlier details when this scan
    # didn't report them (discovery scans carry no OS info).
    conn.execute(
        """
        UPDATE asset
           SET protected = 0,
               device_type = COALESCE(?, device_type),
               vendor = COALESCE(?, vendor),
               hostname = COALESCE(?, hostname),
               last_ip = ?,
               os_guess = COALESCE(?, os_guess),
               os_accuracy = COALESCE(?, os_accuracy),
               last_seen = ?,
               last_scan_id = ?
         WHERE id = ?
        """,
        (
            host.device_type,
            host.vendor,
            host.hostname,
            host.ip,
            host.os_name,
            host.os_accuracy,
            now,
            scan_id,
            row[0],
        ),
    )
    return int(row[0]), False


def _upsert_service(
    conn: sqlite3.Connection, asset_id: int, service, *, scan_id: int, now: str
) -> None:
    conn.execute(
        """
        INSERT INTO service (asset_id, port, protocol, state, name, product, version,
                             extra_info, cpe, first_seen, last_seen, last_scan_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (asset_id, port, protocol) DO UPDATE SET
            state = excluded.state,
            name = excluded.name,
            product = excluded.product,
            version = excluded.version,
            extra_info = excluded.extra_info,
            cpe = COALESCE(excluded.cpe, service.cpe),
            last_seen = excluded.last_seen,
            last_scan_id = excluded.last_scan_id
        """,
        (
            asset_id,
            service.port,
            service.protocol,
            service.state,
            service.name,
            service.product,
            service.version,
            service.extra_info,
            service.cpe,
            now,
            now,
            scan_id,
        ),
    )
