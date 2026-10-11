"""Write observed devices and services into the asset inventory.

Two collectors feed it: the nmap scan (:func:`record_hosts`) and router DHCP
events (:func:`observe_asset`, :func:`record_protected_presence`).

This is the last layer of protected-asset defense before storage. The scan
job has already excluded protected IPs and re-checked the results. If a
protected host still reaches :func:`record_hosts`, it raises, and the caller's
transaction rolls back so nothing from the run is stored.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass, field

from gnomehome.identifiers import InvalidIdentifier, is_locally_administered, normalize_mac
from gnomehome.incidents import NewDevice
from gnomehome.nmap_xml import NmapHost
from gnomehome.protected import Guard


class ProtectedHostInResults(Exception):
    """A protected host reached the inventory writer. Nothing is stored."""


@dataclass(frozen=True)
class Observation:
    """One sighting of a device. ``mac`` must already be normalized."""

    mac: str
    ip: str | None
    vendor: str | None = None
    hostname: str | None = None
    os_name: str | None = None
    os_accuracy: int | None = None
    device_type: str | None = None


@dataclass
class InventoryResult:
    hosts_seen: int = 0
    services_seen: int = 0
    skipped_without_mac: int = 0
    #: Devices seen for the first time.
    new_devices: list[NewDevice] = field(default_factory=list)


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
        observation = Observation(
            mac=mac,
            ip=host.ip,
            vendor=host.vendor,
            hostname=host.hostname,
            os_name=host.os_name,
            os_accuracy=host.os_accuracy,
            device_type=host.device_type,
        )
        asset_id, is_new = observe_asset(conn, observation, seen_at=now, scan_id=scan_id)
        result.hosts_seen += 1
        if is_new:
            result.new_devices.append(
                NewDevice(asset_id, host.ip, mac, host.vendor, host.hostname, now)
            )
        if with_services:
            for service in host.services:
                _upsert_service(conn, asset_id, service, scan_id=scan_id, now=now)
                result.services_seen += 1
    return result


def observe_asset(
    conn: sqlite3.Connection, obs: Observation, *, seen_at: str, scan_id: int | None = None
) -> tuple[int, bool]:
    """Insert or update the asset for ``obs.mac``. Returns ``(asset_id, is_new)``.

    The caller must already have checked the guard. Observations can arrive out of
    order (log lines lag behind scans), so first/last seen take the min/max, and
    the last IP only changes when this sighting is the newest.
    """
    row = conn.execute("SELECT id FROM asset WHERE mac = ?", (obs.mac,)).fetchone()
    if row is None:
        cursor = conn.execute(
            """
            INSERT INTO asset (mac, mac_randomized, device_type, vendor, hostname, last_ip,
                               os_guess, os_accuracy, first_seen, last_seen, last_scan_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                obs.mac,
                int(is_locally_administered(obs.mac)),
                obs.device_type,
                obs.vendor,
                obs.hostname,
                obs.ip,
                obs.os_name,
                obs.os_accuracy,
                seen_at,
                seen_at,
                scan_id,
            ),
        )
        return int(cursor.lastrowid), True
    # Seen before. The guard allowed this device, so clear any protected flag
    # (the device came off the list). Keep earlier details when this sighting
    # didn't report them (DHCP and discovery carry no OS info).
    conn.execute(
        """
        UPDATE asset
           SET protected = 0,
               device_type = COALESCE(?, device_type),
               vendor = COALESCE(?, vendor),
               hostname = COALESCE(?, hostname),
               last_ip = CASE WHEN ? >= last_seen OR last_ip IS NULL
                              THEN COALESCE(?, last_ip) ELSE last_ip END,
               os_guess = COALESCE(?, os_guess),
               os_accuracy = COALESCE(?, os_accuracy),
               first_seen = MIN(first_seen, ?),
               last_seen = MAX(last_seen, ?),
               last_scan_id = COALESCE(?, last_scan_id)
         WHERE id = ?
        """,
        (
            obs.device_type,
            obs.vendor,
            obs.hostname,
            seen_at,
            obs.ip,
            obs.os_name,
            obs.os_accuracy,
            seen_at,
            seen_at,
            scan_id,
            row[0],
        ),
    )
    return int(row[0]), False


def record_protected_presence(conn: sqlite3.Connection, mac: str, seen_at: str) -> None:
    """Record that a protected device exists, and nothing else (plan: Protected assets, step 7).

    Only the MAC, the protected flag, and the moment it was first noticed. The row
    is never updated afterwards, so no timeline of the device's comings and goings
    builds up.
    """
    conn.execute(
        "INSERT INTO asset (mac, protected, first_seen, last_seen) VALUES (?, 1, ?, ?) "
        "ON CONFLICT (mac) DO NOTHING",
        (normalize_mac(mac), seen_at, seen_at),
    )


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
