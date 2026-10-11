"""Vulnerability enrichment job: ``just enrich`` (daily on the Pi). FR-04.

1. Map each service's nmap CPE (2.2) to a CPE 2.3 name, versioned ones only.
2. For each CPE not looked up in the last ``nvd_refresh_hours``, fetch its CVEs
   from NVD and store each CVE plus its vulnerable-configuration rules.
3. Match every service against the stored rules with our own version logic, and
   keep the ``vulnerability`` table in sync: add new matches, drop stale ones.
4. Refresh the CISA KEV catalog and flag CVEs that are known to be exploited.
5. Refresh EPSS (the probability of exploitation) for every matched CVE.

Protected assets have no services (the schema forbids it), and every query
here also filters on ``protected = 0``.
"""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from gnomehome.cpe import CpeMatch, match_service, parse_cpe22, parse_cpe23
from gnomehome.db import transaction
from gnomehome.feeds import CveRecord, FeedError, HttpClient, fetch_epss, fetch_kev, fetch_nvd
from gnomehome.timeutil import format_ts, parse_ts, utc_now

CONFIDENCE = {"cpe_exact": 1.0, "cpe_version_range": 0.9}


@dataclass
class EnrichResult:
    services_mapped: int = 0
    cpes_looked_up: int = 0
    cpes_fresh: int = 0
    cves_stored: int = 0
    vulnerabilities: int = 0
    kev_entries: int = 0
    epss_updated: int = 0
    errors: list[str] = field(default_factory=list)


def run_enrichment(
    conn: sqlite3.Connection,
    client: HttpClient,
    *,
    api_key: str | None = None,
    nvd_refresh_hours: int = 24,
    feed_refresh_hours: int = 20,
    sleep: Callable[[float], None] = time.sleep,
    now: datetime | None = None,
) -> EnrichResult:
    result = EnrichResult()
    now_ts = format_ts(now) if now else utc_now()

    with transaction(conn):
        result.services_mapped = map_services(conn)

    for cpe23 in _cpes_to_look_up(conn, now_ts, nvd_refresh_hours, result):
        try:
            records = fetch_nvd(client, cpe23, api_key=api_key, sleep=sleep)
        except FeedError as exc:
            result.errors.append(f"NVD {cpe23}: {exc}")
            continue
        with transaction(conn):
            store_cves(conn, records, now_ts)
            conn.execute(
                "INSERT INTO nvd_lookup (cpe23, fetched_at, cve_count) VALUES (?, ?, ?) "
                "ON CONFLICT (cpe23) DO UPDATE SET fetched_at = excluded.fetched_at, "
                "cve_count = excluded.cve_count",
                (cpe23, now_ts, len(records)),
            )
        result.cpes_looked_up += 1
        result.cves_stored += len(records)
        _feed_status(conn, "nvd", now_ts, result.cves_stored, f"{result.cpes_looked_up} CPE(s)")

    with transaction(conn):
        result.vulnerabilities = match_all(conn, now_ts)

    if _stale(conn, "kev", now_ts, feed_refresh_hours):
        try:
            entries = fetch_kev(client)
        except FeedError as exc:
            result.errors.append(f"KEV: {exc}")
        else:
            with transaction(conn):
                store_kev(conn, entries)
                _feed_status(conn, "kev", now_ts, len(entries))
            result.kev_entries = len(entries)
    with transaction(conn):
        apply_kev(conn)

    needed = [r[0] for r in conn.execute("SELECT DISTINCT cve_id FROM vulnerability")]
    if needed:
        try:
            scores = fetch_epss(client, needed)
        except FeedError as exc:
            result.errors.append(f"EPSS: {exc}")
        else:
            with transaction(conn):
                for cve_id, score in scores.items():
                    conn.execute(
                        "UPDATE cve SET epss = ?, epss_percentile = ?, epss_date = ? "
                        "WHERE cve_id = ?",
                        (score.epss, score.percentile, score.date, cve_id),
                    )
                _feed_status(conn, "epss", now_ts, len(scores))
            result.epss_updated = len(scores)
    return result


# --------------------------------------------------------------------------
# Steps (each usable on its own, and tested on its own)
# --------------------------------------------------------------------------


def map_services(conn: sqlite3.Connection) -> int:
    """Fill ``service.cpe23`` from nmap's CPE. Only versioned application CPEs."""
    mapped = 0
    rows = conn.execute(
        "SELECT service.id, service.cpe FROM service JOIN asset ON asset.id = service.asset_id "
        "WHERE asset.protected = 0"
    ).fetchall()
    for service_id, cpe in rows:
        parsed = parse_cpe22(cpe) if cpe else None
        cpe23 = parsed.to_23() if parsed and parsed.part == "a" and parsed.has_version else None
        conn.execute("UPDATE service SET cpe23 = ? WHERE id = ?", (cpe23, service_id))
        mapped += cpe23 is not None
    return mapped


def _cpes_to_look_up(
    conn: sqlite3.Connection, now_ts: str, refresh_hours: int, result: EnrichResult
) -> list[str]:
    cutoff = format_ts(parse_ts(now_ts) - timedelta(hours=refresh_hours))
    todo = []
    for (cpe23,) in conn.execute(
        "SELECT DISTINCT cpe23 FROM service JOIN asset ON asset.id = service.asset_id "
        "WHERE asset.protected = 0 AND cpe23 IS NOT NULL ORDER BY cpe23"
    ):
        last = conn.execute(
            "SELECT fetched_at FROM nvd_lookup WHERE cpe23 = ?", (cpe23,)
        ).fetchone()
        if last and last[0] >= cutoff:
            result.cpes_fresh += 1
        else:
            todo.append(cpe23)
    return todo


def store_cves(conn: sqlite3.Connection, records: list[CveRecord], now_ts: str) -> None:
    for record in records:
        conn.execute(
            """
            INSERT INTO cve (cve_id, description, published, cvss_score, cvss_version, cvss_vector,
                             updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (cve_id) DO UPDATE SET
                description = excluded.description, published = excluded.published,
                cvss_score = excluded.cvss_score, cvss_version = excluded.cvss_version,
                cvss_vector = excluded.cvss_vector, updated_at = excluded.updated_at
            """,
            (record.cve_id, record.description, record.published, record.cvss_score,
             record.cvss_version, record.cvss_vector, now_ts),
        )  # fmt: skip
        conn.execute("DELETE FROM cve_rule WHERE cve_id = ?", (record.cve_id,))
        conn.executemany(
            "INSERT INTO cve_rule (cve_id, criteria, vulnerable, start_including, "
            "start_excluding, end_including, end_excluding) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (record.cve_id, r.criteria, int(r.vulnerable), r.start_including,
                 r.start_excluding, r.end_including, r.end_excluding)
                for r in record.rules
            ],
        )  # fmt: skip


def match_all(conn: sqlite3.Connection, now_ts: str) -> int:
    """Re-match every service against stored rules; sync the vulnerability table."""
    total = 0
    services = conn.execute(
        "SELECT service.id, service.cpe23 FROM service JOIN asset ON asset.id = service.asset_id "
        "WHERE asset.protected = 0"
    ).fetchall()
    for service_id, cpe23 in services:
        matches: dict[str, str] = {}
        cpe = parse_cpe23(cpe23) if cpe23 else None
        if cpe is not None:
            prefix = f"cpe:2.3:{cpe.part}:{_vendor_product(cpe23)}:"
            rules = conn.execute(
                "SELECT cve_id, criteria, vulnerable, start_including, start_excluding, "
                "end_including, end_excluding FROM cve_rule "
                "WHERE substr(criteria, 1, ?) = ?",
                (len(prefix), prefix),
            ).fetchall()
            for row in rules:
                rule = CpeMatch(row[1], bool(row[2]), row[3], row[4], row[5], row[6])
                method = match_service(cpe, rule)
                if method and (matches.get(row[0]) != "cpe_exact"):
                    matches[row[0]] = method
        existing = {
            r[0]
            for r in conn.execute(
                "SELECT cve_id FROM vulnerability WHERE service_id = ?", (service_id,)
            )
        }
        for cve_id in existing - set(matches):
            conn.execute(
                "DELETE FROM vulnerability WHERE service_id = ? AND cve_id = ?",
                (service_id, cve_id),
            )
        for cve_id, method in matches.items():
            conn.execute(
                """
                INSERT INTO vulnerability (service_id, cve_id, match_method, confidence,
                                           first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT (service_id, cve_id) DO UPDATE SET
                    match_method = excluded.match_method, confidence = excluded.confidence,
                    last_seen = excluded.last_seen
                """,
                (service_id, cve_id, method, CONFIDENCE[method], now_ts, now_ts),
            )
        total += len(matches)
    return total


def _vendor_product(cpe23: str) -> str:
    """The escaped ``vendor:product`` part of a CPE 2.3 name, as it appears in rules."""
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for ch in cpe23[len("cpe:2.3:") :]:
        if escaped:
            current.append(ch)
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            current.append(ch)
        elif ch == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(ch)
    return f"{fields[1]}:{fields[2]}"


def store_kev(conn: sqlite3.Connection, entries) -> None:
    conn.execute("DELETE FROM kev_entry")
    conn.executemany(
        "INSERT OR REPLACE INTO kev_entry (cve_id, vendor, product, name, date_added, due_date, "
        "ransomware) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [(e.cve_id, e.vendor, e.product, e.name, e.date_added, e.due_date, int(e.ransomware))
         for e in entries],
    )  # fmt: skip


def apply_kev(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        UPDATE cve SET
            kev = CASE WHEN k.cve_id IS NULL THEN 0 ELSE 1 END,
            kev_date_added = k.date_added,
            kev_due_date = k.due_date,
            kev_ransomware = k.ransomware
        FROM (SELECT cve.cve_id AS id, kev_entry.cve_id, kev_entry.date_added,
                     kev_entry.due_date, kev_entry.ransomware
                FROM cve LEFT JOIN kev_entry ON kev_entry.cve_id = cve.cve_id) AS k
        WHERE cve.cve_id = k.id
        """
    )


def _stale(conn: sqlite3.Connection, feed: str, now_ts: str, hours: int) -> bool:
    row = conn.execute("SELECT fetched_at FROM feed_status WHERE feed = ?", (feed,)).fetchone()
    return row is None or parse_ts(now_ts) - parse_ts(row[0]) >= timedelta(hours=hours)


def _feed_status(
    conn: sqlite3.Connection, feed: str, now_ts: str, items: int, detail: str | None = None
) -> None:
    conn.execute(
        "INSERT INTO feed_status (feed, fetched_at, items, detail) VALUES (?, ?, ?, ?) "
        "ON CONFLICT (feed) DO UPDATE SET fetched_at = excluded.fetched_at, "
        "items = excluded.items, detail = excluded.detail",
        (feed, now_ts, items, detail),
    )
