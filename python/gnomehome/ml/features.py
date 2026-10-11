"""Daily behavior features per device (the gold layer's ``device_day`` table).

Inputs are plain mappings with the same keys as the ``event`` table (and the
exported JSON Lines), so this runs on SQLite rows locally and on rows
collected from Delta tables in Databricks. A household produces a few hundred
device-days a month, which fits easily in one process.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from gnomehome.analytics.domains import registered_domain
from gnomehome.timeutil import parse_ts

#: Every feature, with the words used to explain it.
FEATURES: dict[str, str] = {
    "dns_queries": "DNS lookups",
    "distinct_domains": "different domains looked up",
    "nxdomain_share": "share of lookups for domains that don't exist",
    "blocked_share": "share of lookups Pi-hole blocked",
    "new_domains": "domains looked up for the first time",
    "night_share": "share of lookups between midnight and 6 a.m.",
    "flows": "connections",
    "bytes_out": "bytes uploaded",
    "bytes_in": "bytes downloaded",
    "distinct_destinations": "different internet addresses contacted",
    "dns_bypass_flows": "DNS connections that skipped Pi-hole",
}

DNS_PORTS = (53, 853)


@dataclass
class DeviceDay:
    device: str
    day: str
    values: dict[str, float] = field(default_factory=dict)


def daily_features(
    dns: Iterable[Mapping[str, Any]],
    flows: Iterable[Mapping[str, Any]],
    *,
    known_domains: Mapping[str, set[str]] | None = None,
    utc_offset_hours: int = 0,
    pihole_ip: str | None = None,
) -> list[DeviceDay]:
    """One :class:`DeviceDay` per device (by source IP) per local calendar day.

    ``known_domains`` maps a device to the registered domains it used before
    the data starts, so ``new_domains`` isn't inflated on the first day.
    """
    offset = timedelta(hours=utc_offset_hours)
    seen: dict[str, set[str]] = defaultdict(set)
    for device, domains in (known_domains or {}).items():
        seen[device] |= set(domains)

    acc: dict[tuple[str, str], dict[str, Any]] = defaultdict(_empty)
    for row in sorted(dns, key=lambda r: r["ts"]):
        device, local = row["src_ip"], parse_ts(row["ts"]) + offset
        a = acc[(device, local.date().isoformat())]
        a["dns_queries"] += 1
        domain = registered_domain(row["domain"])
        a["domains"].add(domain)
        if domain not in seen[device]:
            seen[device].add(domain)
            a["new_domains"] += 1
        a["nxdomain"] += row.get("status") == "nxdomain"
        a["blocked"] += row.get("status") == "blocked"
        a["night"] += local.hour < 6
    for row in flows:
        device, local = row["src_ip"], parse_ts(row["ts"]) + offset
        a = acc[(device, local.date().isoformat())]
        a["flows"] += 1
        a["bytes_out"] += row.get("bytes_out") or 0
        a["bytes_in"] += row.get("bytes_in") or 0
        a["destinations"].add(row["dst_ip"])
        if row.get("dst_port") in DNS_PORTS and row["dst_ip"] != pihole_ip:
            a["bypass"] += 1

    out = []
    for (device, day), a in sorted(acc.items()):
        queries = a["dns_queries"]
        out.append(
            DeviceDay(
                device,
                day,
                {
                    "dns_queries": float(queries),
                    "distinct_domains": float(len(a["domains"])),
                    "nxdomain_share": a["nxdomain"] / queries if queries else 0.0,
                    "blocked_share": a["blocked"] / queries if queries else 0.0,
                    "new_domains": float(a["new_domains"]),
                    "night_share": a["night"] / queries if queries else 0.0,
                    "flows": float(a["flows"]),
                    "bytes_out": float(a["bytes_out"]),
                    "bytes_in": float(a["bytes_in"]),
                    "distinct_destinations": float(len(a["destinations"])),
                    "dns_bypass_flows": float(a["bypass"]),
                },
            )
        )
    return out


def _empty() -> dict[str, Any]:
    return {
        "dns_queries": 0,
        "domains": set(),
        "new_domains": 0,
        "nxdomain": 0,
        "blocked": 0,
        "night": 0,
        "flows": 0,
        "bytes_out": 0,
        "bytes_in": 0,
        "destinations": set(),
        "bypass": 0,
    }


def fill_missing_days(days: list[DeviceDay]) -> list[DeviceDay]:
    """Add all-zero rows for days a device was silent, between its first and last day.

    A quiet day is information: without it, a device that's usually silent at
    weekends would look normal only on the days it talks.
    """
    by_device: dict[str, dict[str, DeviceDay]] = defaultdict(dict)
    for d in days:
        by_device[d.device][d.day] = d
    out = []
    for device, rows in sorted(by_device.items()):
        start, end = min(rows), max(rows)
        day = parse_ts(f"{start}T00:00:00.000Z")
        while (text := day.date().isoformat()) <= end:
            out.append(rows.get(text) or DeviceDay(device, text, dict.fromkeys(FEATURES, 0.0)))
            day += timedelta(days=1)
    return out
