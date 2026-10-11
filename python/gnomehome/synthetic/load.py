"""Load a synthetic dataset into the dev database, through the protected-asset guard.

This plays the part the real collectors will play later: every record passes
the guard before storage, so the protected work laptop's queries and flows
are dropped (flows match on source or destination). Rows are marked
``synthetic = 1`` and ``source = 'synthetic'``. Ground-truth labels are never
stored, so detection code can't peek at them.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from gnomehome.db import transaction
from gnomehome.identifiers import is_locally_administered
from gnomehome.protected import Guard


@dataclass(frozen=True)
class LoadResult:
    assets: int
    dns_events: int
    flow_events: int
    dropped_protected: int


def _jsonl(path: Path) -> Iterator[dict]:
    with open(path) as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def load_synthetic(conn: sqlite3.Connection, guard: Guard, data_dir: Path) -> LoadResult:
    household = json.loads((data_dir / "household.json").read_text())
    with transaction(conn):
        ip_to_asset: dict[str, int] = {}
        for device in guard.filter(household, ips=lambda d: (d["ip"],), macs=lambda d: (d["mac"],)):
            conn.execute(
                """
                INSERT INTO asset (mac, mac_randomized, device_type, last_ip, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT (mac) DO UPDATE SET last_ip = excluded.last_ip
                """,
                (
                    device["mac"],
                    int(is_locally_administered(device["mac"])),
                    device["kind"],
                    device["ip"],
                    device["first_seen"],
                    device["first_seen"],
                ),
            )
            row = conn.execute("SELECT id FROM asset WHERE mac = ?", (device["mac"],)).fetchone()
            ip_to_asset[device["ip"]] = row[0]

        queries = guard.filter(
            _jsonl(data_dir / "dns" / "queries.jsonl"),
            ips=lambda q: (q["client_ip"],),
            macs=lambda q: (q["client_mac"],),
        )
        dns_rows = [
            (
                q["ts"],
                ip_to_asset.get(q["client_ip"]),
                q["client_ip"],
                q["domain"],
                q["qtype"],
                q["status"],
            )
            for q in queries
        ]
        conn.executemany(
            "INSERT INTO event (ts, kind, source, synthetic, asset_id, src_ip, domain, query_type, "
            "status) VALUES (?, 'dns', 'synthetic', 1, ?, ?, ?, ?, ?)",
            dns_rows,
        )

        flows = guard.filter(
            _jsonl(data_dir / "flows" / "flows.jsonl"),
            ips=lambda f: (f["src_ip"], f["dst_ip"]),
        )
        flow_rows = [
            (
                f["start"],
                ip_to_asset.get(f["src_ip"]),
                f["src_ip"],
                f["src_port"],
                f["dst_ip"],
                f["dst_port"],
                f["protocol"],
                f["bytes_out"],
                f["bytes_in"],
                f["packets_out"],
                f["packets_in"],
                json.dumps({"end": f["end"]}),
            )
            for f in flows
        ]
        conn.executemany(
            "INSERT INTO event (ts, kind, source, synthetic, asset_id, src_ip, src_port, dst_ip, "
            "dst_port, protocol, bytes_out, bytes_in, packets_out, packets_in, attrs) "
            "VALUES (?, 'flow', 'synthetic', 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            flow_rows,
        )
    return LoadResult(
        assets=len(ip_to_asset),
        dns_events=len(dns_rows),
        flow_events=len(flow_rows),
        dropped_protected=guard.passive_drops,
    )
