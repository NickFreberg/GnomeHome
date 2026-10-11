"""Load a synthetic dataset into the dev database, through the protected-asset guard.

This runs the same code the real collectors use, wherever it exists:

* The router syslog goes through the real router syslog job, so the inventory
  is built from DHCP, and new-device and drift incidents are raised exactly
  as they will be on the Pi.
* DNS queries and flows pass the guard before storage (flows match on source
  or destination) and attach to assets by IP.

Rows are marked ``synthetic = 1`` and ``source = 'synthetic'``. Ground-truth
labels are never stored, so detection code can't peek at them.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from gnomehome.collectors.router_syslog import IngestResult, ingest_router_syslog
from gnomehome.db import transaction
from gnomehome.protected import Guard


@dataclass(frozen=True)
class LoadResult:
    assets: int
    dns_events: int
    flow_events: int
    syslog: IngestResult
    dropped_protected: int


def _jsonl(path: Path) -> Iterator[dict]:
    with open(path) as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def load_synthetic(
    conn: sqlite3.Connection, guard: Guard, data_dir: Path, *, learning_minutes: int = 60
) -> LoadResult:
    syslog = ingest_router_syslog(
        conn,
        guard,
        data_dir / "router" / "syslog.log",
        learning_minutes=learning_minutes,
        checkpoint=f"synthetic:{data_dir.name}",
        source="synthetic",
        synthetic=True,
    )
    with transaction(conn):
        ip_to_asset = {
            row[1]: row[0]
            for row in conn.execute(
                "SELECT id, last_ip FROM asset WHERE protected = 0 AND last_ip IS NOT NULL"
            )
        }
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
        syslog=syslog,
        dropped_protected=guard.passive_drops + syslog.dropped_protected,
    )
