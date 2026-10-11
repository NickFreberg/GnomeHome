"""Run the Phase 6 analytics on the local database: ``just ml``.

Databricks runs the same functions nightly on the Delta tables. This is the
quick way to see the results on the Mac (with synthetic data) or on the Pi,
without any cloud.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import timedelta

from gnomehome.ml.anomaly import Anomaly, detect
from gnomehome.ml.classifier import Classification, classify, profiles_from_rows
from gnomehome.ml.features import daily_features, fill_missing_days
from gnomehome.timeutil import format_ts, parse_ts


@dataclass
class LocalResult:
    classifications: list[Classification]
    anomalies: list[Anomaly]
    device_days: int


def run_local(
    conn: sqlite3.Connection,
    *,
    days: int = 35,
    leave_one_out: bool = False,
    utc_offset_hours: int = 0,
    pihole_ip: str | None = None,
) -> LocalResult:
    end = conn.execute("SELECT MAX(ts) FROM event WHERE kind IN ('dns', 'flow')").fetchone()[0]
    if end is None:
        return LocalResult([], [], 0)
    start = format_ts(parse_ts(end) - timedelta(days=days))

    def rows(sql: str, *params: object) -> list[dict]:
        return [dict(r) for r in conn.execute(sql, params)]

    dns = rows("SELECT ts, src_ip, domain, status FROM event WHERE kind = 'dns' AND ts > ?", start)
    flows = rows(
        "SELECT ts, src_ip, dst_ip, dst_port, bytes_out, bytes_in FROM event "
        "WHERE kind = 'flow' AND ts > ?",
        start,
    )
    device_days = fill_missing_days(
        daily_features(dns, flows, utc_offset_hours=utc_offset_hours, pihole_ip=pihole_ip)
    )
    profiles = profiles_from_rows(
        rows("SELECT * FROM asset WHERE protected = 0"),
        rows("SELECT s.* FROM service s JOIN asset a ON a.id = s.asset_id WHERE a.protected = 0"),
        dns,
    )
    return LocalResult(
        classifications=[classify(p) for p in profiles],
        anomalies=detect(device_days, leave_one_out=leave_one_out),
        device_days=len(device_days),
    )
