"""The nightly export: one day of data as gzipped JSON Lines (Phase 6).

Layout, which the Databricks bronze job reads with Auto Loader::

    <export dir>/<table>/date=YYYY-MM-DD/part-0000.jsonl.gz
    <export dir>/_manifests/date=YYYY-MM-DD.json

Tables: snapshots of ``asset``, ``service``, ``vulnerability``, and ``cve``;
that day's ``risk_score``, ``event``, ``audit_log``, and changed ``incident``
rows. Values are exported exactly as stored (JSON columns stay text, so the
audit log's hashes can be re-verified in the cloud).

Protected devices (R-12): their rows never reach the export. Protected assets
are excluded by the queries, and then **every value of every row** is checked
again with the guard (addresses, MACs, and free text). A row that mentions a
protected device is dropped and counted, never written. The protected list
itself stays on the Pi: the cloud can't re-check it, by design.

The manifest lists each file's row count and SHA-256 and the audit log's
latest hash, which anchors the hash chain outside the Pi (docs/audit-log.md).
Files are written with fixed gzip timestamps, so the same data gives the same
bytes.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import shutil
import sqlite3
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from gnomehome.protected import Guard

EXPORT_VERSION = 1
MANIFESTS = "_manifests"

#: Columns that hold an address or a MAC, checked directly as well as as text.
IP_COLUMNS = ("src_ip", "dst_ip", "last_ip")
MAC_COLUMNS = ("mac",)

QUERIES: dict[str, str] = {
    "asset": (
        "SELECT id, mac, mac_randomized, device_type, vendor, hostname, last_ip, os_guess, "
        "os_accuracy, first_seen, last_seen FROM asset WHERE protected = 0 ORDER BY id"
    ),
    "service": (
        "SELECT s.id, s.asset_id, s.port, s.protocol, s.state, s.name, s.product, s.version, "
        "s.extra_info, s.cpe, s.first_seen, s.last_seen FROM service s "
        "JOIN asset a ON a.id = s.asset_id WHERE a.protected = 0 ORDER BY s.id"
    ),
    "vulnerability": (
        "SELECT v.* FROM vulnerability v JOIN service s ON s.id = v.service_id "
        "JOIN asset a ON a.id = s.asset_id WHERE a.protected = 0 ORDER BY v.id"
    ),
    "cve": "SELECT * FROM cve ORDER BY cve_id",
    "risk_score": (
        "SELECT r.* FROM risk_score r JOIN asset a ON a.id = r.asset_id "
        "WHERE a.protected = 0 AND r.score_date = :day ORDER BY r.id"
    ),
    "event": "SELECT * FROM event WHERE ts >= :start AND ts < :end ORDER BY id",
    "incident": (
        "SELECT * FROM incident WHERE updated_at >= :start AND updated_at < :end ORDER BY id"
    ),
    "audit_log": "SELECT * FROM audit_log WHERE ts >= :start AND ts < :end ORDER BY seq",
}


@dataclass
class TableExport:
    rows: int = 0
    dropped_protected: int = 0
    file: str = ""
    sha256: str = ""


@dataclass
class ExportResult:
    day: str
    out_dir: Path
    manifest: Path
    tables: dict[str, TableExport] = field(default_factory=dict)

    @property
    def dropped_protected(self) -> int:
        return sum(t.dropped_protected for t in self.tables.values())


def yesterday(today: date) -> str:
    return (today - timedelta(days=1)).isoformat()


def mentions_protected(guard: Guard, row: dict[str, Any]) -> bool:
    for key, value in row.items():
        if not isinstance(value, str) or not value:
            continue
        if key in IP_COLUMNS and guard.is_protected(ip=value):
            return True
        if key in MAC_COLUMNS and guard.is_protected(mac=value):
            return True
        if guard.text_mentions_protected(value):
            return True
    return False


def export_day(
    conn: sqlite3.Connection,
    guard: Guard,
    out_dir: Path,
    day: str,
    *,
    generated_at: str,
    synthetic: bool,
    keep_days: int = 14,
) -> ExportResult:
    """Write one day's partition and its manifest. Rerunning a day replaces it."""
    start = f"{day}T00:00:00.000Z"
    end = f"{date.fromisoformat(day) + timedelta(days=1)}T00:00:00.000Z"
    params = {"day": day, "start": start, "end": end}
    result = ExportResult(day, out_dir, out_dir / MANIFESTS / f"date={day}.json")
    for table, sql in QUERIES.items():
        stats = TableExport()
        lines = []
        for row in conn.execute(sql, params):
            record = dict(row)
            if mentions_protected(guard, record):
                stats.dropped_protected += 1
                continue
            lines.append(json.dumps(record, ensure_ascii=False, sort_keys=True))
            stats.rows += 1
        relative = Path(table) / f"date={day}" / "part-0000.jsonl.gz"
        data = _gzip(("\n".join(lines) + "\n").encode() if lines else b"")
        _write_private(out_dir / relative, data)
        stats.file, stats.sha256 = relative.as_posix(), hashlib.sha256(data).hexdigest()
        result.tables[table] = stats

    head = conn.execute("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
    manifest = {
        "export_version": EXPORT_VERSION,
        "day": day,
        "generated_at": generated_at,
        "synthetic": synthetic,
        "guard_checked": True,
        "audit_head": {"seq": head[0], "hash": head[1]} if head else None,
        "tables": {name: asdict(t) for name, t in result.tables.items()},
    }
    _write_private(result.manifest, (json.dumps(manifest, indent=2) + "\n").encode())
    _prune(out_dir, day, keep_days)
    return result


def _gzip(data: bytes) -> bytes:
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as gz:
        gz.write(data)
    return buffer.getvalue()


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    tmp.chmod(0o600)
    tmp.replace(path)


def _prune(out_dir: Path, day: str, keep_days: int) -> None:
    """Delete local partitions older than ``keep_days`` before ``day`` (the SD card is small)."""
    cutoff = (date.fromisoformat(day) - timedelta(days=keep_days)).isoformat()
    for partition in out_dir.glob("*/date=*"):
        stamp = partition.name.removeprefix("date=").removesuffix(".json")
        if stamp < cutoff:
            if partition.is_dir():
                shutil.rmtree(partition)
            else:
                partition.unlink()


def partition_files(out_dir: Path, day: str) -> list[Path]:
    """Every file for ``day``, data first and the manifest last."""
    data = sorted(out_dir.glob(f"*/date={day}/part-*.jsonl.gz"))
    manifest = out_dir / MANIFESTS / f"date={day}.json"
    return [*data, manifest] if manifest.exists() else data


def verify_partition(manifest: dict[str, Any], read: Callable[[str], bytes]) -> list[str]:
    """Problems with an exported partition, or an empty list if it's complete and intact.

    ``read`` returns a file's bytes by its manifest path. The silver job calls
    this before trusting a day: the manifest must say the guard checked every
    row, and every file must match its recorded SHA-256.
    """
    problems = []
    if manifest.get("export_version") != EXPORT_VERSION:
        problems.append(f"unknown export version {manifest.get('export_version')!r}")
    if manifest.get("guard_checked") is not True:
        problems.append("the manifest doesn't say the protected-asset guard checked every row")
    for name, entry in manifest.get("tables", {}).items():
        try:
            data = read(entry["file"])
        except (OSError, KeyError) as exc:
            problems.append(f"{name}: file missing ({exc})")
            continue
        if hashlib.sha256(data).hexdigest() != entry.get("sha256"):
            problems.append(f"{name}: SHA-256 doesn't match the manifest")
    return problems
