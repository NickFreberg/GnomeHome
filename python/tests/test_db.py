"""SQLite connection settings, migrations, and the schema's own safety rules."""

from __future__ import annotations

import sqlite3
import stat
from pathlib import Path

import pytest
from helpers import EXAMPLE_PROTECTED

from gnomehome.db import connect, open_database, transaction
from gnomehome.db.migrate import Migration, MigrationError, current_version, discover, migrate
from gnomehome.db.scrub import scrub_protected
from gnomehome.protected import ProtectedAssets

TS = "2026-10-11T14:03:00.000Z"
ZERO_HASH = "0" * 64


@pytest.fixture
def db(tmp_path: Path) -> sqlite3.Connection:
    conn = open_database(tmp_path / "data" / "test.sqlite3")
    yield conn
    conn.close()


def add_asset(conn, mac: str, *, protected: int = 0, **fields) -> int:
    cols = {"mac": mac, "protected": protected, "first_seen": TS, "last_seen": TS, **fields}
    names = ", ".join(cols)
    marks = ", ".join("?" for _ in cols)
    return conn.execute(
        f"INSERT INTO asset ({names}) VALUES ({marks})", tuple(cols.values())
    ).lastrowid


def add_service(conn, asset_id: int, port: int = 80) -> int:
    return conn.execute(
        "INSERT INTO service (asset_id, port, protocol, state, first_seen, last_seen) "
        "VALUES (?, ?, 'tcp', 'open', ?, ?)",
        (asset_id, port, TS, TS),
    ).lastrowid


def add_event(conn, *, asset_id=None, src_ip="192.0.2.23", dst_ip="198.51.100.7") -> int:
    return conn.execute(
        "INSERT INTO event (ts, kind, source, asset_id, src_ip, dst_ip, protocol) "
        "VALUES (?, 'flow', 'test', ?, ?, ?, 'tcp')",
        (TS, asset_id, src_ip, dst_ip),
    ).lastrowid


def count(conn, table: str) -> int:
    return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


# ------------------------------------------------------------------ connection


def test_connect_uses_wal_and_safe_settings(tmp_path: Path):
    conn = connect(tmp_path / "data" / "x.sqlite3")
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 5000
    assert conn.execute("PRAGMA synchronous").fetchone()[0] == 1  # NORMAL


def test_new_database_is_private_to_the_owner(tmp_path: Path):
    path = tmp_path / "data" / "x.sqlite3"
    connect(path).close()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_transaction_rolls_back_on_error(db):
    with pytest.raises(RuntimeError), transaction(db):
        add_asset(db, "00:00:5e:00:53:01")
        raise RuntimeError("boom")
    assert count(db, "asset") == 0


# ------------------------------------------------------------------ migrations


def test_migrations_are_discovered_in_order():
    versions = [m.version for m in discover()]
    assert versions[0] == 1
    assert versions == sorted(versions)


def test_migrate_is_idempotent(tmp_path: Path):
    conn = connect(tmp_path / "x.sqlite3")
    assert migrate(conn) == [m.version for m in discover()]
    assert migrate(conn) == []
    assert current_version(conn) == len(discover())


def test_all_core_tables_exist(db):
    names = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    expected = {"asset", "service", "cve", "vulnerability", "risk_score", "event", "incident"}
    assert expected | {"audit_log", "scan_run", "schema_migrations"} <= names


def test_edited_migration_is_refused(tmp_path: Path):
    conn = connect(tmp_path / "x.sqlite3")
    migrate(conn)
    original = discover()
    edited = [Migration(original[0].version, original[0].name, original[0].sql + "\n-- edit")]
    with pytest.raises(MigrationError, match="changed after it was applied"):
        migrate(conn, edited + original[1:])


def test_failed_migration_leaves_nothing_behind(tmp_path: Path):
    conn = connect(tmp_path / "x.sqlite3")
    broken = Migration(1, "broken", "CREATE TABLE half_done (x INTEGER);\nTHIS IS NOT SQL;")
    with pytest.raises(MigrationError, match="failed"):
        migrate(conn, [broken])
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert "half_done" not in tables
    assert current_version(conn) == 0


# ------------------------------------------------------------------ schema rules


def test_strict_tables_enforce_types(db):
    asset_id = add_asset(db, "00:00:5e:00:53:01")
    with pytest.raises(sqlite3.IntegrityError):
        db.execute(
            "INSERT INTO service (asset_id, port, protocol, state, first_seen, last_seen) "
            "VALUES (?, 'eighty', 'tcp', 'open', ?, ?)",
            (asset_id, TS, TS),
        )


@pytest.mark.parametrize("mac", ["00:00:5E:00:53:01", "00-00-5e-00-53-01", "0:0:5e:0:53:1"])
def test_only_normalized_macs_can_be_stored(db, mac):
    with pytest.raises(sqlite3.IntegrityError):
        add_asset(db, mac)


@pytest.mark.parametrize("ts", ["2026-10-11 14:03:00", "2026-10-11T14:03:00Z", "yesterday"])
def test_timestamps_must_use_the_shared_format(db, ts):
    with pytest.raises(sqlite3.IntegrityError):
        db.execute(
            "INSERT INTO asset (mac, first_seen, last_seen) VALUES ('00:00:5e:00:53:01', ?, ?)",
            (ts, ts),
        )


def test_event_kinds_require_their_fields(db):
    with pytest.raises(sqlite3.IntegrityError):
        db.execute(
            "INSERT INTO event (ts, kind, source, src_ip) VALUES (?, 'dns', 'test', '192.0.2.5')",
            (TS,),
        )


# ------------------------------------------------------------------ protected assets in the schema


def test_protected_asset_cannot_carry_details(db):
    with pytest.raises(sqlite3.IntegrityError):
        add_asset(db, "00:00:5e:00:53:01", protected=1, vendor="Example Corp")
    add_asset(db, "00:00:5e:00:53:01", protected=1)  # existence only: allowed


@pytest.mark.parametrize("table", ["service", "event", "risk_score", "incident"])
def test_nothing_can_be_stored_about_a_protected_asset(db, table):
    asset_id = add_asset(db, "00:00:5e:00:53:01", protected=1)
    inserts = {
        "service": lambda: add_service(db, asset_id),
        "event": lambda: add_event(db, asset_id=asset_id),
        "risk_score": lambda: db.execute(
            "INSERT INTO risk_score (asset_id, score_date, score, level, model_version, "
            "computed_at) VALUES (?, '2026-10-11', 10, 'low', 'v0', ?)",
            (asset_id, TS),
        ),
        "incident": lambda: db.execute(
            "INSERT INTO incident (created_at, updated_at, asset_id, detection, severity, title, "
            "summary) VALUES (?, ?, ?, 'test', 'low', 't', 's')",
            (TS, TS, asset_id),
        ),
    }
    with pytest.raises(sqlite3.IntegrityError, match="protected asset"):
        inserts[table]()


def test_rows_cannot_be_moved_onto_a_protected_asset(db):
    normal = add_asset(db, "00:00:5e:00:53:20")
    protected = add_asset(db, "00:00:5e:00:53:01", protected=1)
    service_id = add_service(db, normal)
    with pytest.raises(sqlite3.IntegrityError, match="protected asset"):
        db.execute("UPDATE service SET asset_id = ? WHERE id = ?", (protected, service_id))


def test_marking_an_asset_protected_deletes_its_history(db):
    asset_id = add_asset(db, "00:00:5e:00:53:01", vendor="Example Corp", last_ip="192.0.2.10")
    add_service(db, asset_id)
    add_event(db, asset_id=asset_id)
    db.execute(
        "UPDATE asset SET protected = 1, vendor = NULL, last_ip = NULL WHERE id = ?", (asset_id,)
    )
    assert count(db, "service") == 0
    assert count(db, "event") == 0


# ------------------------------------------------------------------ audit log rules


def _audit(db, seq: int, prev_hash: str, hash_: str):
    db.execute(
        "INSERT INTO audit_log (seq, ts, actor, action, result, prev_hash, hash) "
        "VALUES (?, ?, 'test', 'test.action', 'success', ?, ?)",
        (seq, TS, prev_hash, hash_),
    )


def test_audit_log_is_append_only(db):
    _audit(db, 1, ZERO_HASH, "a" * 64)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        db.execute("UPDATE audit_log SET actor = 'mallory'")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        db.execute("DELETE FROM audit_log")


def test_audit_log_chain_must_link(db):
    with pytest.raises(sqlite3.IntegrityError, match="prev_hash"):
        _audit(db, 1, "f" * 64, "a" * 64)  # first row must point at the zero hash
    _audit(db, 1, ZERO_HASH, "a" * 64)
    with pytest.raises(sqlite3.IntegrityError, match="prev_hash"):
        _audit(db, 2, "b" * 64, "c" * 64)  # wrong previous hash
    with pytest.raises(sqlite3.IntegrityError, match="seq"):
        _audit(db, 3, "a" * 64, "c" * 64)  # gap in sequence
    _audit(db, 2, "a" * 64, "c" * 64)


# ------------------------------------------------------------------ scrub


def test_scrub_marks_protected_assets_and_deletes_their_data(db):
    assets = ProtectedAssets.load(EXAMPLE_PROTECTED)
    laptop = add_asset(db, "00:00:5e:00:53:02", vendor="Example Corp", last_ip="192.0.2.99")
    by_ip = add_asset(db, "00:00:5e:00:53:30", last_ip="192.0.2.10")
    other = add_asset(db, "00:00:5e:00:53:31", vendor="Other", last_ip="192.0.2.31")
    add_service(db, laptop)
    add_service(db, other)
    add_event(db, src_ip="192.0.2.10")  # unattributed flow from the protected IP
    add_event(db, src_ip="192.0.2.31", dst_ip="192.0.2.10")  # flow *to* the protected IP
    add_event(db, src_ip="192.0.2.31")  # unrelated: kept

    result = scrub_protected(db, assets)

    assert result.assets_marked == 2
    assert result.events_deleted == 2
    rows = {r["id"]: r for r in db.execute("SELECT * FROM asset")}
    assert rows[laptop]["protected"] == 1 and rows[laptop]["vendor"] is None
    assert rows[by_ip]["protected"] == 1
    assert rows[other]["protected"] == 0 and rows[other]["vendor"] == "Other"
    assert count(db, "service") == 1
    assert count(db, "event") == 1
    assert scrub_protected(db, assets).assets_marked == 0  # idempotent
