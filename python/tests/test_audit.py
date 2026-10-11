"""The hash-chained audit log: shared vectors, appending, and tamper detection."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from helpers import EXAMPLE_PROTECTED, TESTDATA

from gnomehome.audit import GENESIS_HASH, AuditLog, canonical_bytes, compute_hash, verify
from gnomehome.db import open_database
from gnomehome.db.scrub import scrub_protected
from gnomehome.protected import Guard, ProtectedAssets, ProtectedTargetError

VECTORS = json.loads((TESTDATA / "audit_vectors.json").read_text())
FIELDS = ("seq", "ts", "actor", "action", "target", "result", "details", "prev_hash")


@pytest.fixture
def db(tmp_path: Path) -> sqlite3.Connection:
    conn = open_database(tmp_path / "audit.sqlite3")
    yield conn
    conn.close()


# ------------------------------------------------------------------ shared vectors


@pytest.mark.parametrize("entry", VECTORS["entries"], ids=lambda e: f"seq{e['seq']}")
def test_vector_hashes(entry):
    fields = {name: entry[name] for name in FIELDS}
    assert compute_hash(**fields) == entry["hash"]
    if "canonical_utf8" in entry:
        assert canonical_bytes(**fields) == entry["canonical_utf8"].encode("utf-8")


def test_vectors_form_a_chain():
    prev = VECTORS["genesis_prev_hash"]
    assert prev == GENESIS_HASH
    for entry in VECTORS["entries"]:
        assert entry["prev_hash"] == prev
        prev = entry["hash"]


def test_vectors_load_into_the_table_and_verify(db):
    for entry in VECTORS["entries"]:
        db.execute(
            "INSERT INTO audit_log (seq, ts, actor, action, target, result, details, prev_hash, "
            "hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            tuple(entry[name] for name in (*FIELDS, "hash")),
        )
    result = verify(db)
    assert result.ok, result.problems
    assert result.rows == len(VECTORS["entries"])


def test_null_and_empty_string_hash_differently():
    base = {name: VECTORS["entries"][0][name] for name in FIELDS}
    assert compute_hash(**{**base, "target": None}) != compute_hash(**{**base, "target": ""})


# ------------------------------------------------------------------ appending


def test_append_builds_a_valid_chain(db):
    log = AuditLog(db)
    first = log.append(actor="system:test", action="test.one", target=None, result="success")
    second = log.append(
        actor="system:test", action="test.two", target="x", result="failure", details={"b": 2}
    )
    assert first.seq == 1 and first.prev_hash == GENESIS_HASH
    assert second.seq == 2 and second.prev_hash == first.hash
    assert second.details == '{"b":2}'
    assert verify(db).ok


def test_append_validates_input(db):
    with pytest.raises(ValueError):
        AuditLog(db).append(actor="", action="x", target=None, result="success")
    with pytest.raises(ValueError):
        AuditLog(db).append(actor="a", action="x", target=None, result="maybe")


# ------------------------------------------------------------------ tamper detection


def _build(db, n: int = 4) -> None:
    log = AuditLog(db)
    for i in range(n):
        log.append(actor="system:test", action=f"step.{i}", target=None, result="success")


def test_edited_row_is_detected(db):
    _build(db)
    db.execute("DROP TRIGGER audit_log_no_update")  # what an attacker would do first
    db.execute("UPDATE audit_log SET actor = 'mallory' WHERE seq = 2")
    result = verify(db)
    assert not result.ok
    assert any("seq 2: hash mismatch" in p for p in result.problems)


def test_deleted_row_is_detected(db):
    _build(db)
    db.execute("DROP TRIGGER audit_log_no_delete")
    db.execute("DELETE FROM audit_log WHERE seq = 2")
    problems = verify(db).problems
    assert any("seq 3: expected 2" in p for p in problems)
    assert any("seq 3: prev_hash" in p for p in problems)


# ------------------------------------------------------------------ integration with the guard


def test_guard_refusal_lands_in_the_audit_log_without_identifiers(db):
    guard = Guard(ProtectedAssets.load(EXAMPLE_PROTECTED), audit=AuditLog(db), actor="system:test")
    with pytest.raises(ProtectedTargetError):
        guard.require_allowed("quarantine", mac="00-00-5E-00-53-01")
    row = db.execute("SELECT * FROM audit_log").fetchone()
    assert row["action"] == "guard.refused"
    assert row["result"] == "refused"
    assert row["target"] == "protected:Work laptop"
    stored = " ".join(str(v) for v in tuple(row))
    assert "00:00:5e:00:53:01" not in stored and "192.0.2.10" not in stored
    assert verify(db).ok


def test_scrub_is_audited_with_counts_only(db):
    db.execute(
        "INSERT INTO asset (mac, vendor, first_seen, last_seen) VALUES "
        "('00:00:5e:00:53:01', 'Example', '2026-10-11T00:00:00.000Z', '2026-10-11T00:00:00.000Z')"
    )
    scrub_protected(db, ProtectedAssets.load(EXAMPLE_PROTECTED), audit=AuditLog(db))
    row = db.execute("SELECT action, details FROM audit_log").fetchone()
    assert row["action"] == "guard.scrub"
    assert json.loads(row["details"]) == {"assets_marked_protected": 1, "events_deleted": 0}
