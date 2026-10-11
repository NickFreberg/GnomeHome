"""Append-only, hash-chained audit log (NFR-06). Spec: ``docs/audit-log.md``.

Each row stores the SHA-256 of its own fields plus the previous row's hash,
so editing or removing a row in the middle breaks every hash after it, and
``just audit-verify`` reports where. The schema also blocks UPDATE and DELETE
and refuses rows whose ``seq``/``prev_hash`` don't continue the chain.

The plan gives the audit log to Rust. Python writes to the same table today
because the scan job must record refusals. Both languages follow the same
spec, and both must reproduce ``testdata/audit_vectors.json``.

Keep audit appends out of long write transactions: an entry written inside a
transaction that later rolls back disappears with it.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field
from typing import Any

from gnomehome.db import transaction
from gnomehome.timeutil import utc_now

GENESIS_HASH = "0" * 64
ENCODING_TAG = b"gnomehome-audit-v1\n"
RESULTS = ("success", "failure", "refused")


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    ts: str
    actor: str
    action: str
    target: str | None
    result: str
    details: str | None
    prev_hash: str
    hash: str


def canonical_bytes(
    *,
    seq: int,
    ts: str,
    actor: str,
    action: str,
    target: str | None,
    result: str,
    details: str | None,
    prev_hash: str,
) -> bytes:
    """Length-prefixed encoding of every field (see docs/audit-log.md).

    Each field is ``<byte length>:<UTF-8 bytes>\\n``, or ``-\\n`` for NULL. Length
    prefixes make the encoding unambiguous without any escaping rules, which
    keeps it identical across Python and Rust.
    """
    out = bytearray(ENCODING_TAG)
    for value in (str(seq), ts, actor, action, target, result, details, prev_hash):
        if value is None:
            out += b"-\n"
        else:
            data = value.encode("utf-8")
            out += str(len(data)).encode("ascii") + b":" + data + b"\n"
    return bytes(out)


def compute_hash(**fields: Any) -> str:
    return hashlib.sha256(canonical_bytes(**fields)).hexdigest()


def encode_details(details: dict[str, Any] | None) -> str | None:
    """Compact, key-sorted JSON. The hash covers the stored text exactly."""
    if details is None:
        return None
    return json.dumps(details, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class AuditLog:
    """Appends to and verifies the ``audit_log`` table."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def append(
        self,
        *,
        actor: str,
        action: str,
        target: str | None,
        result: str,
        details: dict[str, Any] | None = None,
    ) -> AuditEntry:
        if not actor or not action:
            raise ValueError("audit entries need an actor and an action")
        if result not in RESULTS:
            raise ValueError(f"result must be one of {RESULTS}, got {result!r}")
        details_text = encode_details(details)
        # BEGIN IMMEDIATE takes the write lock before reading the last hash, so two
        # writers (even in different processes or languages) can't fork the chain.
        with transaction(self.conn):
            last = self.conn.execute(
                "SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            seq = last[0] + 1 if last else 1
            prev_hash = last[1] if last else GENESIS_HASH
            ts = utc_now()
            digest = compute_hash(
                seq=seq,
                ts=ts,
                actor=actor,
                action=action,
                target=target,
                result=result,
                details=details_text,
                prev_hash=prev_hash,
            )
            self.conn.execute(
                "INSERT INTO audit_log "
                "(seq, ts, actor, action, target, result, details, prev_hash, hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (seq, ts, actor, action, target, result, details_text, prev_hash, digest),
            )
        return AuditEntry(seq, ts, actor, action, target, result, details_text, prev_hash, digest)


@dataclass
class VerifyResult:
    rows: int = 0
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


def verify(conn: sqlite3.Connection, *, max_problems: int = 20) -> VerifyResult:
    """Recompute the whole chain and report any break.

    Limit (documented in docs/audit-log.md): someone able to rewrite the
    entire database can rebuild a consistent chain. Anchoring the latest hash
    outside the Pi comes in a later phase.
    """
    result = VerifyResult()
    expected_seq = 1
    prev_hash = GENESIS_HASH
    rows = conn.execute(
        "SELECT seq, ts, actor, action, target, result, details, prev_hash, hash "
        "FROM audit_log ORDER BY seq"
    )
    for row in rows:
        result.rows += 1
        seq = row[0]
        if seq != expected_seq:
            result.problems.append(f"seq {seq}: expected {expected_seq} (rows missing?)")
        if row[7] != prev_hash:
            result.problems.append(f"seq {seq}: prev_hash does not match the previous row's hash")
        recomputed = compute_hash(
            seq=seq,
            ts=row[1],
            actor=row[2],
            action=row[3],
            target=row[4],
            result=row[5],
            details=row[6],
            prev_hash=row[7],
        )
        if recomputed != row[8]:
            result.problems.append(f"seq {seq}: hash mismatch (row was modified)")
        if len(result.problems) >= max_problems:
            result.problems.append("... stopping after too many problems")
            break
        expected_seq = seq + 1
        prev_hash = row[8]
    return result
