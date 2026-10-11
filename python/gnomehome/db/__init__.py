"""SQLite access: the contract between the Python jobs and the Rust services.

Every connection gets the same settings:

* ``journal_mode=WAL``: readers and one writer can work at the same time,
  so the Rust API can read while a Python job writes.
* ``foreign_keys=ON``: SQLite leaves foreign keys off unless asked.
* ``busy_timeout=5000``: wait up to 5 s for another writer instead of failing.
* ``synchronous=NORMAL``: safe with WAL and far fewer SD-card writes (R-11).

Connections run in autocommit mode. Group writes with :func:`transaction`,
which uses ``BEGIN IMMEDIATE`` so the write lock is taken up front.
"""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


def connect(path: Path) -> sqlite3.Connection:
    """Open (creating if needed) the database at ``path`` with GnomeHome's settings."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    is_new = not path.exists()
    conn = sqlite3.connect(path, isolation_level=None)
    conn.row_factory = sqlite3.Row
    mode = conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]
    if mode.lower() != "wal":
        conn.close()
        raise RuntimeError(f"could not enable WAL mode on {path} (got {mode!r})")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA synchronous=NORMAL")
    if is_new:
        # The DB will hold DNS history and device details: owner-only access.
        # SQLite gives the -wal and -shm files the same permissions.
        os.chmod(path, 0o600)
    return conn


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """``BEGIN IMMEDIATE`` ... ``COMMIT``, rolling back on any exception.

    If a transaction is already open, this joins it instead of nesting.
    """
    if conn.in_transaction:
        yield conn
        return
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


def open_database(path: Path) -> sqlite3.Connection:
    """Connect and apply any pending migrations. What every job should call."""
    from gnomehome.db.migrate import migrate

    conn = connect(path)
    migrate(conn)
    return conn
