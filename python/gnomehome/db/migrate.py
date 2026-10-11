"""Apply numbered SQL migrations from ``gnomehome/db/migrations/``.

* Files are named ``NNNN_description.sql`` and applied in order, each in its
  own transaction (DDL is transactional in SQLite, so a failed migration
  leaves nothing behind).
* ``schema_migrations`` records each applied version with the SHA-256 of
  its file. If an applied file changes later, migrating stops with an error.
  Never edit an applied migration; add a new one.
* Python owns migrations. The Rust services only read ``schema_migrations``
  to check that the version is one they understand.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
from dataclasses import dataclass
from importlib import resources

from gnomehome.timeutil import utc_now

_NAME_RE = re.compile(r"^(\d{4})_([a-z0-9_]+)\.sql$")

_CREATE_TRACKING = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    sha256     TEXT NOT NULL,
    applied_at TEXT NOT NULL
) STRICT
"""


class MigrationError(Exception):
    """Migrations are inconsistent or one failed to apply."""


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    sql: str

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.sql.encode("utf-8")).hexdigest()


def discover() -> list[Migration]:
    """Find migration files, checking they are numbered 1, 2, 3, ... with no gaps."""
    folder = resources.files("gnomehome.db") / "migrations"
    found = []
    for entry in folder.iterdir():
        match = _NAME_RE.match(entry.name)
        if match:
            found.append(Migration(int(match[1]), match[2], entry.read_text(encoding="utf-8")))
    found.sort(key=lambda m: m.version)
    versions = [m.version for m in found]
    if versions != list(range(1, len(found) + 1)):
        raise MigrationError(f"migration numbers must run 1, 2, 3, ... without gaps: {versions}")
    return found


def applied_versions(conn: sqlite3.Connection) -> dict[int, str]:
    conn.execute(_CREATE_TRACKING)
    return {row[0]: row[1] for row in conn.execute("SELECT version, sha256 FROM schema_migrations")}


def migrate(conn: sqlite3.Connection, migrations: list[Migration] | None = None) -> list[int]:
    """Apply pending migrations. Returns the versions applied (empty if up to date)."""
    migrations = discover() if migrations is None else migrations
    applied = applied_versions(conn)
    newly_applied = []
    for migration in migrations:
        if migration.version in applied:
            if applied[migration.version] != migration.sha256:
                raise MigrationError(
                    f"migration {migration.version:04d}_{migration.name}.sql changed after it was "
                    "applied. Revert the edit and put the change in a new migration file."
                )
            continue
        try:
            # executescript runs the whole file; BEGIN IMMEDIATE makes it one transaction.
            conn.executescript(f"BEGIN IMMEDIATE;\n{migration.sql}")
            conn.execute(
                "INSERT INTO schema_migrations (version, name, sha256, applied_at) "
                "VALUES (?, ?, ?, ?)",
                (migration.version, migration.name, migration.sha256, utc_now()),
            )
            conn.execute("COMMIT")
        except sqlite3.Error as exc:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise MigrationError(
                f"migration {migration.version:04d}_{migration.name}.sql failed: {exc}"
            ) from exc
        newly_applied.append(migration.version)
    return newly_applied


def current_version(conn: sqlite3.Connection) -> int:
    applied = applied_versions(conn)
    return max(applied) if applied else 0
