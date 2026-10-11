//! SQLite connections with the settings every GnomeHome process uses.
//!
//! Same as `python/gnomehome/db/__init__.py`: WAL so readers and one writer work at
//! once, foreign keys on, a 5-second busy timeout, and `synchronous=NORMAL` to spare
//! the SD card (R-11). Python owns the migrations. Rust only checks the version.

use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, OptionalExtension};

/// The oldest schema version the Rust services work with. Migrations only ever add
/// (an applied file is never edited), so a newer database is fine.
pub const MIN_SCHEMA_VERSION: i64 = 4;

#[derive(Debug)]
pub enum DbError {
    Sqlite(rusqlite::Error),
    NotWal(String),
    Schema(String),
}

impl std::fmt::Display for DbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DbError::Sqlite(err) => write!(f, "database error: {err}"),
            DbError::NotWal(mode) => write!(f, "could not enable WAL mode (got {mode:?})"),
            DbError::Schema(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for DbError {}

impl From<rusqlite::Error> for DbError {
    fn from(err: rusqlite::Error) -> Self {
        DbError::Sqlite(err)
    }
}

/// Opens an existing database read-write with GnomeHome's settings. It never
/// creates one: the Python jobs (`just migrate`) do that, with the schema.
pub fn open(path: &Path) -> Result<Connection, DbError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(path, flags)?;
    configure(&conn)?;
    Ok(conn)
}

/// Applies the shared connection settings.
pub fn configure(conn: &Connection) -> Result<(), DbError> {
    let mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") && !mode.eq_ignore_ascii_case("memory") {
        return Err(DbError::NotWal(mode));
    }
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.busy_timeout(Duration::from_millis(5000))?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    Ok(())
}

/// The highest applied migration, or 0 for an empty database.
pub fn schema_version(conn: &Connection) -> Result<i64, DbError> {
    let exists: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if exists.is_none() {
        return Ok(0);
    }
    Ok(conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
        [],
        |row| row.get(0),
    )?)
}

/// Refuses a database whose schema is older than `minimum`.
pub fn require_schema(conn: &Connection, minimum: i64) -> Result<i64, DbError> {
    let version = schema_version(conn)?;
    if version < minimum {
        return Err(DbError::Schema(format!(
            "database schema is version {version}, but this program needs {minimum} or newer. Run `just migrate`."
        )));
    }
    Ok(version)
}

/// Runs `body` inside `BEGIN IMMEDIATE ... COMMIT`, rolling back on error. The write
/// lock is taken up front, like Python's `transaction()`.
pub fn immediate<T, E: From<rusqlite::Error>>(
    conn: &mut Connection,
    body: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<T, E>,
) -> Result<T, E> {
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let value = body(&tx)?;
    tx.commit()?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::migrated_db;

    #[test]
    fn migrated_database_reports_its_version_and_uses_wal() {
        let (_dir, path) = migrated_db();
        let conn = open(&path).unwrap();
        let version = schema_version(&conn).unwrap();
        assert!(version >= MIN_SCHEMA_VERSION);
        assert_eq!(require_schema(&conn, MIN_SCHEMA_VERSION).unwrap(), version);
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        let fk: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(fk, 1);
    }

    #[test]
    fn open_never_creates_a_database() {
        let dir = tempfile::tempdir().unwrap();
        assert!(open(&dir.path().join("missing.sqlite3")).is_err());
    }

    #[test]
    fn empty_database_is_too_old() {
        let conn = Connection::open_in_memory().unwrap();
        assert_eq!(schema_version(&conn).unwrap(), 0);
        assert!(require_schema(&conn, MIN_SCHEMA_VERSION).is_err());
    }
}
