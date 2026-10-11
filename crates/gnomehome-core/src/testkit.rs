//! Test helpers: a database built from the real Python migrations.

use std::path::PathBuf;

use rusqlite::Connection;

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A temporary database with every migration in `python/gnomehome/db/migrations/`
/// applied in order, recorded in `schema_migrations` the way Python records them.
pub fn migrated_db() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.sqlite3");
    let conn = Connection::open(&path).unwrap();
    crate::db::configure(&conn).unwrap();
    apply_migrations(&conn);
    (dir, path)
}

pub fn apply_migrations(conn: &Connection) {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, \
         sha256 TEXT NOT NULL, applied_at TEXT NOT NULL) STRICT",
    )
    .unwrap();
    let mut files: Vec<PathBuf> =
        std::fs::read_dir(repo_root().join("python/gnomehome/db/migrations"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "sql"))
            .collect();
    files.sort();
    for file in files {
        let name = file.file_stem().unwrap().to_string_lossy().into_owned();
        let version: i64 = name[..4].parse().unwrap();
        conn.execute_batch(&std::fs::read_to_string(&file).unwrap())
            .unwrap();
        conn.execute(
            "INSERT INTO schema_migrations VALUES (?1, ?2, 'test', '2026-10-11T00:00:00.000Z')",
            rusqlite::params![version, &name[5..]],
        )
        .unwrap();
    }
}
