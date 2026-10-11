use std::io::Write;

use gnomehome_core::testkit::{migrated_db, repo_root};
use rusqlite::Connection;

use super::*;

const P: &str = "Oct 11 14:03:00 dnsmasq[812]: ";

fn setup() -> (tempfile::TempDir, PathBuf, Tailer) {
    let (dir, db_path) = migrated_db();
    let conn = gnomehome_core::db::open(&db_path).unwrap();
    conn.execute(
        "INSERT INTO asset (mac, first_seen, last_seen, last_ip, protected) \
         VALUES ('00:00:5e:00:53:21', '2026-10-11T00:00:00.000Z', '2026-10-11T00:00:00.000Z', '192.0.2.21', 0)",
        [],
    )
    .unwrap();
    let list = repo_root().join("config/protected_assets.example.yaml");
    let tailer = Tailer::new(conn, &list, LogClock::Utc, true).unwrap();
    let log = dir.path().join("pihole.log");
    (dir, log, tailer)
}

fn write(path: &Path, lines: &[String]) {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    for line in lines {
        writeln!(f, "{line}").unwrap();
    }
}

fn events(conn: &Connection) -> Vec<(String, String, String, Option<i64>)> {
    let mut stmt = conn
        .prepare(
            "SELECT src_ip, domain, status, asset_id FROM event WHERE kind = 'dns' ORDER BY id",
        )
        .unwrap();
    stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[test]
fn once_stores_queries_and_resumes_without_duplicates() {
    let (_dir, log, mut tailer) = setup();
    write(
        &log,
        &[
            format!("{P}query[A] example.test from 192.0.2.21"),
            format!("{P}forwarded example.test to 198.51.100.53"),
            format!("{P}reply example.test is 203.0.113.7"),
            format!("{P}query[A] other.test from 192.0.2.22"),
            format!("{P}cached other.test is 203.0.113.8"),
        ],
    );
    run_once(&mut tailer, &log).unwrap();
    assert_eq!(tailer.stats.stored, 2);
    let got = events(&tailer.conn);
    assert_eq!(
        got[0],
        (
            "192.0.2.21".into(),
            "example.test".into(),
            "forwarded".into(),
            Some(1)
        )
    );
    assert_eq!(got[1].3, None); // no asset with that address yet

    // A second run reads only the new line.
    write(
        &log,
        &[
            format!("{P}query[A] third.test from 192.0.2.21"),
            format!("{P}reply third.test is NXDOMAIN"),
        ],
    );
    run_once(&mut tailer, &log).unwrap();
    let got = events(&tailer.conn);
    assert_eq!(got.len(), 3);
    assert_eq!(got[2].2, "nxdomain");
}

#[test]
fn partial_lines_wait_for_their_newline() {
    let (_dir, log, mut tailer) = setup();
    std::fs::write(
        &log,
        format!("{P}query[A] a.test from 192.0.2.21\n{P}reply a.te"),
    )
    .unwrap();
    run_once(&mut tailer, &log).unwrap();
    // The query was stored as unanswered at the end of the run; the half line wasn't read.
    let offset: i64 = tailer
        .conn
        .query_row(
            "SELECT byte_offset FROM ingest_checkpoint WHERE source = 'pihole_log'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        offset as usize,
        format!("{P}query[A] a.test from 192.0.2.21\n").len()
    );
}

#[test]
fn rotation_restarts_at_the_beginning() {
    let (dir, log, mut tailer) = setup();
    write(
        &log,
        &[
            format!("{P}query[A] old.test from 192.0.2.21"),
            format!("{P}cached old.test is 203.0.113.7"),
        ],
    );
    run_once(&mut tailer, &log).unwrap();
    std::fs::rename(&log, dir.path().join("pihole.log.1")).unwrap();
    write(
        &log,
        &[
            format!("{P}query[A] new.test from 192.0.2.21"),
            format!("{P}cached new.test is 203.0.113.7"),
        ],
    );
    run_once(&mut tailer, &log).unwrap();
    let domains: Vec<String> = events(&tailer.conn).into_iter().map(|e| e.1).collect();
    assert_eq!(domains, vec!["old.test", "new.test"]);
}

#[test]
fn protected_queries_never_reach_the_database() {
    let (_dir, log, mut tailer) = setup();
    write(
        &log,
        &[
            // The laptop itself (192.0.2.10 in the example list), plain and v4-mapped.
            format!("{P}query[A] work.example from 192.0.2.10"),
            format!("{P}reply work.example is 203.0.113.9"),
            format!("{P}query[A] mapped.example from ::ffff:192.0.2.10"),
            format!("{P}reply mapped.example is 203.0.113.9"),
            // Someone else looking the laptop up by address.
            format!("{P}query[PTR] 10.2.0.192.in-addr.arpa from 192.0.2.21"),
            format!("{P}reply 10.2.0.192.in-addr.arpa is NXDOMAIN"),
            // A name that embeds the laptop's MAC.
            format!("{P}query[A] 00-00-5e-00-53-01.lan.test from 192.0.2.21"),
            format!("{P}reply 00-00-5e-00-53-01.lan.test is NXDOMAIN"),
            // An unparseable client fails closed.
            format!("{P}query[A] odd.test from not-an-ip"),
            format!("{P}reply odd.test is NXDOMAIN"),
            // And one ordinary query that should be kept.
            format!("{P}query[A] fine.test from 192.0.2.21"),
            format!("{P}reply fine.test is 203.0.113.1"),
        ],
    );
    run_once(&mut tailer, &log).unwrap();
    assert_eq!(tailer.stats.dropped_protected, 5);
    let got = events(&tailer.conn);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].1, "fine.test");
    let leaked: i64 = tailer
        .conn
        .query_row(
            "SELECT COUNT(*) FROM event WHERE src_ip LIKE '%192.0.2.10%' OR domain LIKE '%192%' OR domain LIKE '%53-01%'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(leaked, 0);
}

#[test]
fn an_invalid_protected_list_stops_the_tailer() {
    let (dir, _db) = migrated_db();
    let conn = gnomehome_core::db::open(&dir.path().join("test.sqlite3")).unwrap();
    let list = dir.path().join("protected_assets.yaml");
    std::fs::write(&list, "version: 1\nprotected: []\n").unwrap();
    assert!(matches!(
        Tailer::new(conn, &list, LogClock::Utc, false),
        Err(TailError::Protected(_))
    ));
}

#[test]
fn a_list_edited_into_garbage_is_caught_on_refresh() {
    let (dir, db) = migrated_db();
    let conn = gnomehome_core::db::open(&db).unwrap();
    let list = dir.path().join("protected_assets.yaml");
    std::fs::copy(
        repo_root().join("config/protected_assets.example.yaml"),
        &list,
    )
    .unwrap();
    let mut tailer = Tailer::new(conn, &list, LogClock::Utc, false).unwrap();
    std::fs::write(&list, "not: [valid").unwrap();
    // Make sure the modification time differs even on coarse-grained filesystems.
    let later = std::time::SystemTime::now() + std::time::Duration::from_secs(5);
    std::fs::File::options()
        .write(true)
        .open(&list)
        .unwrap()
        .set_modified(later)
        .unwrap();
    assert!(tailer.refresh(true).is_err());
}
