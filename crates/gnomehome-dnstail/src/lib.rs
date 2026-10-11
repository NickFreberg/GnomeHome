//! The DNS log tailer (FR-06): Pi-hole's query log into the shared SQLite database.
//!
//! It runs all the time on the Pi, so it's written in Rust and kept small. Each
//! query becomes one `dns` event with the client, name, type, and outcome.
//!
//! Protected devices (R-12): a query is dropped before storage when the client is
//! protected, when it's a reverse lookup of a protected address, or when the name
//! itself contains a protected address or MAC. Unparseable clients count as
//! protected. The list is re-read whenever the file changes, and if it becomes
//! unreadable or invalid, the tailer stops rather than carry on unguarded.
//!
//! Reading is incremental and survives log rotation. The byte offset is saved in
//! `ingest_checkpoint` in the same transaction as the events, so a restart never
//! stores a line twice. Queries still waiting for their reply when the process is
//! killed (a few seconds' worth) can be lost; a normal stop stores them first.

pub mod pair;
pub mod parse;

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime};

use chrono::{DateTime, Duration, Utc};
use gnomehome_core::protected::{Guard, ProtectedAssets, ProtectedListError};
use gnomehome_core::time::{LogClock, format_ts, parse_syslog_stamp, utc_now};
use rusqlite::{Connection, OptionalExtension, params};

use crate::pair::{Completed, Pairer};
use crate::parse::{parse_line, reverse_lookup_ip};

/// The `ingest_checkpoint.source` and `event.source` values.
pub const CHECKPOINT_SOURCE: &str = "pihole_log";
pub const EVENT_SOURCE: &str = "pihole";

/// How long a query may wait for its outcome line.
pub const PAIR_TIMEOUT_SECONDS: i64 = 5;

#[derive(Debug)]
pub enum TailError {
    Io(PathBuf, std::io::Error),
    Db(rusqlite::Error),
    Protected(ProtectedListError),
}

impl std::fmt::Display for TailError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TailError::Io(path, err) => write!(f, "{}: {err}", path.display()),
            TailError::Db(err) => write!(f, "database error: {err}"),
            TailError::Protected(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for TailError {}

impl From<rusqlite::Error> for TailError {
    fn from(err: rusqlite::Error) -> Self {
        TailError::Db(err)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Stats {
    pub lines: u64,
    pub queries: u64,
    pub stored: u64,
    pub dropped_protected: u64,
}

/// The protected list, re-read when its file changes.
struct WatchedGuard {
    path: PathBuf,
    modified: Option<SystemTime>,
    guard: Guard,
}

impl WatchedGuard {
    fn load(path: &Path) -> Result<WatchedGuard, TailError> {
        let modified = std::fs::metadata(path).and_then(|m| m.modified()).ok();
        let guard = Guard::new(ProtectedAssets::load(path).map_err(TailError::Protected)?);
        Ok(WatchedGuard {
            path: path.to_path_buf(),
            modified,
            guard,
        })
    }

    /// Fails closed: an unreadable or invalid list is an error, never "no list".
    fn refresh(&mut self) -> Result<(), TailError> {
        let modified = std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .ok();
        if modified.is_none() || modified != self.modified {
            *self = WatchedGuard::load(&self.path)?;
        }
        Ok(())
    }
}

pub struct Tailer {
    conn: Connection,
    guard: WatchedGuard,
    clock: LogClock,
    synthetic: bool,
    pairer: Pairer,
    assets: HashMap<String, i64>,
    refreshed: Instant,
    ready: Vec<Completed>,
    last_log_ts: Option<DateTime<Utc>>,
    pub stats: Stats,
}

/// Where reading should resume for one log file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Position {
    pub inode: u64,
    pub offset: u64,
}

impl Tailer {
    pub fn new(
        conn: Connection,
        protected_list: &Path,
        clock: LogClock,
        synthetic: bool,
    ) -> Result<Tailer, TailError> {
        let guard = WatchedGuard::load(protected_list)?;
        let mut tailer = Tailer {
            conn,
            guard,
            clock,
            synthetic,
            pairer: Pairer::new(Duration::seconds(PAIR_TIMEOUT_SECONDS)),
            assets: HashMap::new(),
            refreshed: Instant::now(),
            ready: Vec::new(),
            last_log_ts: None,
            stats: Stats::default(),
        };
        tailer.load_assets()?;
        Ok(tailer)
    }

    fn load_assets(&mut self) -> Result<(), TailError> {
        let mut stmt = self
            .conn
            .prepare("SELECT last_ip, id FROM asset WHERE protected = 0 AND last_ip IS NOT NULL")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
        self.assets = rows.collect::<Result<_, _>>()?;
        self.refreshed = Instant::now();
        Ok(())
    }

    /// Re-reads the asset table and the protected list, at most once a minute.
    pub fn refresh(&mut self, force: bool) -> Result<(), TailError> {
        if force || self.refreshed.elapsed().as_secs() >= 60 {
            self.guard.refresh()?;
            self.load_assets()?;
        }
        Ok(())
    }

    /// The saved position for `path`, or the start if the file was rotated.
    pub fn resume_position(
        &self,
        path: &Path,
        current: Position,
        len: u64,
    ) -> Result<u64, TailError> {
        let saved: Option<(String, i64, i64)> = self
            .conn
            .query_row(
                "SELECT path, inode, byte_offset FROM ingest_checkpoint WHERE source = ?1",
                [CHECKPOINT_SOURCE],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        Ok(match saved {
            Some((p, inode, offset))
                if p == path.to_string_lossy()
                    && inode as u64 == current.inode
                    && offset as u64 <= len =>
            {
                offset as u64
            }
            _ => 0,
        })
    }

    /// Feeds complete lines. Returns how many bytes were consumed (up to the last newline).
    pub fn feed_bytes(&mut self, data: &[u8]) -> usize {
        let Some(end) = data.iter().rposition(|&b| b == b'\n') else {
            return 0;
        };
        for raw in data[..=end].split(|&b| b == b'\n') {
            if raw.is_empty() {
                continue;
            }
            self.stats.lines += 1;
            // Invalid UTF-8 can only come from a hostile name: skip the line.
            let Ok(line) = std::str::from_utf8(raw) else {
                continue;
            };
            self.feed_line(line);
        }
        end + 1
    }

    fn feed_line(&mut self, line: &str) {
        let Some(parsed) = parse_line(line) else {
            return;
        };
        let now = Utc::now();
        let Some(ts) = parse_syslog_stamp(parsed.stamp, now, self.clock) else {
            return;
        };
        if matches!(parsed.kind, parse::Kind::Query { .. }) {
            self.stats.queries += 1;
        }
        self.pairer
            .feed(ts, parsed.id, &parsed.kind, &mut self.ready);
        if self.last_log_ts.is_none_or(|last| ts > last) {
            self.last_log_ts = Some(ts);
            self.pairer.expire(ts, &mut self.ready);
        }
    }

    /// Completes queries that waited too long, by the wall clock (for a quiet log).
    pub fn expire_idle(&mut self) {
        self.pairer.expire(Utc::now(), &mut self.ready);
    }

    pub fn flush_pending(&mut self) {
        self.pairer.flush(&mut self.ready);
    }

    pub fn ready(&self) -> usize {
        self.ready.len()
    }

    fn is_protected(&self, query: &Completed) -> bool {
        let guard = &self.guard.guard;
        guard.is_protected(Some(&query.client), None)
            || reverse_lookup_ip(&query.domain)
                .is_some_and(|ip| guard.is_protected(Some(&ip), None))
            || guard.text_mentions_protected(&query.domain)
    }

    /// Stores completed queries and the new position in one transaction.
    pub fn commit(&mut self, path: &Path, position: Position) -> Result<(), TailError> {
        let ready = std::mem::take(&mut self.ready);
        let (kept, dropped): (Vec<Completed>, Vec<Completed>) =
            ready.into_iter().partition(|q| !self.is_protected(q));
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        {
            let mut insert = tx.prepare_cached(
                "INSERT INTO event (ts, kind, source, synthetic, asset_id, src_ip, domain, query_type, status) \
                 VALUES (?1, 'dns', ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?;
            for q in &kept {
                insert.execute(params![
                    format_ts(q.ts),
                    EVENT_SOURCE,
                    i64::from(self.synthetic),
                    self.assets.get(&q.client),
                    q.client,
                    q.domain,
                    q.qtype,
                    q.status.as_str(),
                ])?;
            }
            tx.execute(
                "INSERT INTO ingest_checkpoint (source, path, inode, byte_offset, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT (source) DO UPDATE SET path = excluded.path, inode = excluded.inode, \
                 byte_offset = excluded.byte_offset, updated_at = excluded.updated_at",
                params![
                    CHECKPOINT_SOURCE,
                    path.to_string_lossy(),
                    position.inode as i64,
                    position.offset as i64,
                    utc_now()
                ],
            )?;
        }
        tx.commit()?;
        self.stats.stored += kept.len() as u64;
        self.stats.dropped_protected += dropped.len() as u64;
        Ok(())
    }
}

/// The inode, which changes when logrotate moves the file aside.
pub fn inode(metadata: &std::fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        std::os::unix::fs::MetadataExt::ino(metadata)
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        0
    }
}

/// An open log file being followed.
pub struct LogFile {
    pub path: PathBuf,
    file: File,
    pub inode: u64,
    /// Offset just past the last complete line handed to the tailer.
    pub offset: u64,
    partial: Vec<u8>,
}

impl LogFile {
    pub fn open(path: &Path, tailer: &Tailer) -> Result<LogFile, TailError> {
        let io = |err| TailError::Io(path.to_path_buf(), err);
        let mut file = File::open(path).map_err(io)?;
        let meta = file.metadata().map_err(io)?;
        let inode = inode(&meta);
        let offset = tailer.resume_position(path, Position { inode, offset: 0 }, meta.len())?;
        file.seek(SeekFrom::Start(offset)).map_err(io)?;
        Ok(LogFile {
            path: path.to_path_buf(),
            file,
            inode,
            offset,
            partial: Vec::new(),
        })
    }

    pub fn position(&self) -> Position {
        Position {
            inode: self.inode,
            offset: self.offset,
        }
    }

    /// Reads whatever is new and feeds complete lines. Returns bytes read.
    pub fn pump(&mut self, tailer: &mut Tailer) -> Result<usize, TailError> {
        let mut chunk = Vec::new();
        let read = (&mut self.file)
            .take(4 << 20)
            .read_to_end(&mut chunk)
            .map_err(|e| TailError::Io(self.path.clone(), e))?;
        if read == 0 {
            return Ok(0);
        }
        self.partial.extend_from_slice(&chunk);
        let consumed = tailer.feed_bytes(&self.partial);
        self.partial.drain(..consumed);
        self.offset += consumed as u64;
        Ok(read)
    }

    /// True if the path now names a different file (moved aside) or the file shrank
    /// (copied and truncated).
    pub fn rotated(&self) -> bool {
        match std::fs::metadata(&self.path) {
            Ok(meta) => inode(&meta) != self.inode || meta.len() < self.offset,
            Err(_) => false, // between the move and the new file appearing
        }
    }
}

/// Reads from the checkpoint to the end of the file, stores everything, and returns.
pub fn run_once(tailer: &mut Tailer, path: &Path) -> Result<(), TailError> {
    let mut log = LogFile::open(path, tailer)?;
    while log.pump(tailer)? > 0 {
        if tailer.ready() >= 5000 {
            tailer.commit(path, log.position())?;
        }
    }
    tailer.flush_pending();
    tailer.commit(path, log.position())
}

#[cfg(test)]
mod tests;
