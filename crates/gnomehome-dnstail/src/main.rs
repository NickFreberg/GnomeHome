//! `gnomehome-dnstail`: follow Pi-hole's query log into SQLite.
//!
//! ```text
//! gnomehome-dnstail                 follow the log (what the systemd service runs)
//! gnomehome-dnstail --once          read what's new, store it, and exit
//! gnomehome-dnstail --dev --once --log data/synthetic/dns/pihole.log --clock utc
//! ```
//!
//! The config file comes from `--config`, `GNOMEHOME_CONFIG`, or
//! `config/gnomehome.toml`. Output is counts only, never identifiers.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use gnomehome_core::config::{Config, config_path};
use gnomehome_core::db;
use gnomehome_core::time::LogClock;
use gnomehome_dnstail::{LogFile, TailError, Tailer, run_once};

const USAGE: &str =
    "usage: gnomehome-dnstail [--config PATH] [--dev] [--log PATH] [--clock local|utc] [--once]";

struct Args {
    config: PathBuf,
    dev: bool,
    log: Option<PathBuf>,
    clock: LogClock,
    once: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        config: config_path(),
        dev: false,
        log: None,
        clock: LogClock::Local,
        once: false,
    };
    let mut it = std::env::args_os().skip(1);
    while let Some(arg) = it.next() {
        let mut value = |name: &str| it.next().ok_or_else(|| format!("{name} needs a value"));
        match arg.to_str() {
            Some("--config") => args.config = PathBuf::from(value("--config")?),
            Some("--log") => args.log = Some(PathBuf::from(value("--log")?)),
            Some("--clock") => {
                args.clock = match value("--clock")?.to_str() {
                    Some("local") => LogClock::Local,
                    Some("utc") => LogClock::Utc,
                    _ => return Err("--clock must be local or utc".to_owned()),
                }
            }
            Some("--dev") => args.dev = true,
            Some("--once") => args.once = true,
            Some("-h" | "--help") => return Err(String::new()),
            _ => return Err(format!("unknown argument {arg:?}")),
        }
    }
    Ok(args)
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(args) => args,
        Err(msg) => {
            if !msg.is_empty() {
                eprintln!("gnomehome-dnstail: {msg}");
            }
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("gnomehome-dnstail: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &Args) -> Result<(), String> {
    let config = Config::load(&args.config).map_err(|e| e.to_string())?;
    let log = args
        .log
        .clone()
        .or_else(|| config.pihole_log.clone())
        .ok_or("no Pi-hole log: set pihole_log for this platform or pass --log")?;
    let db_path = config.database(args.dev);
    let conn = db::open(db_path)
        .map_err(|e| format!("{}: {e}. Run `just migrate` first.", db_path.display()))?;
    db::require_schema(&conn, db::MIN_SCHEMA_VERSION).map_err(|e| e.to_string())?;
    let mut tailer = Tailer::new(conn, &config.protected_assets, args.clock, args.dev)
        .map_err(|e| e.to_string())?;

    if args.once {
        run_once(&mut tailer, &log).map_err(|e| e.to_string())?;
    } else {
        follow(&mut tailer, &log).map_err(|e| e.to_string())?;
    }
    let s = &tailer.stats;
    println!(
        "dnstail: {} lines, {} queries, {} stored, {} dropped (protected device)",
        s.lines, s.queries, s.stored, s.dropped_protected
    );
    Ok(())
}

/// Follows the log until SIGTERM or Ctrl+C, then stores what's pending and exits.
fn follow(tailer: &mut Tailer, path: &std::path::Path) -> Result<(), TailError> {
    let stop = Arc::new(AtomicBool::new(false));
    for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        signal_hook::flag::register(signal, Arc::clone(&stop))
            .map_err(|e| TailError::Io(path.to_path_buf(), e))?;
    }
    let Some(mut log) = wait_for_file(path, tailer, &stop)? else {
        return Ok(());
    };
    println!("dnstail: following the Pi-hole log");
    let mut last_commit = Instant::now();
    loop {
        let read = log.pump(tailer)?;
        if read == 0 {
            tailer.expire_idle();
        }
        if tailer.ready() >= 500
            || (tailer.ready() > 0 && last_commit.elapsed() >= Duration::from_secs(2))
        {
            tailer.commit(path, log.position())?;
            last_commit = Instant::now();
        }
        tailer.refresh(false)?;
        if stop.load(Ordering::Relaxed) {
            tailer.flush_pending();
            return tailer.commit(path, log.position());
        }
        if read == 0 && log.rotated() {
            // Everything in the old file has been read: store it, then start the new one.
            tailer.flush_pending();
            tailer.commit(path, log.position())?;
            let Some(next) = wait_for_file(path, tailer, &stop)? else {
                return Ok(());
            };
            log = next;
            continue;
        }
        if read == 0 {
            std::thread::sleep(Duration::from_millis(500));
        }
    }
}

/// Opens the log, waiting while it doesn't exist yet (just after rotation, or before
/// Pi-hole first starts). Returns None if asked to stop while waiting.
fn wait_for_file(
    path: &std::path::Path,
    tailer: &Tailer,
    stop: &AtomicBool,
) -> Result<Option<LogFile>, TailError> {
    let mut warned = false;
    loop {
        match LogFile::open(path, tailer) {
            Ok(log) => return Ok(Some(log)),
            Err(TailError::Io(_, err)) if err.kind() == std::io::ErrorKind::NotFound => {
                if !warned {
                    eprintln!("dnstail: waiting for {} to appear", path.display());
                    warned = true;
                }
            }
            Err(err) => return Err(err),
        }
        if stop.load(Ordering::Relaxed) {
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}
