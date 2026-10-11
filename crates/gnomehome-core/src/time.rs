//! Timestamps in the one format shared with Python (`timeutil.py`).
//!
//! UTC, millisecond precision, trailing `Z`: `2026-10-11T14:03:00.000Z`. The fixed
//! width means text order equals time order, so SQLite compares them as strings.

use chrono::{
    DateTime, Datelike, Duration, Local, LocalResult, NaiveDate, NaiveDateTime, TimeZone, Utc,
};

pub const FORMAT: &str = "%Y-%m-%dT%H:%M:%S%.3fZ";

pub fn format_ts(moment: DateTime<Utc>) -> String {
    moment.format(FORMAT).to_string()
}

pub fn utc_now() -> String {
    format_ts(Utc::now())
}

pub fn parse_ts(text: &str) -> Option<DateTime<Utc>> {
    NaiveDateTime::parse_from_str(text, FORMAT)
        .ok()
        .map(|n| n.and_utc())
}

/// Which clock a log file's timestamps use. dnsmasq on the Pi logs local time.
/// The synthetic logs are written in UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogClock {
    Local,
    Utc,
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Parses a classic syslog stamp (`Oct 11 14:03:00` or `Oct  1 14:03:00`), which has no
/// year. The year is the one that puts the moment closest to `now` without being more
/// than a day in the future, so a December line read in January lands in the old year.
pub fn parse_syslog_stamp(
    stamp: &str,
    now: DateTime<Utc>,
    clock: LogClock,
) -> Option<DateTime<Utc>> {
    let mut parts = stamp.split_whitespace();
    let month_name = parts.next()?;
    let month = MONTHS.iter().position(|m| *m == month_name)? as u32 + 1;
    let day: u32 = parts.next()?.parse().ok()?;
    let time = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let mut hms = time.split(':');
    let (h, m, s): (u32, u32, u32) = (
        hms.next()?.parse().ok()?,
        hms.next()?.parse().ok()?,
        hms.next()?.parse().ok()?,
    );
    if hms.next().is_some() {
        return None;
    }
    let candidates = [now.year() - 1, now.year(), now.year() + 1];
    candidates
        .iter()
        .filter_map(|&year| {
            let naive = NaiveDate::from_ymd_opt(year, month, day)?.and_hms_opt(h, m, s)?;
            to_utc(naive, clock)
        })
        .filter(|moment| *moment <= now + Duration::days(1))
        .max()
}

fn to_utc(naive: NaiveDateTime, clock: LogClock) -> Option<DateTime<Utc>> {
    match clock {
        LogClock::Utc => Some(naive.and_utc()),
        LogClock::Local => match Local.from_local_datetime(&naive) {
            LocalResult::Single(t) => Some(t.with_timezone(&Utc)),
            // The repeated hour when clocks go back: take the earlier reading.
            LocalResult::Ambiguous(earlier, _) => Some(earlier.with_timezone(&Utc)),
            // The skipped hour when clocks go forward can't appear in a real log.
            LocalResult::None => None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utc(text: &str) -> DateTime<Utc> {
        parse_ts(text).unwrap()
    }

    #[test]
    fn round_trips_the_shared_format() {
        let text = "2026-10-11T14:03:00.120Z";
        assert_eq!(format_ts(utc(text)), text);
        assert!(parse_ts("2026-10-11 14:03:00").is_none());
        assert_eq!(utc_now().len(), 24);
    }

    #[test]
    fn syslog_year_is_inferred() {
        let now = utc("2026-10-11T14:05:00.000Z");
        let got = parse_syslog_stamp("Oct 11 14:03:00", now, LogClock::Utc).unwrap();
        assert_eq!(format_ts(got), "2026-10-11T14:03:00.000Z");
        let got = parse_syslog_stamp("Oct  1 09:00:07", now, LogClock::Utc).unwrap();
        assert_eq!(format_ts(got), "2026-10-01T09:00:07.000Z");

        let january = utc("2027-01-01T00:10:00.000Z");
        let got = parse_syslog_stamp("Dec 31 23:59:59", january, LogClock::Utc).unwrap();
        assert_eq!(format_ts(got), "2026-12-31T23:59:59.000Z");
    }

    #[test]
    fn bad_stamps_are_rejected() {
        let now = utc("2026-10-11T14:05:00.000Z");
        for bad in [
            "",
            "Oct 11",
            "Foo 11 14:03:00",
            "Oct 32 14:03:00",
            "Oct 11 25:00:00",
            "Oct 11 14:03:00 x",
        ] {
            assert!(
                parse_syslog_stamp(bad, now, LogClock::Utc).is_none(),
                "{bad}"
            );
        }
    }
}
