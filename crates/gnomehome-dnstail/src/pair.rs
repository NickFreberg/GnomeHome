//! Pairs each query line with the line that says how it ended.
//!
//! A query is logged first (`query[A] name from client`), and its outcome comes a
//! moment later (`reply`, `cached`, `gravity blocked`, ...). In `log-queries=extra`
//! mode both lines carry a query ID. Otherwise they're matched by name, oldest first.
//! A query with no outcome after `timeout` is stored anyway, so nothing is lost when
//! an upstream server never answers.

use chrono::{DateTime, Duration, Utc};

use crate::parse::Kind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Answered by an upstream server.
    Forwarded,
    /// Answered from Pi-hole's cache or local records.
    Cached,
    /// The name doesn't exist.
    NxDomain,
    /// Pi-hole refused to resolve it.
    Blocked,
    /// No outcome was logged within the timeout.
    Unanswered,
}

impl Status {
    /// The value stored in `event.status`, matching the Python analytics.
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Forwarded => "forwarded",
            Status::Cached => "cached",
            Status::NxDomain => "nxdomain",
            Status::Blocked => "blocked",
            Status::Unanswered => "unanswered",
        }
    }
}

/// A finished query, ready to store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Completed {
    pub ts: DateTime<Utc>,
    pub client: String,
    pub domain: String,
    pub qtype: String,
    pub status: Status,
}

#[derive(Debug)]
struct Pending {
    id: Option<u64>,
    ts: DateTime<Utc>,
    client: String,
    domain: String,
    key: String,
    qtype: String,
    forwarded: bool,
}

#[derive(Debug)]
pub struct Pairer {
    pending: Vec<Pending>,
    timeout: Duration,
    /// Cap on queries waiting for an outcome, so a flood can't grow memory.
    max_pending: usize,
}

impl Pairer {
    pub fn new(timeout: Duration) -> Pairer {
        Pairer {
            pending: Vec::new(),
            timeout,
            max_pending: 10_000,
        }
    }

    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Feeds one parsed line. Returns any queries it completed.
    pub fn feed(
        &mut self,
        ts: DateTime<Utc>,
        id: Option<u64>,
        kind: &Kind<'_>,
        out: &mut Vec<Completed>,
    ) {
        match *kind {
            Kind::Query {
                qtype,
                domain,
                client,
            } => {
                if id.is_some() && self.pending.iter().any(|p| p.id == id) {
                    return; // a retry of a query already waiting
                }
                if self.pending.len() >= self.max_pending {
                    let oldest = self.pending.remove(0);
                    out.push(finish(oldest, None));
                }
                self.pending.push(Pending {
                    id,
                    ts,
                    client: client.to_owned(),
                    domain: domain.trim_end_matches('.').to_owned(),
                    key: key(domain),
                    qtype: qtype.to_owned(),
                    forwarded: false,
                });
            }
            Kind::Forwarded { domain } => {
                let k = key(domain);
                for p in self.pending.iter_mut().filter(|p| matches(p, id, &k)) {
                    p.forwarded = true;
                }
            }
            Kind::Answer {
                domain,
                answer,
                cached,
            } => {
                let status = if answer == "NXDOMAIN" {
                    Status::NxDomain
                } else if cached {
                    Status::Cached
                } else {
                    Status::Forwarded
                };
                self.complete(id, &key(domain), status, out);
            }
            Kind::Blocked { domain } => self.complete(id, &key(domain), Status::Blocked, out),
        }
    }

    fn complete(&mut self, id: Option<u64>, k: &str, status: Status, out: &mut Vec<Completed>) {
        let mut i = 0;
        while i < self.pending.len() {
            if matches(&self.pending[i], id, k) {
                let p = self.pending.remove(i);
                out.push(finish(p, Some(status)));
                if id.is_some() {
                    return; // an ID names exactly one query
                }
            } else {
                i += 1;
            }
        }
    }

    /// Completes queries that have waited longer than the timeout.
    pub fn expire(&mut self, now: DateTime<Utc>, out: &mut Vec<Completed>) {
        let timeout = self.timeout;
        let (expired, kept): (Vec<_>, Vec<_>) =
            self.pending.drain(..).partition(|p| now - p.ts > timeout);
        self.pending = kept;
        out.extend(expired.into_iter().map(|p| finish(p, None)));
    }

    /// Completes everything still waiting (end of a `--once` run, or shutdown).
    pub fn flush(&mut self, out: &mut Vec<Completed>) {
        out.extend(self.pending.drain(..).map(|p| finish(p, None)));
    }
}

fn key(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

fn matches(p: &Pending, id: Option<u64>, key: &str) -> bool {
    match (id, p.id) {
        (Some(a), Some(b)) => a == b,
        _ => p.key == key,
    }
}

fn finish(p: Pending, status: Option<Status>) -> Completed {
    let status = status.unwrap_or(if p.forwarded {
        Status::Forwarded
    } else {
        Status::Unanswered
    });
    Completed {
        ts: p.ts,
        client: p.client,
        domain: p.domain,
        qtype: p.qtype,
        status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_line;

    fn run(lines: &[&str]) -> (Vec<Completed>, Pairer) {
        let mut pairer = Pairer::new(Duration::seconds(5));
        let mut out = Vec::new();
        let ts = DateTime::<Utc>::from_timestamp(1_791_727_380, 0).unwrap();
        for line in lines {
            let parsed = parse_line(line).unwrap();
            pairer.feed(ts, parsed.id, &parsed.kind, &mut out);
        }
        (out, pairer)
    }

    const P: &str = "Oct 11 14:03:00 dnsmasq[1]: ";

    #[test]
    fn query_and_reply_pair_by_name() {
        let (out, pairer) = run(&[
            &format!("{P}query[A] Example.test from 192.0.2.21"),
            &format!("{P}forwarded example.test to 198.51.100.53"),
            &format!("{P}reply example.test is 203.0.113.7"),
            &format!("{P}query[A] gone.test from 192.0.2.22"),
            &format!("{P}reply gone.test is NXDOMAIN"),
            &format!("{P}query[A] ads.test from 192.0.2.23"),
            &format!("{P}gravity blocked ads.test is 0.0.0.0"),
            &format!("{P}query[A] example.test from 192.0.2.24"),
            &format!("{P}cached example.test is 203.0.113.7"),
        ]);
        let got: Vec<(&str, &str, Status)> = out
            .iter()
            .map(|c| (c.client.as_str(), c.domain.as_str(), c.status))
            .collect();
        assert_eq!(
            got,
            vec![
                ("192.0.2.21", "Example.test", Status::Forwarded),
                ("192.0.2.22", "gone.test", Status::NxDomain),
                ("192.0.2.23", "ads.test", Status::Blocked),
                ("192.0.2.24", "example.test", Status::Cached),
            ]
        );
        assert_eq!(pairer.pending(), 0);
    }

    #[test]
    fn ids_pair_exactly_and_retries_are_ignored() {
        let (out, _) = run(&[
            &format!("{P}1 192.0.2.21/5000 query[A] same.test from 192.0.2.21"),
            &format!("{P}2 192.0.2.22/5001 query[A] same.test from 192.0.2.22"),
            &format!("{P}1 192.0.2.21/5000 query[A] same.test from 192.0.2.21"),
            &format!("{P}2 192.0.2.22/5001 cached same.test is 203.0.113.7"),
        ]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].client, "192.0.2.22");
    }

    #[test]
    fn unanswered_queries_expire() {
        let (mut out, mut pairer) = run(&[
            &format!("{P}query[A] slow.test from 192.0.2.21"),
            &format!("{P}forwarded slow.test to 198.51.100.53"),
            &format!("{P}query[A] never.test from 192.0.2.21"),
        ]);
        assert!(out.is_empty());
        let later = DateTime::<Utc>::from_timestamp(1_791_727_380 + 6, 0).unwrap();
        pairer.expire(later, &mut out);
        let statuses: Vec<Status> = out.iter().map(|c| c.status).collect();
        assert_eq!(statuses, vec![Status::Forwarded, Status::Unanswered]);
    }
}
