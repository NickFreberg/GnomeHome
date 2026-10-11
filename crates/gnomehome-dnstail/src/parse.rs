//! Parses the dnsmasq `log-queries` lines that Pi-hole writes to `pihole.log`.
//!
//! ```text
//! Oct 11 14:03:00 dnsmasq[812]: query[A] example.test from 192.0.2.21
//! Oct 11 14:03:00 dnsmasq[812]: forwarded example.test to 198.51.100.53
//! Oct 11 14:03:00 dnsmasq[812]: reply example.test is 203.0.113.7
//! Oct 11 14:03:01 dnsmasq[812]: cached example.test is 203.0.113.7
//! Oct 11 14:03:02 dnsmasq[812]: gravity blocked ads.example.test is 0.0.0.0
//! ```
//!
//! With `log-queries=extra`, each message starts with a query ID and the client's
//! address and port (`17 192.0.2.21/53122 query[A] ...`). The ID makes pairing exact.
//!
//! Every name and address here can come from a device, so it is untrusted text:
//! it is length-limited, control characters are refused, and nothing is ever passed
//! to a shell.

/// One meaningful log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line<'a> {
    /// The syslog stamp, such as `Oct 11 14:03:00`.
    pub stamp: &'a str,
    /// The query ID from `log-queries=extra`, if present.
    pub id: Option<u64>,
    pub kind: Kind<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind<'a> {
    Query {
        qtype: &'a str,
        domain: &'a str,
        client: &'a str,
    },
    Forwarded {
        domain: &'a str,
    },
    /// `reply`, `cached`, and local answers (`config`, `/etc/hosts`, ...).
    Answer {
        domain: &'a str,
        answer: &'a str,
        cached: bool,
    },
    /// Pi-hole refused to resolve it (gravity, deny lists, regex filters).
    Blocked {
        domain: &'a str,
    },
}

/// The longest DNS name (253) plus some slack for a trailing dot.
const MAX_NAME: usize = 255;

/// Parses a line, or returns None for lines that don't describe a query outcome
/// (DNSSEC, startup messages, DHCP, anything malformed).
pub fn parse_line(line: &str) -> Option<Line<'_>> {
    let line = line.trim_end_matches(['\r', '\n']);
    let (stamp, rest) = split_stamp(line)?;
    // `dnsmasq[812]: ` or `pihole-FTL[812]: `
    let (_process, message) = rest.split_once("]: ")?;
    let (id, message) = strip_extra_prefix(message);
    let mut words = message.split(' ');
    let verb = words.next()?;
    let kind = if let Some(qtype) = verb
        .strip_prefix("query[")
        .and_then(|v| v.strip_suffix(']'))
    {
        let domain = words.next()?;
        if words.next()? != "from" {
            return None;
        }
        let client = words.next()?;
        Kind::Query {
            qtype: valid_qtype(qtype)?,
            domain: valid_name(domain)?,
            client,
        }
    } else {
        match verb {
            "forwarded" => Kind::Forwarded {
                domain: valid_name(words.next()?)?,
            },
            "reply" | "cached" | "cached-stale" => {
                let domain = valid_name(words.next()?)?;
                if words.next()? != "is" {
                    return None;
                }
                Kind::Answer {
                    domain,
                    answer: words.next()?,
                    cached: verb != "reply",
                }
            }
            "gravity" | "exactly" | "regex" | "special" => {
                // gravity blocked / exactly blacklisted / exactly denied / regex denied /
                // special domain
                let what = words.next()?;
                if !matches!(what, "blocked" | "blacklisted" | "denied" | "domain") {
                    return None;
                }
                Kind::Blocked {
                    domain: valid_name(words.next()?)?,
                }
            }
            "config" | "/etc/hosts" | "local" | "DHCP" => {
                let domain = valid_name(words.next()?)?;
                if words.next()? != "is" {
                    return None;
                }
                Kind::Answer {
                    domain,
                    answer: words.next()?,
                    cached: true,
                }
            }
            other if other.starts_with('/') => {
                // Answers from other host files Pi-hole manages, such as custom.list.
                let domain = valid_name(words.next()?)?;
                if words.next()? != "is" {
                    return None;
                }
                Kind::Answer {
                    domain,
                    answer: words.next()?,
                    cached: true,
                }
            }
            _ => return None,
        }
    };
    Some(Line { stamp, id, kind })
}

/// `Oct 11 14:03:00 rest` or `Oct  1 14:03:00 rest` (day padded with a space).
fn split_stamp(line: &str) -> Option<(&str, &str)> {
    if line.len() < 16 || !line.is_char_boundary(15) || line.as_bytes()[15] != b' ' {
        return None;
    }
    Some((&line[..15], &line[16..]))
}

/// Strips `17 192.0.2.21/53122 ` and returns the ID.
fn strip_extra_prefix(message: &str) -> (Option<u64>, &str) {
    let mut parts = message.splitn(3, ' ');
    if let (Some(id), Some(addr), Some(rest)) = (parts.next(), parts.next(), parts.next()) {
        if let Ok(id) = id.parse::<u64>() {
            if addr.contains('/') {
                return (Some(id), rest);
            }
        }
    }
    (None, message)
}

fn valid_name(name: &str) -> Option<&str> {
    let ok =
        !name.is_empty() && name.len() <= MAX_NAME && name.bytes().all(|b| b.is_ascii_graphic());
    ok.then_some(name)
}

fn valid_qtype(qtype: &str) -> Option<&str> {
    let ok = !qtype.is_empty()
        && qtype.len() <= 16
        && qtype
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'=');
    ok.then_some(qtype)
}

/// The address inside a reverse-lookup name (`10.2.0.192.in-addr.arpa` is 192.0.2.10),
/// so a PTR lookup of a protected device can be dropped like any other mention of it.
pub fn reverse_lookup_ip(domain: &str) -> Option<String> {
    let lower = domain.trim_end_matches('.').to_ascii_lowercase();
    if let Some(rest) = lower.strip_suffix(".in-addr.arpa") {
        let octets: Vec<&str> = rest.split('.').collect();
        if octets.len() == 4 && octets.iter().all(|o| o.parse::<u8>().is_ok()) {
            return Some(octets.iter().rev().copied().collect::<Vec<_>>().join("."));
        }
    }
    if let Some(rest) = lower.strip_suffix(".ip6.arpa") {
        let nibbles: Vec<&str> = rest.split('.').collect();
        if nibbles.len() == 32
            && nibbles
                .iter()
                .all(|n| n.len() == 1 && n.chars().all(|c| c.is_ascii_hexdigit()))
        {
            let hex: String = nibbles.iter().rev().copied().collect();
            let groups: Vec<&str> = (0..8).map(|i| &hex[i * 4..i * 4 + 4]).collect();
            return Some(groups.join(":"));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_each_line_type() {
        let p = |s| parse_line(s).unwrap().kind;
        assert_eq!(
            p("Oct 11 14:03:00 dnsmasq[812]: query[AAAA] example.test from 192.0.2.21"),
            Kind::Query {
                qtype: "AAAA",
                domain: "example.test",
                client: "192.0.2.21"
            }
        );
        assert_eq!(
            p("Oct 11 14:03:00 dnsmasq[812]: forwarded example.test to 198.51.100.53"),
            Kind::Forwarded {
                domain: "example.test"
            }
        );
        assert_eq!(
            p("Oct 11 14:03:00 dnsmasq[812]: reply example.test is NXDOMAIN"),
            Kind::Answer {
                domain: "example.test",
                answer: "NXDOMAIN",
                cached: false
            }
        );
        assert_eq!(
            p("Oct  1 14:03:00 pihole-FTL[9]: cached example.test is 203.0.113.7"),
            Kind::Answer {
                domain: "example.test",
                answer: "203.0.113.7",
                cached: true
            }
        );
        assert_eq!(
            p("Oct 11 14:03:00 dnsmasq[812]: gravity blocked ads.example.test is 0.0.0.0"),
            Kind::Blocked {
                domain: "ads.example.test"
            }
        );
        assert_eq!(
            p("Oct 11 14:03:00 dnsmasq[812]: regex denied x.example.test is 0.0.0.0"),
            Kind::Blocked {
                domain: "x.example.test"
            }
        );
        assert_eq!(
            p(
                "Oct 11 14:03:00 dnsmasq[812]: /etc/pihole/hosts/custom.list nas.home.test is 192.0.2.40"
            ),
            Kind::Answer {
                domain: "nas.home.test",
                answer: "192.0.2.40",
                cached: true
            }
        );
    }

    #[test]
    fn extra_mode_carries_an_id() {
        let line = parse_line("Oct 11 14:03:00 dnsmasq[812]: 17 192.0.2.21/53122 query[A] example.test from 192.0.2.21")
            .unwrap();
        assert_eq!(line.id, Some(17));
        assert_eq!(line.stamp, "Oct 11 14:03:00");
    }

    #[test]
    fn ignores_noise_and_malformed_lines() {
        for line in [
            "",
            "Oct 11 14:03:00 dnsmasq[812]: started, version pi-hole-v2.90",
            "Oct 11 14:03:00 dnsmasq[812]: dnssec-query[DS] test to 198.51.100.53",
            "Oct 11 14:03:00 dnsmasq[812]: query[A] example.test 192.0.2.21",
            "Oct 11 14:03:00 dnsmasq[812]: query[A] bad\u{7}name from 192.0.2.21",
            "garbage",
        ] {
            assert!(parse_line(line).is_none(), "{line:?}");
        }
    }

    #[test]
    fn reverse_lookups_decode() {
        assert_eq!(
            reverse_lookup_ip("10.2.0.192.in-addr.arpa").as_deref(),
            Some("192.0.2.10")
        );
        assert_eq!(
            reverse_lookup_ip("10.2.0.192.IN-ADDR.ARPA.").as_deref(),
            Some("192.0.2.10")
        );
        let v6 = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa";
        assert_eq!(
            reverse_lookup_ip(v6).as_deref(),
            Some("2001:0db8:0000:0000:0000:0000:0000:0001")
        );
        assert_eq!(reverse_lookup_ip("example.test"), None);
        assert_eq!(reverse_lookup_ip("2.0.192.in-addr.arpa"), None);
    }
}
