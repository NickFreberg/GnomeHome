//! MAC and IP normalization, matching `python/gnomehome/identifiers.py` exactly.
//!
//! The same device can appear as `AA-BB-CC-DD-EE-FF` (Windows), `aa:bb:cc:dd:ee:ff`
//! (nmap), `aabb.ccdd.eeff` (Cisco), or `a:b:c:d:e:f` (macOS `arp`). Every comparison
//! goes through these functions first.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A MAC or IP string that can't be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidIdentifier(pub String);

impl fmt::Display for InvalidIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid identifier: {:?}", self.0)
    }
}

impl std::error::Error for InvalidIdentifier {}

fn invalid(value: &str) -> InvalidIdentifier {
    InvalidIdentifier(value.to_owned())
}

/// The canonical `aa:bb:cc:dd:ee:ff` form.
pub fn normalize_mac(value: &str) -> Result<String, InvalidIdentifier> {
    let text = value.trim().to_ascii_lowercase();
    let is_hex = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit());
    for (sep, other) in [(':', '-'), ('-', ':')] {
        if text.contains(sep) {
            if text.contains(other) {
                return Err(invalid(value));
            }
            let parts: Vec<&str> = text.split(sep).collect();
            if parts.len() == 6 && parts.iter().all(|p| p.len() <= 2 && is_hex(p)) {
                let octets: Vec<String> = parts.iter().map(|p| format!("{p:0>2}")).collect();
                return Ok(octets.join(":"));
            }
            return Err(invalid(value));
        }
    }
    let bytes = text.as_bytes();
    let hex = if text.len() == 14 && bytes[4] == b'.' && bytes[9] == b'.' {
        text.replace('.', "")
    } else {
        text.clone()
    };
    if hex.len() == 12 && is_hex(&hex) {
        let octets: Vec<&str> = (0..12).step_by(2).map(|i| &hex[i..i + 2]).collect();
        return Ok(octets.join(":"));
    }
    Err(invalid(value))
}

/// Parses an IP address. IPv4-mapped IPv6 (`::ffff:a.b.c.d`) becomes plain IPv4.
pub fn normalize_ip(value: &str) -> Result<IpAddr, InvalidIdentifier> {
    let addr: IpAddr = value.trim().parse().map_err(|_| invalid(value))?;
    Ok(unmap(addr))
}

fn unmap(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    }
}

/// True for multicast and broadcast MACs, which never identify a single device.
pub fn is_multicast(mac: &str) -> bool {
    normalize_mac(mac)
        .ok()
        .and_then(|m| u8::from_str_radix(&m[..2], 16).ok())
        .is_some_and(|b| b & 0x01 == 0x01)
}

/// An address or CIDR block. A single address is a /32 or /128.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Network {
    addr: IpAddr,
    prefix: u8,
}

impl Network {
    pub fn parse(value: &str) -> Result<Network, InvalidIdentifier> {
        let text = value.trim();
        let (addr_text, prefix_text) = match text.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (text, None),
        };
        let raw: IpAddr = addr_text.parse().map_err(|_| invalid(value))?;
        let max = if raw.is_ipv4() { 32 } else { 128 };
        let mut prefix = match prefix_text {
            Some(p) => p.parse::<u8>().map_err(|_| invalid(value))?,
            None => max,
        };
        if prefix > max {
            return Err(invalid(value));
        }
        let mut addr = raw;
        // An IPv4-mapped IPv6 block (::ffff:a.b.c.d/96+) becomes the IPv4 block.
        if let IpAddr::V6(v6) = raw {
            if prefix >= 96 {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    addr = IpAddr::V4(v4);
                    prefix -= 96;
                }
            }
        }
        Ok(Network {
            addr: mask(addr, prefix),
            prefix,
        })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = unmap(ip);
        ip.is_ipv4() == self.addr.is_ipv4() && mask(ip, self.prefix) == self.addr
    }

    pub fn is_ipv4(&self) -> bool {
        self.addr.is_ipv4()
    }
}

fn mask(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let m = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix))
            };
            IpAddr::V4(Ipv4Addr::from(bits & m))
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let m = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix))
            };
            IpAddr::V6(Ipv6Addr::from(bits & m))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_formats_normalize_to_one_form() {
        for raw in [
            "00:00:5e:00:53:0a",
            "00-00-5E-00-53-0A",
            "0000.5e00.530a",
            "00005e00530a",
            "0:0:5e:0:53:a",
            "  00:00:5e:00:53:0a\n",
        ] {
            assert_eq!(normalize_mac(raw).unwrap(), "00:00:5e:00:53:0a", "{raw}");
        }
    }

    #[test]
    fn bad_macs_are_rejected() {
        for raw in [
            "",
            "00:00:5e:00:53",
            "00:00-5e:00:53:0a",
            "zz:00:5e:00:53:0a",
            "000:0:5e:0:53:a",
        ] {
            assert!(normalize_mac(raw).is_err(), "{raw}");
        }
    }

    #[test]
    fn mapped_ipv6_becomes_ipv4_and_cidrs_contain() {
        assert_eq!(
            normalize_ip("::ffff:192.0.2.10").unwrap(),
            "192.0.2.10".parse::<IpAddr>().unwrap()
        );
        let net = Network::parse("192.0.2.65/30").unwrap();
        assert!(net.contains("192.0.2.64".parse().unwrap()));
        assert!(!net.contains("192.0.2.68".parse().unwrap()));
        assert_eq!(Network::parse("::ffff:192.0.2.64/126").unwrap(), net);
    }

    #[test]
    fn multicast_bit() {
        assert!(is_multicast("ff:ff:ff:ff:ff:ff"));
        assert!(!is_multicast("00:00:5e:00:53:01"));
    }
}
