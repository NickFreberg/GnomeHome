"""Normalize MAC and IP identifiers so formatting can't dodge a comparison.

The same device can show up as ``AA-BB-CC-DD-EE-FF`` (Windows ``ipconfig /all``),
``aa:bb:cc:dd:ee:ff`` (nmap), ``aabb.ccdd.eeff`` (Cisco), or
``a:b:c:d:e:f`` (macOS ``arp -an``, which drops leading zeros). Every
comparison in GnomeHome goes through these functions first.
"""

from __future__ import annotations

import ipaddress
import re

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

_COLON_OR_DASH = re.compile(r"^[0-9a-f]{1,2}([:-])[0-9a-f]{1,2}(?:\1[0-9a-f]{1,2}){4}$")
_CISCO = re.compile(r"^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$")
_BARE = re.compile(r"^[0-9a-f]{12}$")
_IPV4_MAPPED = ipaddress.IPv6Network("::ffff:0:0/96")


class InvalidIdentifier(ValueError):
    """A MAC or IP string that can't be parsed."""


def normalize_mac(value: str) -> str:
    """Return the canonical ``aa:bb:cc:dd:ee:ff`` form, or raise :class:`InvalidIdentifier`."""
    if not isinstance(value, str):
        raise InvalidIdentifier(f"MAC must be a string, got {type(value).__name__}")
    text = value.strip().lower()
    if _COLON_OR_DASH.match(text):
        return ":".join(octet.zfill(2) for octet in re.split(r"[:-]", text))
    if _CISCO.match(text):
        text = text.replace(".", "")
    if _BARE.match(text):
        return ":".join(text[i : i + 2] for i in range(0, 12, 2))
    raise InvalidIdentifier(f"not a MAC address: {value!r}")


def normalize_ip(value: str) -> IPAddress:
    """Parse an IP address. IPv4-mapped IPv6 (``::ffff:a.b.c.d``) becomes plain IPv4."""
    if not isinstance(value, str):
        raise InvalidIdentifier(f"IP must be a string, got {type(value).__name__}")
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        raise InvalidIdentifier(f"not an IP address: {value!r}") from None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def normalize_network(value: str) -> IPNetwork:
    """Parse an address or CIDR into a network (a single address becomes /32 or /128)."""
    if not isinstance(value, str):
        raise InvalidIdentifier(f"IP must be a string, got {type(value).__name__}")
    try:
        net = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        raise InvalidIdentifier(f"not an IP address or CIDR: {value!r}") from None
    if isinstance(net, ipaddress.IPv6Network) and net.subnet_of(_IPV4_MAPPED):
        v4_base = ipaddress.IPv4Address(int(net.network_address) & 0xFFFFFFFF)
        return ipaddress.IPv4Network((v4_base, net.prefixlen - 96))
    return net


def is_locally_administered(mac: str) -> bool:
    """True for MACs with the local bit set, which includes phones' randomized MACs."""
    return bool(int(normalize_mac(mac)[:2], 16) & 0x02)


def is_multicast(mac: str) -> bool:
    """True for multicast and broadcast MACs, which never identify a single device."""
    return bool(int(normalize_mac(mac)[:2], 16) & 0x01)
