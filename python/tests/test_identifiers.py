import ipaddress

import pytest

from gnomehome.identifiers import (
    InvalidIdentifier,
    is_locally_administered,
    is_multicast,
    normalize_ip,
    normalize_mac,
    normalize_network,
)


@pytest.mark.parametrize(
    "raw",
    [
        "00:00:5e:00:53:0a",
        "00:00:5E:00:53:0A",
        "00-00-5E-00-53-0A",
        "0000.5e00.530a",
        "00005e00530a",
        "0:0:5e:0:53:a",
        "  00:00:5e:00:53:0a\n",
    ],
)
def test_mac_formats_normalize_to_one_form(raw):
    assert normalize_mac(raw) == "00:00:5e:00:53:0a"


@pytest.mark.parametrize(
    "raw",
    ["", "00:00:5e:00:53", "00:00:5e:00:53:0a:01", "00:00-5e:00:53:0a", "zz:00:5e:00:53:0a", 42],
)
def test_bad_macs_raise(raw):
    with pytest.raises(InvalidIdentifier):
        normalize_mac(raw)


def test_ipv4_mapped_ipv6_becomes_ipv4():
    assert normalize_ip("::ffff:192.0.2.10") == ipaddress.ip_address("192.0.2.10")
    assert normalize_network("::ffff:192.0.2.64/126") == ipaddress.ip_network("192.0.2.64/30")


@pytest.mark.parametrize("raw", ["", "192.0.2.256", "192.000.002.010", "192.0.2.0/24", "host"])
def test_bad_ips_raise(raw):
    with pytest.raises(InvalidIdentifier):
        normalize_ip(raw)


def test_network_accepts_single_addresses_and_cidrs():
    assert normalize_network("192.0.2.10").prefixlen == 32
    assert normalize_network("192.0.2.65/30") == ipaddress.ip_network("192.0.2.64/30")


def test_mac_bits():
    assert is_locally_administered("02:00:5e:00:53:01")
    assert not is_locally_administered("00:00:5e:00:53:01")
    assert is_multicast("ff:ff:ff:ff:ff:ff")
    assert is_multicast("01:00:5e:00:00:fb")
    assert not is_multicast("00:00:5e:00:53:01")
