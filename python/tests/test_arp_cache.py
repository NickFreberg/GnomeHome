from helpers import EXAMPLE_PROTECTED

from gnomehome.collectors.arp_cache import ArpEntry, check_drift, parse_arp_output
from gnomehome.protected import ProtectedAssets

# Sample outputs with fake documentation-range values, in each tool's real format.
MACOS_ARP = """\
? (192.0.2.1) at 0:0:5e:0:53:a1 on en0 ifscope [ethernet]
? (192.0.2.10) at 0:0:5e:0:53:1 on en0 ifscope [ethernet]
? (192.0.2.44) at (incomplete) on en0 ifscope [ethernet]
? (192.0.2.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
? (198.51.100.9) at 0:0:5e:0:53:99 on bridge100 ifscope [bridge]
"""

LINUX_IP_NEIGH = """\
192.0.2.1 dev eth0 lladdr 00:00:5e:00:53:a1 REACHABLE
192.0.2.10 dev eth0 lladdr 00:00:5e:00:53:01 STALE
192.0.2.44 dev eth0 FAILED
2001:db8::1 dev eth0 lladdr 00:00:5e:00:53:a1 router STALE
"""

LINUX_NET_TOOLS = "? (192.0.2.1) at 00:00:5e:00:53:a1 [ether] on eth0\n"

ASSETS = ProtectedAssets.load(EXAMPLE_PROTECTED)  # laptop: 00:00:5e:00:53:01/02 at 192.0.2.10


def test_parses_macos_arp_with_zero_stripped_macs():
    entries = parse_arp_output(MACOS_ARP)
    assert ArpEntry("192.0.2.1", "00:00:5e:00:53:a1", "en0") in entries
    assert ArpEntry("192.0.2.10", "00:00:5e:00:53:01", "en0") in entries
    ips = {e.ip for e in entries}
    assert "192.0.2.44" not in ips  # incomplete
    assert "192.0.2.255" not in ips  # broadcast
    assert "224.0.0.251" not in ips  # multicast
    assert ("198.51.100.9", "bridge100") in {(e.ip, e.interface) for e in entries}


def test_parses_linux_ip_neigh_and_net_tools():
    entries = parse_arp_output(LINUX_IP_NEIGH)
    assert [e.ip for e in entries] == ["192.0.2.1", "192.0.2.10"]  # FAILED and IPv6 skipped
    assert parse_arp_output(LINUX_NET_TOOLS) == [ArpEntry("192.0.2.1", "00:00:5e:00:53:a1", "eth0")]


def test_no_drift_when_laptop_is_at_its_reserved_ip():
    report = check_drift([ArpEntry("192.0.2.10", "00:00:5e:00:53:01", "en0")], ASSETS)
    assert report.extra_excludes == [] and report.warnings == []


def test_protected_mac_at_unlisted_ip_adds_an_exclusion():
    report = check_drift([ArpEntry("192.0.2.77", "00:00:5e:00:53:02", "en0")], ASSETS)
    assert report.extra_excludes == ["192.0.2.77"]
    assert report.findings == [("Work laptop", "protected_mac_at_unlisted_ip")]
    assert "192.0.2.77" in report.warnings[0]


def test_unknown_mac_at_protected_ip_warns():
    report = check_drift([ArpEntry("192.0.2.10", "00:00:5e:00:53:66", "en0")], ASSETS)
    assert report.extra_excludes == []  # the IP is already excluded
    assert report.findings == [("Work laptop", "unknown_mac_at_protected_ip")]
