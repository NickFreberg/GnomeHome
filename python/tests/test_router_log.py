from datetime import UTC, datetime

import pytest

from gnomehome.router_log import parse_dhcp, parse_syslog_line

NOW = datetime(2026, 10, 11, 15, 0, tzinfo=UTC)


def test_rsyslog_rfc3339_line_with_host():
    line = parse_syslog_line(
        "2026-10-11T14:03:12.123456+02:00 router dnsmasq-dhcp[1234]: "
        "DHCPACK(br0) 192.0.2.21 00:00:5e:00:53:21 kids-phone"
    )
    assert line.ts == datetime(2026, 10, 11, 12, 3, 12, 123456, tzinfo=UTC)  # converted to UTC
    assert line.program == "dnsmasq-dhcp"
    dhcp = parse_dhcp(line)
    assert (dhcp.kind, dhcp.interface, dhcp.ip, dhcp.mac, dhcp.hostname) == (
        "DHCPACK",
        "br0",
        "192.0.2.21",
        "00:00:5e:00:53:21",
        "kids-phone",
    )


def test_router_rfc3164_line_without_host_infers_the_year():
    line = parse_syslog_line(
        "Oct 11 14:03:12 dnsmasq-dhcp[99]: DHCPDISCOVER(br0) 00:00:5e:00:53:21", now=NOW
    )
    assert line.ts == datetime(2026, 10, 11, 14, 3, 12, tzinfo=UTC)
    dhcp = parse_dhcp(line)
    assert dhcp.kind == "DHCPDISCOVER" and dhcp.ip is None and dhcp.hostname is None


def test_december_line_read_in_january_is_last_year():
    line = parse_syslog_line("Dec 31 23:59:59 kernel: x", now=datetime(2027, 1, 1, tzinfo=UTC))
    assert line.ts.year == 2026


@pytest.mark.parametrize(
    ("message", "kind", "ip", "hostname"),
    [
        ("DHCPOFFER(br0) 192.0.2.21 00:00:5e:00:53:21", "DHCPOFFER", "192.0.2.21", None),
        ("DHCPREQUEST(br0) 192.0.2.21 00:00:5e:00:53:21", "DHCPREQUEST", "192.0.2.21", None),
        ("DHCPACK(br0) 192.0.2.21 00:00:5e:00:53:21", "DHCPACK", "192.0.2.21", None),
        ("DHCPNAK(br0) 192.0.2.21 00:00:5e:00:53:21 wrong address", "DHCPNAK", "192.0.2.21", None),
        ("DHCPRELEASE(br0) 192.0.2.21 00:00:5e:00:53:21", "DHCPRELEASE", "192.0.2.21", None),
        (
            "DHCPACK(br0) 192.0.2.21 00:00:5e:00:53:21 My iPhone",
            "DHCPACK",
            "192.0.2.21",
            "My iPhone",
        ),
    ],
)
def test_dhcp_message_kinds(message, kind, ip, hostname):
    dhcp = parse_dhcp(parse_syslog_line(f"2026-10-11T14:03:12Z router dnsmasq-dhcp[1]: {message}"))
    assert (dhcp.kind, dhcp.ip, dhcp.hostname) == (kind, ip, hostname)


def test_non_dhcp_lines_parse_but_are_not_dhcp():
    line = parse_syslog_line("2026-10-11T14:03:12Z router kernel: DROP IN=eth0 SRC=203.0.113.9")
    assert line.program == "kernel" and parse_dhcp(line) is None
    other = parse_syslog_line(
        "2026-10-11T14:03:12Z router dnsmasq-dhcp[1]: 123 available DHCP range"
    )
    assert parse_dhcp(other) is None


@pytest.mark.parametrize(
    "raw", ["", "garbage", "2026-13-45T99:99:99Z router x: y", "Foo 1 00:00:00 x: y"]
)
def test_unparseable_lines_return_none(raw):
    assert parse_syslog_line(raw, now=NOW) is None
