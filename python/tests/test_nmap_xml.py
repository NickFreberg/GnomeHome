import pytest
from helpers import FIXTURES

from gnomehome.nmap_xml import NmapXmlError, clean_text, parse_nmap_xml

NMAP = FIXTURES / "nmap"


def test_parses_discovery_output():
    run = parse_nmap_xml((NMAP / "discovery.xml").read_bytes())
    assert run.version == "7.95"
    assert run.hosts_up == 4
    by_ip = {h.ip: h for h in run.hosts}
    assert by_ip["192.0.2.1"].mac == "00:00:5E:00:53:A1"
    assert by_ip["192.0.2.1"].vendor == "Example Router Co"
    assert by_ip["192.0.2.5"].mac is None  # the scanner itself
    assert all(h.status == "up" for h in run.hosts)


def test_parses_services_os_and_cpe_and_skips_closed_ports():
    run = parse_nmap_xml((NMAP / "service.xml").read_bytes())
    router = next(h for h in run.hosts if h.ip == "192.0.2.1")
    ports = {s.port: s for s in router.services}
    assert sorted(ports) == [53, 80, 443]  # 22 is closed
    assert ports[53].product == "dnsmasq"
    assert ports[53].version == "2.90"
    assert ports[53].cpe == "cpe:/a:thekelleys:dnsmasq:2.90"
    assert ports[443].extra_info == "router admin"
    assert router.os_name == "Linux 4.15 - 5.19"
    assert router.os_accuracy == 98
    assert router.device_type == "WAP"


def test_untrusted_text_is_cleaned():
    assert clean_text("evil\x1b[31m\x00banner") == "evil?[31m?banner"
    assert clean_text("x" * 1000) == "x" * 255
    assert clean_text("   ") is None
    assert clean_text(None) is None


def test_entity_expansion_is_refused():
    bomb = (
        b'<?xml version="1.0"?><!DOCTYPE nmaprun [<!ENTITY a "aaaaaaaaaa">'
        b'<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]><nmaprun>&b;</nmaprun>'
    )
    with pytest.raises(NmapXmlError):
        parse_nmap_xml(bomb)


@pytest.mark.parametrize("data", [b"", b"not xml", b"<other/>"])
def test_garbage_is_refused(data):
    with pytest.raises(NmapXmlError):
        parse_nmap_xml(data)
