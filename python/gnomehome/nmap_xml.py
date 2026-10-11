"""Parse nmap's XML output (``-oX``).

Hostnames, banners, product names, and OS strings come from the devices being
scanned, and a malicious device controls them. So:

* XML is parsed with defusedxml, which refuses entity tricks.
* Every device-supplied string goes through :func:`clean_text`: control
  characters are replaced and length is capped. It's stored only via bound
  SQL parameters and never interpreted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from xml.etree.ElementTree import Element

import defusedxml.ElementTree as SafeET
from defusedxml import DefusedXmlException

MAX_TEXT = 255
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class NmapXmlError(Exception):
    """The XML could not be parsed or isn't nmap output."""


@dataclass(frozen=True)
class NmapService:
    port: int
    protocol: str
    state: str
    name: str | None
    product: str | None
    version: str | None
    extra_info: str | None
    cpe: str | None


@dataclass(frozen=True)
class NmapHost:
    status: str
    ip: str | None
    mac: str | None
    vendor: str | None
    hostname: str | None
    services: tuple[NmapService, ...] = ()
    os_name: str | None = None
    os_accuracy: int | None = None
    device_type: str | None = None


@dataclass(frozen=True)
class NmapRun:
    version: str | None
    hosts: tuple[NmapHost, ...]
    hosts_total: int | None
    hosts_up: int | None


def clean_text(value: str | None, max_len: int = MAX_TEXT) -> str | None:
    """Make untrusted device text safe to store and display."""
    if value is None:
        return None
    text = _CONTROL.sub("?", value).strip()
    if not text:
        return None
    return text[:max_len]


def parse_nmap_xml(data: bytes) -> NmapRun:
    try:
        root = SafeET.fromstring(data)
    except (SafeET.ParseError, DefusedXmlException) as exc:
        raise NmapXmlError(f"could not parse nmap XML: {exc}") from None
    if root.tag != "nmaprun":
        raise NmapXmlError(f"not nmap output (root element is <{root.tag}>)")
    hosts = tuple(_parse_host(host) for host in root.findall("host"))
    stats = root.find("runstats/hosts")
    return NmapRun(
        version=root.get("version"),
        hosts=hosts,
        hosts_total=_int(stats.get("total")) if stats is not None else None,
        hosts_up=_int(stats.get("up")) if stats is not None else None,
    )


def _parse_host(host: Element) -> NmapHost:
    status_el = host.find("status")
    ip = mac = vendor = None
    for address in host.findall("address"):
        kind = address.get("addrtype")
        if kind == "ipv4" and ip is None:
            ip = address.get("addr")
        elif kind == "mac" and mac is None:
            mac = address.get("addr")
            vendor = clean_text(address.get("vendor"))
    hostname_el = host.find("hostnames/hostname")
    services = tuple(
        service for port in host.findall("ports/port") if (service := _parse_port(port)) is not None
    )
    os_name = os_accuracy = device_type = None
    best = host.find("os/osmatch")
    if best is not None:
        os_name = clean_text(best.get("name"))
        os_accuracy = _int(best.get("accuracy"))
        osclass = best.find("osclass")
        if osclass is not None:
            device_type = clean_text(osclass.get("type"))
    return NmapHost(
        status=status_el.get("state", "unknown") if status_el is not None else "unknown",
        ip=ip,
        mac=mac,
        vendor=vendor,
        hostname=clean_text(hostname_el.get("name")) if hostname_el is not None else None,
        services=services,
        os_name=os_name,
        os_accuracy=os_accuracy if os_accuracy is not None and 0 <= os_accuracy <= 100 else None,
        device_type=device_type,
    )


def _parse_port(port: Element) -> NmapService | None:
    state_el = port.find("state")
    state = state_el.get("state", "") if state_el is not None else ""
    if not state.startswith("open"):
        return None  # only open and open|filtered ports are services
    number = _int(port.get("portid"))
    protocol = port.get("protocol")
    if number is None or not 0 <= number <= 65535 or protocol not in ("tcp", "udp", "sctp"):
        return None
    service = port.find("service")
    cpe_el = service.find("cpe") if service is not None else None
    return NmapService(
        port=number,
        protocol=protocol,
        state=state,
        name=clean_text(service.get("name")) if service is not None else None,
        product=clean_text(service.get("product")) if service is not None else None,
        version=clean_text(service.get("version")) if service is not None else None,
        extra_info=clean_text(service.get("extrainfo")) if service is not None else None,
        cpe=clean_text(cpe_el.text) if cpe_el is not None else None,
    )


def _int(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None
