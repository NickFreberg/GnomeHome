"""Synthetic nmap service-scan output for the fake household.

Written in nmap's real XML format and loaded through the real parser and
inventory writer, so ``just enrich --dev`` and ``just score --dev`` have
software to work on. The CPEs name real products and versions, so a live
enrichment run finds real CVEs. The protected work laptop never appears,
just as the exclude file keeps it out of a real scan.
"""

from __future__ import annotations

from datetime import datetime
from xml.etree.ElementTree import Element, SubElement, tostring

from gnomehome.synthetic.household import ROUTER_IP, Device

ROUTER_MAC = "00:00:5e:00:53:a1"

#: device name -> (vendor, os name, os type, [(port, service, product, version, cpe)])
SERVICES: dict[str, tuple[str | None, str | None, str | None, list[tuple]]] = {
    "router": ("Example Router Co", "Linux 4.15 - 5.19", "WAP", [
        (53, "domain", "dnsmasq", "2.85", "cpe:/a:thekelleys:dnsmasq:2.85"),
        (80, "http", "Example router httpd", None, None),
        (443, "https", "Example router httpd", None, None),
    ]),
    "garage-camera": ("Example Camera Co", "Linux 3.2 - 4.9", "webcam", [
        (22, "ssh", "OpenSSH", "7.4", "cpe:/a:openbsd:openssh:7.4"),
        (23, "telnet", "BusyBox telnetd", "1.19.4", "cpe:/a:busybox:busybox:1.19.4"),
        (80, "http", "lighttpd", "1.4.35", "cpe:/a:lighttpd:lighttpd:1.4.35"),
        (554, "rtsp", "Example RTSP server", None, None),
    ]),
    "office-printer": ("Example Printer Co", None, "printer", [
        (80, "http", "Example printer web UI", None, None),
        (631, "ipp", "CUPS", "2.2", None),
        (9100, "jetdirect", None, None, None),
    ]),
    "living-room-tv": ("Example TV Inc", "Android 10 - 12", "media device", [
        (8008, "http", None, None, None),
        (8009, "ssl/castv2", None, None, None),
    ]),
    "family-laptop": ("Example Laptop Maker", "Microsoft Windows 10", "general purpose", [
        (445, "microsoft-ds", None, None, None),
    ]),
    "thermostat": ("Example Thermostat Co", None, "specialized", [
        (443, "https", None, None, None),
    ]),
}  # fmt: skip


def service_scan_xml(devices: list[Device], scanned_at: datetime) -> bytes:
    root = Element("nmaprun", scanner="nmap", args="synthetic", version="synthetic",
                   start=str(int(scanned_at.timestamp())))  # fmt: skip
    hosts = [("router", ROUTER_IP, ROUTER_MAC)] + [
        (d.name, d.ip, d.mac) for d in devices if not d.protected and d.joins_at == 0
    ]
    for name, ip, mac in hosts:
        vendor, os_name, os_type, ports = SERVICES.get(name, (None, None, None, []))
        host = SubElement(root, "host")
        SubElement(host, "status", state="up", reason="user-set")
        SubElement(host, "address", addr=ip, addrtype="ipv4")
        mac_attrs = {"addr": mac.upper(), "addrtype": "mac"}
        if vendor:
            mac_attrs["vendor"] = vendor
        SubElement(host, "address", **mac_attrs)
        SubElement(host, "hostnames")
        port_list = SubElement(host, "ports")
        for port, service, product, version, cpe in ports:
            port_el = SubElement(port_list, "port", protocol="tcp", portid=str(port))
            SubElement(port_el, "state", state="open", reason="syn-ack")
            attrs = {"name": service, "method": "probed"}
            if product:
                attrs["product"] = product
            if version:
                attrs["version"] = version
            service_el = SubElement(port_el, "service", **attrs)
            if cpe:
                SubElement(service_el, "cpe").text = cpe
        if os_name:
            os_el = SubElement(host, "os")
            match = SubElement(os_el, "osmatch", name=os_name, accuracy="95")
            SubElement(match, "osclass", type=os_type or "general purpose")
    stats = SubElement(root, "runstats")
    SubElement(stats, "hosts", up=str(len(hosts)), down="0", total=str(len(hosts)))
    return b'<?xml version="1.0" encoding="UTF-8"?>\n' + tostring(root)
