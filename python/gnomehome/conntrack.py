"""Parse the router's connection table (``/proc/net/nf_conntrack``).

Stock ASUS firmware is Linux, so its connection tracking table looks like::

    ipv4     2 tcp      6 431999 ESTABLISHED src=192.0.2.21 dst=203.0.113.15 sport=51234 dport=443 \
packets=12 bytes=3456 src=203.0.113.15 dst=198.51.100.1 sport=443 dport=51234 packets=10 \
bytes=9876 [ASSURED] mark=0 zone=0 use=2

The first ``src/dst/...`` group is the original direction (who started the
connection), and the second is the reply direction, after NAT. Older kernels
(``/proc/net/ip_conntrack``) drop the leading ``ipv4 2``. Byte and packet
counters appear only when the router has accounting enabled. Without them,
they read as 0.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_PROTOCOLS = {"tcp", "udp", "icmp", "sctp", "udplite", "gre", "icmpv6"}
_STATES = {
    "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT", "CLOSE_WAIT", "LAST_ACK",
    "TIME_WAIT", "CLOSE", "LISTEN", "NONE", "SYN_SENT2",
}  # fmt: skip
_KV = re.compile(r"^([a-z]+)=(\S+)$")


@dataclass(frozen=True)
class ConnEntry:
    protocol: str
    state: str | None
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    packets_out: int
    bytes_out: int
    reply_src_ip: str | None
    reply_dst_ip: str | None
    packets_in: int
    bytes_in: int

    @property
    def key(self) -> str:
        return f"{self.protocol}|{self.src_ip}|{self.src_port}|{self.dst_ip}|{self.dst_port}"


def parse_line(line: str) -> ConnEntry | None:
    tokens = line.split()
    proto_index = next((i for i, t in enumerate(tokens[:4]) if t in _PROTOCOLS), None)
    if proto_index is None:
        return None
    protocol = tokens[proto_index]
    state = next((t for t in tokens[proto_index + 1 : proto_index + 5] if t in _STATES), None)
    groups: list[dict[str, str]] = [{}, {}]
    group = 0
    for token in tokens[proto_index + 1 :]:
        match = _KV.match(token)
        if not match:
            continue
        key, value = match.groups()
        if key == "src" and "src" in groups[0]:
            group = 1
        if key in ("src", "dst", "sport", "dport", "packets", "bytes"):
            groups[group].setdefault(key, value)
    original, reply = groups
    if "src" not in original or "dst" not in original:
        return None
    return ConnEntry(
        protocol=protocol,
        state=state,
        src_ip=original["src"],
        dst_ip=original["dst"],
        src_port=_int(original.get("sport")),
        dst_port=_int(original.get("dport")),
        packets_out=_int(original.get("packets")) or 0,
        bytes_out=_int(original.get("bytes")) or 0,
        reply_src_ip=reply.get("src"),
        reply_dst_ip=reply.get("dst"),
        packets_in=_int(reply.get("packets")) or 0,
        bytes_in=_int(reply.get("bytes")) or 0,
    )


def parse_table(text: str) -> list[ConnEntry]:
    return [entry for line in text.splitlines() if (entry := parse_line(line)) is not None]


def _int(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None
