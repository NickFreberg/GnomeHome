"""Synthetic connection flows, plus the router's connection-table snapshots.

On stock ASUS firmware, GnomeHome will read the router's connection table
over SSH about once a minute (FR-08). That table is Linux conntrack, so the
raw output here imitates ``/proc/net/nf_conntrack``: one line per tracked
connection, with byte counters that grow between snapshots. As in real life,
connections shorter than the snapshot interval may never show up.

Scenarios, labeled in labels.json:

* ``beacon``: the camera's small, regular HTTPS check-ins to the C2 IP
* ``exfil``: the family laptop uploads about 1.5 GB overnight (T1048)
* ``dns_bypass``: the streaming stick skips Pi-hole, using plain DNS to
  8.8.8.8 and DNS over HTTPS to 1.1.1.1 (risk R-07)
* ``protected``: the work laptop's flows, including a long VPN session,
  which ingestion must drop
"""

from __future__ import annotations

import random
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta

from gnomehome.synthetic.dns import BEACON_DOMAIN, DnsQuery
from gnomehome.synthetic.household import ROUTER_WAN_IP, Device, answer_ip
from gnomehome.timeutil import format_ts

EXFIL_DST = "198.51.100.200"
VPN_DST = "203.0.113.250"
BYPASS_DNS = "8.8.8.8"
BYPASS_DOH = "1.1.1.1"
STREAMING_PROFILES = ("smart_tv",)


@dataclass(frozen=True)
class Flow:
    start: datetime
    end: datetime
    device: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    bytes_out: int
    bytes_in: int
    label: str

    @property
    def packets_out(self) -> int:
        return max(1, self.bytes_out // 900)

    @property
    def packets_in(self) -> int:
        return max(1, self.bytes_in // 1200)


def generate_flows(
    rng: random.Random,
    devices: Iterable[Device],
    queries: Iterable[DnsQuery],
    start: datetime,
    hours: int,
) -> tuple[list[Flow], dict]:
    end = start + timedelta(hours=hours)
    span = (end - start).total_seconds()
    roster = {d.name: d for d in devices}
    flows: list[Flow] = []

    # Most successful lookups lead to an HTTPS connection to the answer.
    for q in queries:
        if q.status not in ("forwarded", "cached") or q.qtype != "A":
            continue
        device = roster[q.device]
        if q.domain == BEACON_DOMAIN:
            flows.append(_flow(rng, device, q.ts, 1.5, q.answer, 443, "tcp",
                               rng.randint(600, 900), rng.randint(300, 500), "beacon"))  # fmt: skip
            continue
        if rng.random() > 0.35:
            continue
        label = "protected" if device.protected else "normal"
        if device.profile in STREAMING_PROFILES and rng.random() < 0.3:
            seconds = rng.uniform(600, 5400)  # a show
            out, inn = rng.randint(2_000_000, 8_000_000), int(seconds * rng.uniform(4e5, 8e5))
        else:
            seconds = rng.lognormvariate(2.5, 1.2)
            out, inn = rng.randint(800, 40_000), rng.randint(2_000, 600_000)
        flows.append(_flow(rng, device, q.ts, seconds, q.answer, 443, "tcp", out, inn, label))

    # dns_bypass: the streaming stick never asks Pi-hole.
    stick = roster["streaming-stick"]
    t = start + timedelta(seconds=rng.uniform(0, 600))
    while t < end:
        flows.append(_flow(rng, stick, t, 0.05, BYPASS_DNS, 53, "udp", 70, 140, "dns_bypass"))
        if rng.random() < 0.3:
            flows.append(_flow(rng, stick, t, rng.uniform(30, 300), BYPASS_DOH, 443, "tcp",
                               rng.randint(2_000, 9_000), rng.randint(4_000, 20_000),
                               "dns_bypass"))  # fmt: skip
        if rng.random() < 0.2:
            seconds = rng.uniform(600, 3600)
            flows.append(_flow(rng, stick, t, seconds, answer_ip("cdn.stream.example"), 443,
                               "tcp", rng.randint(1_000_000, 4_000_000),
                               int(seconds * rng.uniform(4e5, 8e5)), "normal"))  # fmt: skip
        t += timedelta(seconds=rng.uniform(60, 600))

    # exfil: about 1.5 GB out over 40 minutes, starting at 15% of the window.
    laptop = roster["family-laptop"]
    exfil_start = start + timedelta(seconds=0.15 * span)
    exfil = _flow(rng, laptop, exfil_start, 2400, EXFIL_DST, 443, "tcp",
                  1_500_000_000 + rng.randint(0, 50_000_000), rng.randint(1_000_000, 3_000_000),
                  "exfil")  # fmt: skip
    flows.append(exfil)

    # protected: the work laptop's VPN session for most of the window.
    work = roster["work-laptop"]
    vpn_start = start + timedelta(seconds=0.05 * span)
    flows.append(_flow(rng, work, vpn_start, 0.8 * span, VPN_DST, 443, "udp",
                       rng.randint(50_000_000, 90_000_000), rng.randint(200_000_000, 400_000_000),
                       "protected"))  # fmt: skip

    flows = [f for f in flows if f.start < end]
    flows.sort(key=lambda f: (f.start, f.src_ip, f.src_port))
    scenarios = {
        "exfil": {
            "device": laptop.name,
            "dst_ip": EXFIL_DST,
            "starts": format_ts(exfil.start),
            "bytes_out": exfil.bytes_out,
            "mitre": "T1048",
        },
        "dns_bypass": {"device": stick.name, "resolvers": [BYPASS_DNS, BYPASS_DOH]},
    }
    return flows, scenarios


def _flow(
    rng: random.Random,
    device: Device,
    at: datetime,
    seconds: float,
    dst_ip: str | None,
    dst_port: int,
    protocol: str,
    bytes_out: int,
    bytes_in: int,
    label: str,
) -> Flow:
    begin = at + timedelta(milliseconds=rng.randint(20, 200))
    return Flow(
        start=begin,
        end=begin + timedelta(seconds=max(seconds, 0.05)),
        device=device.name,
        src_ip=device.ip,
        src_port=rng.randint(49152, 65535),
        dst_ip=dst_ip or answer_ip("unknown.example"),
        dst_port=dst_port,
        protocol=protocol,
        bytes_out=bytes_out,
        bytes_in=bytes_in,
        label=label,
    )


def conntrack_snapshots(
    flows: list[Flow], start: datetime, hours: int, every_seconds: int
) -> Iterator[str]:
    """``# snapshot <ts>`` headers, each followed by the connections open at that moment."""
    end = start + timedelta(hours=hours)
    pending = sorted(flows, key=lambda f: f.start)
    active: list[Flow] = []
    index = 0
    moment = start
    while moment < end:
        while index < len(pending) and pending[index].start <= moment:
            active.append(pending[index])
            index += 1
        active = [f for f in active if f.end > moment]
        yield f"# snapshot {format_ts(moment)}"
        for flow in active:
            yield _conntrack_line(flow, moment)
        moment += timedelta(seconds=every_seconds)


def _conntrack_line(flow: Flow, moment: datetime) -> str:
    total = (flow.end - flow.start).total_seconds()
    done = min(1.0, (moment - flow.start).total_seconds() / total) if total > 0 else 1.0
    out_bytes, in_bytes = int(flow.bytes_out * done), int(flow.bytes_in * done)
    out_pkts, in_pkts = max(1, int(flow.packets_out * done)), max(1, int(flow.packets_in * done))
    original = f"src={flow.src_ip} dst={flow.dst_ip} sport={flow.src_port} dport={flow.dst_port}"
    reply = f"src={flow.dst_ip} dst={ROUTER_WAN_IP} sport={flow.dst_port} dport={flow.src_port}"
    counters_out = f"packets={out_pkts} bytes={out_bytes}"
    counters_in = f"packets={in_pkts} bytes={in_bytes}"
    tail = "[ASSURED] mark=0 zone=0 use=2"
    if flow.protocol == "tcp":
        head = "ipv4     2 tcp      6 431999 ESTABLISHED"
    else:
        head = "ipv4     2 udp      17 179"
    return f"{head} {original} {counters_out} {reply} {counters_in} {tail}"


def flow_record(flow: Flow) -> dict:
    return {
        "start": format_ts(flow.start),
        "end": format_ts(flow.end),
        "device": flow.device,
        "src_ip": flow.src_ip,
        "src_port": flow.src_port,
        "dst_ip": flow.dst_ip,
        "dst_port": flow.dst_port,
        "protocol": flow.protocol,
        "bytes_out": flow.bytes_out,
        "bytes_in": flow.bytes_in,
        "packets_out": flow.packets_out,
        "packets_in": flow.packets_in,
        "label": flow.label,
    }
