"""Synthetic DNS queries, written the way Pi-hole logs them.

Normal traffic: browsing in short bursts that follow the household's daily
rhythm, per-device app domains, ads that Pi-hole blocks, and IoT devices
checking in on fixed schedules. The IoT check-ins look periodic on purpose,
because that's the classic false positive for beaconing detection.

Scenarios, labeled in labels.json:

* ``beacon``: the garage camera checks in with a ``.test`` C2 domain every
  ~5 minutes with small jitter (T1071.004)
* ``dga``: the family laptop bursts dozens of random-looking ``.test``
  names, mostly NXDOMAIN (T1568.002)
* ``known_bad``: the kid's tablet looks up domains from the fake threat
  feed, and Pi-hole blocks them
* ``new_device``: an unknown device appears partway through, starting with a
  phone's usual connectivity checks
* ``protected``: the work laptop's queries, which ingestion must drop
* ``dns_bypass``: the streaming stick sends nothing here at all (see flows)

Log format: dnsmasq's ``log-queries`` lines, which Pi-hole writes to
``pihole.log``. Check them against a real Pi-hole log before building the
Rust tailer on top of this. Synthetic timestamps are UTC.
"""

from __future__ import annotations

import random
import string
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta

from gnomehome.synthetic.household import UPSTREAM_DNS, Device, answer_ip, diurnal
from gnomehome.timeutil import format_ts

COMMON = [
    "www.google.com",
    "www.gstatic.com",
    "fonts.googleapis.com",
    "www.youtube.com",
    "i.ytimg.com",
    "en.wikipedia.org",
    "www.amazon.com",
    "m.media-amazon.com",
    "www.reddit.com",
    "github.com",
    "api.github.com",
    "cdn.jsdelivr.net",
    "www.cloudflare.com",
]
APPLE = [
    "gateway.icloud.com",
    "api.apple-cloudkit.com",
    "gsp-ssl.ls.apple.com",
    "mesu.apple.com",
    "init.itunes.apple.com",
    "time.apple.com",
]
ANDROID = [
    "android.googleapis.com",
    "play.googleapis.com",
    "connectivitycheck.gstatic.com",
    "mtalk.google.com",
    "www.googleapis.com",
]
SOCIAL = [
    "www.instagram.com",
    "scontent.cdninstagram.com",
    "graph.facebook.com",
    "www.tiktok.com",
    "api.twitter.com",
    "discord.com",
]
STREAMING = [
    "www.netflix.com",
    "api-global.netflix.com",
    "occ-0-1-2.1.nflxso.net",
    "ipv4-c001.1.nflxvideo.net",
    "spclient.wg.spotify.com",
    "www.youtube.com",
    "rr3---sn-example.googlevideo.com",
]
WINDOWS = [
    "login.live.com",
    "settings-win.data.microsoft.com",
    "ctldl.windowsupdate.com",
    "officeclient.microsoft.com",
    "www.bing.com",
]
WORK = [
    "login.microsoftonline.com",
    "outlook.office365.com",
    "teams.microsoft.com",
    "vpn.employer.example",
    "sso.employer.example",
]
GAMING = ["game-network.example", "matchmaking.game-network.example", "cdn.game-network.example"]
ADS = ["ad.doubleclick.net", "googleads.g.doubleclick.net", "pagead2.googlesyndication.com",
       "ads.ad-network.example", "tracker.metrics.example"]  # fmt: skip

#: Profile -> domain pools (with weights) for interactive use.
PROFILES: dict[str, list[tuple[list[str], int]]] = {
    "apple_phone": [(COMMON, 4), (APPLE, 3), (SOCIAL, 2), (STREAMING, 1)],
    "android_phone": [(COMMON, 3), (ANDROID, 3), (SOCIAL, 4), (STREAMING, 1)],
    "kid_tablet": [(COMMON, 2), (APPLE, 2), (STREAMING, 3), (GAMING, 1)],
    "home_laptop": [(COMMON, 6), (WINDOWS, 2), (SOCIAL, 1), (STREAMING, 1)],
    "smart_tv": [(STREAMING, 8), (COMMON, 1)],
    "console": [(GAMING, 6), (STREAMING, 2)],
    "work_laptop": [(WORK, 6), (WINDOWS, 3), (COMMON, 1)],
}

#: Profile -> (domain, period in seconds) for devices that check in on a schedule.
PERIODIC: dict[str, list[tuple[str, int]]] = {
    "iot_speaker": [("speaker-cloud.vendor.example", 120), ("time.vendor.example", 3600)],
    "iot_camera": [("events.camera-vendor.example", 60), ("fw.camera-vendor.example", 21600)],
    "iot_thermostat": [("api.thermostat-vendor.example", 900)],
    "iot_printer": [("status.printer-vendor.example", 1800)],
    "smart_tv": [("tv-telemetry.vendor.example", 600)],
}

#: What a phone looks up in its first seconds on a network.
JOIN_BURST = ["connectivitycheck.gstatic.com", "android.googleapis.com", "mtalk.google.com"]

BEACON_DOMAIN = "status.cloudsync-update.test"
BEACON_PERIOD = 300
BEACON_JITTER = 0.05
THREAT_FEED = [
    "malware-drop.test", "phish-login-verify.test", "coinminer-pool.test",
    "loader-cdn.test", "exfil-paste.test",
]  # fmt: skip
CACHE_SECONDS = 300
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_DNSMASQ_PID = 402


@dataclass(frozen=True)
class DnsQuery:
    ts: datetime
    device: str
    client_ip: str
    client_mac: str
    domain: str
    qtype: str
    #: forwarded, cached, blocked, or nxdomain
    status: str
    answer: str | None
    label: str


@dataclass(frozen=True)
class _Raw:
    ts: datetime
    device: Device
    domain: str
    qtype: str
    label: str
    forced: str | None = None  # "blocked" or "nxdomain"


def generate_queries(
    rng: random.Random, devices: Iterable[Device], start: datetime, hours: int
) -> tuple[list[DnsQuery], dict]:
    """All DNS queries for the window, sorted by time, plus scenario details for labels.json."""
    end = start + timedelta(hours=hours)
    span = (end - start).total_seconds()
    roster = {d.name: d for d in devices}
    raw: list[_Raw] = []

    for device in roster.values():
        if device.bypasses_dns:
            continue
        joined = start + timedelta(seconds=device.joins_at * span)
        label = "protected" if device.protected else "normal"
        if device.joins_at > 0:
            # Phones check connectivity the moment they join Wi-Fi.
            for i, domain in enumerate(JOIN_BURST):
                raw.append(_Raw(joined + timedelta(seconds=i), device, domain, "A", "new_device"))
        if device.peak_rate > 0:
            raw += _browsing(rng, device, joined, end, label)
        for domain, period in PERIODIC.get(device.profile, []):
            periodic_label = label if device.protected else "benign_periodic"
            raw += _periodic(rng, device, domain, period, 0.02, joined, end, periodic_label)

    # beacon: from 10% of the window to the end
    camera = roster["garage-camera"]
    beacon_start = start + timedelta(seconds=0.10 * span)
    raw += _periodic(
        rng, camera, BEACON_DOMAIN, BEACON_PERIOD, BEACON_JITTER, beacon_start, end, "beacon"
    )

    # dga: a two-minute burst at 40% of the window
    laptop = roster["family-laptop"]
    dga_start = start + timedelta(seconds=0.40 * span)
    dga_domains = [_dga_name(rng) for _ in range(40)]
    resolving = set(rng.sample(dga_domains, 2))
    for name in dga_domains:
        when = dga_start + timedelta(seconds=rng.uniform(0, 120))
        raw.append(_Raw(when, laptop, name, "A", "dga", None if name in resolving else "nxdomain"))

    # known_bad: the tablet looks up three feed domains at 25% and 70% of the window
    tablet = roster["kid-tablet"]
    bad_lookups = []
    for fraction, domain in (
        (0.25, THREAT_FEED[0]),
        (0.25, THREAT_FEED[1]),
        (0.70, THREAT_FEED[2]),
    ):
        when = start + timedelta(seconds=fraction * span + rng.uniform(0, 60))
        raw.append(_Raw(when, tablet, domain, "A", "known_bad", "blocked"))
        bad_lookups.append({"ts": format_ts(when), "domain": domain})

    raw.sort(key=lambda r: (r.ts, r.device.name, r.domain))
    queries = list(_resolve(raw))
    scenarios = {
        "beacon": {
            "device": camera.name,
            "domain": BEACON_DOMAIN,
            "period_seconds": BEACON_PERIOD,
            "jitter": BEACON_JITTER,
            "c2_ip": answer_ip(BEACON_DOMAIN),
            "starts": format_ts(beacon_start),
            "mitre": "T1071.004",
        },
        "dga": {
            "device": laptop.name,
            "starts": format_ts(dga_start),
            "domains": dga_domains,
            "resolving": sorted(resolving),
            "mitre": "T1568.002",
        },
        "known_bad": {"device": tablet.name, "lookups": bad_lookups},
    }
    return queries, scenarios


def _browsing(
    rng: random.Random, device: Device, joined: datetime, end: datetime, label: str
) -> list[_Raw]:
    """Bursts of related queries, thinned by the daily rhythm."""
    out = []
    pools = PROFILES[device.profile]
    rate = device.peak_rate / 3600 / 2.5  # bursts per second (about 2.5 queries per burst)
    t = joined
    while True:
        t += timedelta(seconds=rng.expovariate(rate))
        if t >= end:
            return out
        if rng.random() >= diurnal(t.hour + t.minute / 60):
            continue
        pool = rng.choices([p for p, _ in pools], weights=[w for _, w in pools])[0]
        for i in range(rng.randint(1, 4)):
            when = t + timedelta(seconds=rng.uniform(0, 3) * i)
            out.append(_Raw(when, device, rng.choice(pool), _qtype(rng, device), label))
        if rng.random() < 0.15:  # a page with an ad: Pi-hole blocks it
            out.append(_Raw(t, device, rng.choice(ADS), "A", label, "blocked"))


def _periodic(
    rng: random.Random,
    device: Device,
    domain: str,
    period: int,
    jitter: float,
    begin: datetime,
    end: datetime,
    label: str,
) -> list[_Raw]:
    out = []
    t = begin + timedelta(seconds=rng.uniform(0, period))
    while t < end:
        out.append(_Raw(t, device, domain, "A", label))
        t += timedelta(seconds=period * rng.uniform(1 - jitter, 1 + jitter))
    return out


def _qtype(rng: random.Random, device: Device) -> str:
    roll = rng.random()
    if device.profile in ("apple_phone", "kid_tablet") and roll < 0.15:
        return "HTTPS"
    return "AAAA" if roll < 0.40 else "A"


def _dga_name(rng: random.Random) -> str:
    length = rng.randint(12, 20)
    return (
        "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(length)) + ".test"
    )


def _resolve(raw: list[_Raw]) -> Iterator[DnsQuery]:
    """Turn raw lookups into Pi-hole outcomes, including its 5-minute cache."""
    cached_until: dict[tuple[str, str], datetime] = {}
    for r in raw:
        key = (r.domain, r.qtype)
        if r.forced == "blocked":
            status, answer = "blocked", "::" if r.qtype == "AAAA" else "0.0.0.0"  # noqa: S104
        elif r.forced == "nxdomain":
            status, answer = "nxdomain", None
        else:
            status = "cached" if cached_until.get(key, r.ts) > r.ts else "forwarded"
            if status == "forwarded":
                cached_until[key] = r.ts + timedelta(seconds=CACHE_SECONDS)
            answer = _answer(r.domain, r.qtype)
        yield DnsQuery(
            ts=r.ts,
            device=r.device.name,
            client_ip=r.device.ip,
            client_mac=r.device.mac,
            domain=r.domain,
            qtype=r.qtype,
            status=status,
            answer=answer,
            label=r.label,
        )


def _answer(domain: str, qtype: str) -> str:
    ip = answer_ip(domain)
    if qtype == "AAAA":
        return "2001:db8::" + format(int(ip.split(".")[-1]) * 7 + 1, "x")
    if qtype == "HTTPS":
        return "<HTTPS>"
    return ip


def pihole_log_lines(queries: Iterable[DnsQuery]) -> Iterator[str]:
    """dnsmasq-style lines, three or so per query, as Pi-hole writes them."""
    for q in queries:
        stamp = f"{_MONTHS[q.ts.month - 1]} {q.ts.day:2d} {q.ts:%H:%M:%S}"
        prefix = f"{stamp} dnsmasq[{_DNSMASQ_PID}]: "
        yield f"{prefix}query[{q.qtype}] {q.domain} from {q.client_ip}"
        if q.status == "blocked":
            yield f"{prefix}gravity blocked {q.domain} is {q.answer}"
        elif q.status == "cached":
            yield f"{prefix}cached {q.domain} is {q.answer}"
        else:
            yield f"{prefix}forwarded {q.domain} to {UPSTREAM_DNS}"
            yield f"{prefix}reply {q.domain} is {q.answer if q.answer else 'NXDOMAIN'}"


def query_record(q: DnsQuery) -> dict:
    return {
        "ts": format_ts(q.ts),
        "device": q.device,
        "client_ip": q.client_ip,
        "client_mac": q.client_mac,
        "domain": q.domain,
        "qtype": q.qtype,
        "status": q.status,
        "answer": q.answer,
        "label": q.label,
    }
