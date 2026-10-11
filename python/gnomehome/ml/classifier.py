"""Device-type classifier (FR-12): what kind of thing is this device?

Each clue (an open port, the manufacturer, nmap's OS guess, the domains it
looks up, a randomized MAC, its self-reported name) adds points to one or more
device types. The scores become probabilities through a softmax, and the
answer comes with the clues that decided it, so the owner can see *why* a
device was called a camera.

It's a transparent, hand-weighted model rather than a trained one, because a
single household never has enough labeled devices to train on. Owner
corrections can be added as extra clues later. A device with too little
evidence is reported as ``unknown`` rather than guessed.

Device-supplied names (hostnames) are untrusted, so they count for little: a
device can call itself anything (R-04).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field

from gnomehome.analytics.domains import normalize_domain

TYPES = (
    "phone", "tablet", "computer", "tv", "speaker", "camera", "thermostat", "console", "printer",
    "network",
)  # fmt: skip

#: Below this many points for the best type, the answer is "unknown".
MIN_EVIDENCE = 2.5

# tcp port -> ({type: points}, why)
PORTS: dict[int, tuple[dict[str, float], str]] = {
    554: ({"camera": 3.0}, "streams video (RTSP, port 554)"),
    8554: ({"camera": 2.5}, "streams video (RTSP, port 8554)"),
    631: ({"printer": 4.0}, "accepts print jobs (IPP, port 631)"),
    9100: ({"printer": 4.0}, "accepts print jobs (port 9100)"),
    515: ({"printer": 3.0}, "accepts print jobs (LPD, port 515)"),
    8008: ({"tv": 2.5, "speaker": 1.5}, "accepts casting (port 8008)"),
    8009: ({"tv": 2.5, "speaker": 1.5}, "accepts casting (port 8009)"),
    7000: ({"tv": 2.0, "speaker": 1.0, "computer": 0.5}, "accepts AirPlay (port 7000)"),
    445: ({"computer": 3.0}, "shares files (SMB, port 445)"),
    139: ({"computer": 2.0}, "shares files (NetBIOS, port 139)"),
    3389: ({"computer": 3.0}, "accepts remote desktop (port 3389)"),
    5900: ({"computer": 2.0}, "accepts screen sharing (VNC, port 5900)"),
    62078: ({"phone": 3.0, "tablet": 2.5}, "has Apple's device-sync port (62078)"),
    53: ({"network": 3.0}, "answers DNS (port 53)"),
    1900: ({"tv": 1.0, "network": 1.0}, "announces itself over UPnP (port 1900)"),
    23: (
        {"camera": 1.0, "network": 1.0},
        "runs Telnet (port 23), common on cheap embedded devices",
    ),
}

# nmap OS type (the asset's device_type) -> ({type: points}, why)
OS_TYPES: dict[str, dict[str, float]] = {
    "webcam": {"camera": 4.0},
    "printer": {"printer": 4.0},
    "media device": {"tv": 3.0, "speaker": 1.0},
    "general purpose": {"computer": 2.0},
    "phone": {"phone": 4.0},
    "game console": {"console": 4.0},
    "WAP": {"network": 4.0},
    "router": {"network": 4.0},
    "broadband router": {"network": 4.0},
    "switch": {"network": 4.0},
    "specialized": {"thermostat": 1.0, "camera": 0.5, "speaker": 0.5},
}

# Substrings of the OS guess -> points
OS_NAMES: list[tuple[str, dict[str, float]]] = [
    ("windows", {"computer": 2.5}),
    ("mac os", {"computer": 2.0}),
    ("ios", {"phone": 2.0, "tablet": 1.5}),
    ("android", {"phone": 1.5, "tv": 1.0, "tablet": 1.0}),
    ("playstation", {"console": 4.0}),
]

# Words in the manufacturer name -> points
VENDOR_WORDS: list[tuple[str, dict[str, float]]] = [
    ("camera", {"camera": 3.0}), ("ring", {"camera": 3.0}), ("hikvision", {"camera": 3.0}),
    ("wyze", {"camera": 3.0}), ("arlo", {"camera": 3.0}),
    ("printer", {"printer": 3.0}), ("brother", {"printer": 3.0}), ("epson", {"printer": 3.0}),
    ("canon", {"printer": 2.0}), ("hewlett", {"printer": 2.0, "computer": 1.0}),
    ("tv", {"tv": 2.5}), ("roku", {"tv": 3.0}), ("vizio", {"tv": 3.0}), ("tcl", {"tv": 2.0}),
    ("thermostat", {"thermostat": 4.0}), ("ecobee", {"thermostat": 4.0}),
    ("nest", {"thermostat": 2.0, "camera": 1.0, "speaker": 1.0}),
    ("sonos", {"speaker": 4.0}), ("bose", {"speaker": 3.0}), ("speaker", {"speaker": 3.0}),
    ("router", {"network": 3.0}), ("asustek", {"network": 1.5, "computer": 1.0}),
    ("netgear", {"network": 3.0}), ("ubiquiti", {"network": 3.0}), ("tp-link", {"network": 2.0}),
    ("laptop", {"computer": 2.0}), ("dell", {"computer": 2.5}), ("lenovo", {"computer": 2.5}),
    ("intel", {"computer": 2.0}), ("apple", {"phone": 1.0, "tablet": 1.0, "computer": 1.0}),
    ("nintendo", {"console": 4.0}), ("sony interactive", {"console": 4.0}),
    ("microsoft", {"console": 1.0, "computer": 1.0}),
    ("espressif", {"thermostat": 1.0, "speaker": 0.5, "camera": 0.5}),
]  # fmt: skip

# Words in a looked-up domain name -> (points, family name). Each family counts once.
DOMAIN_FAMILIES: list[tuple[tuple[str, ...], dict[str, float], str]] = [
    (("icloud", "apple"), {"phone": 1.0, "tablet": 1.0, "computer": 0.5}, "Apple services"),
    (("android", "play.googleapis", "connectivitycheck.gstatic", "mtalk.google"),
     {"phone": 1.5, "tablet": 0.5, "tv": 0.5}, "Android services"),
    (("windowsupdate", "microsoft", "live.com", "bing"), {"computer": 2.5}, "Windows services"),
    (("netflix", "nflx", "googlevideo", "youtube", "spotify"), {"tv": 1.5, "tablet": 0.5},
     "streaming"),
    (("instagram", "tiktok", "facebook", "twitter", "discord"), {"phone": 1.5, "tablet": 0.5},
     "social apps"),
    (("game", "xboxlive", "playstation", "nintendo", "steam"), {"console": 3.0}, "gaming"),
    (("camera",), {"camera": 3.0}, "a camera maker's cloud"),
    (("printer",), {"printer": 3.0}, "a printer maker's cloud"),
    (("thermostat", "ecobee", "nest"), {"thermostat": 3.0}, "a thermostat maker's cloud"),
    (("speaker", "sonos"), {"speaker": 3.0}, "a speaker maker's cloud"),
]  # fmt: skip

# Words in the device's own name (untrusted, so low weight)
NAME_WORDS: list[tuple[tuple[str, ...], str]] = [
    (("iphone", "phone", "pixel", "galaxy"), "phone"),
    (("ipad", "tablet", "kindle"), "tablet"),
    (("laptop", "macbook", "desktop", "pc"), "computer"),
    (("tv", "roku", "chromecast", "stick", "firetv"), "tv"),
    (("speaker", "echo", "sonos", "homepod"), "speaker"),
    (("camera", "cam", "doorbell"), "camera"),
    (("thermostat", "ecobee"), "thermostat"),
    (("xbox", "playstation", "ps5", "switch", "console"), "console"),
    (("printer", "laserjet", "officejet"), "printer"),
]
NAME_POINTS = 1.5


@dataclass
class DeviceProfile:
    device: str
    vendor: str | None = None
    os_name: str | None = None
    os_type: str | None = None
    open_ports: set[int] = field(default_factory=set)
    domains: Counter[str] = field(default_factory=Counter)
    hostname: str | None = None
    mac_randomized: bool = False


@dataclass(frozen=True)
class Classification:
    device: str
    label: str
    confidence: float
    evidence: tuple[str, ...]
    scores: dict[str, float]


def classify(profile: DeviceProfile) -> Classification:
    scores = dict.fromkeys(TYPES, 0.0)
    clues: list[tuple[float, str]] = []

    def add(points: dict[str, float], why: str) -> None:
        for kind, value in points.items():
            scores[kind] += value
        clues.append((max(points.values()), why))

    for port in sorted(profile.open_ports):
        if port in PORTS:
            add(*PORTS[port])
    if profile.os_type in OS_TYPES:
        add(OS_TYPES[profile.os_type], f"nmap says it's a {profile.os_type}")
    os_name = (profile.os_name or "").lower()
    for word, points in OS_NAMES:
        if re.search(rf"\b{re.escape(word)}\b", os_name):
            add(points, f"runs {profile.os_name}")
            break
    vendor = (profile.vendor or "").lower()
    for word, points in VENDOR_WORDS:
        if re.search(rf"\b{re.escape(word)}\b", vendor):
            add(points, f"made by {profile.vendor}")
            break
    total = sum(profile.domains.values())
    for words, points, family in DOMAIN_FAMILIES:
        hits = sum(n for d, n in profile.domains.items() if any(w in d for w in words))
        if hits and hits >= max(3, 0.02 * total):
            add(points, f"looks up {family} ({hits} lookups)")
    if profile.mac_randomized:
        add({"phone": 1.5, "tablet": 1.0, "computer": 0.5}, "uses a randomized (private) MAC")
    name = (profile.hostname or "").lower()
    for words, kind in NAME_WORDS:
        if any(re.search(rf"(^|[^a-z]){re.escape(w)}([^a-z]|$)", name) for w in words):
            add({kind: NAME_POINTS}, f'calls itself "{profile.hostname}" (unverified)')
            break

    best = max(scores, key=lambda k: scores[k])
    if scores[best] < MIN_EVIDENCE:
        return Classification(profile.device, "unknown", 0.0, _top(clues), scores)
    peak = scores[best]
    weights = {k: math.exp(v - peak) for k, v in scores.items()}
    confidence = weights[best] / sum(weights.values())
    return Classification(profile.device, best, round(confidence, 2), _top(clues), scores)


def _top(clues: list[tuple[float, str]]) -> tuple[str, ...]:
    return tuple(why for _, why in sorted(clues, key=lambda c: -c[0])[:4])


def profiles_from_rows(
    assets: Iterable[dict],
    services: Iterable[dict],
    dns: Iterable[dict],
) -> list[DeviceProfile]:
    """Build profiles from asset, service, and DNS rows (by asset ID, or by IP for DNS)."""
    by_id: dict[int, DeviceProfile] = {}
    by_ip: dict[str, DeviceProfile] = {}
    for a in assets:
        profile = DeviceProfile(
            device=a.get("last_ip") or a["mac"],
            vendor=a.get("vendor"),
            os_name=a.get("os_guess"),
            os_type=a.get("device_type"),
            hostname=a.get("hostname"),
            mac_randomized=bool(a.get("mac_randomized")),
        )
        by_id[a["id"]] = profile
        if a.get("last_ip"):
            by_ip[a["last_ip"]] = profile
    for s in services:
        profile = by_id.get(s["asset_id"])
        is_open_tcp = s.get("protocol", "tcp") == "tcp" and s.get("state", "open") == "open"
        if profile is not None and is_open_tcp:
            profile.open_ports.add(int(s["port"]))
    for row in dns:
        profile = by_ip.get(row["src_ip"])
        if profile is not None:
            profile.domains[normalize_domain(row["domain"])] += 1
    return list(by_id.values())
