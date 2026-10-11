"""The fake household: devices, their behavior profiles, and shared helpers."""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import asdict, dataclass

LAN = ipaddress.IPv4Network("192.0.2.0/24")
ROUTER_IP = "192.0.2.1"
ROUTER_WAN_IP = "198.51.100.1"  # the router's public side (NAT), fake
UPSTREAM_DNS = "1.1.1.1"  # Pi-hole's upstream, as in the Docker setup
INTERNET_NETS = (ipaddress.IPv4Network("203.0.113.0/24"), ipaddress.IPv4Network("198.51.100.0/24"))


@dataclass(frozen=True)
class Device:
    name: str
    kind: str
    mac: str
    ip: str
    #: Browsing profile key (see dns.PROFILES).
    profile: str
    #: Queries per hour at the busiest time of day (before the daily rhythm).
    peak_rate: float
    protected: bool = False
    #: When the device first appears, as a fraction of the window (new-device scenario).
    joins_at: float = 0.0
    #: True if the device ignores Pi-hole (hardcoded DNS / DNS over HTTPS, risk R-07).
    bypasses_dns: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def _mac(n: int, randomized: bool = False) -> str:
    return f"{'02' if randomized else '00'}:00:5e:00:53:{n:02x}"


def build_household() -> list[Device]:
    """The fixed roster. Deterministic, so labels and tests can refer to devices by name."""
    return [
        Device("parent-phone", "phone", _mac(0x21, True), "192.0.2.21", "apple_phone", 90),
        Device("teen-phone", "phone", _mac(0x22, True), "192.0.2.22", "android_phone", 140),
        Device("kid-tablet", "tablet", _mac(0x23, True), "192.0.2.23", "kid_tablet", 60),
        Device("family-laptop", "laptop", _mac(0x30), "192.0.2.30", "home_laptop", 160),
        Device("living-room-tv", "tv", _mac(0x40), "192.0.2.40", "smart_tv", 50),
        Device("streaming-stick", "tv", _mac(0x41), "192.0.2.41", "smart_tv", 30,
               bypasses_dns=True),
        Device("kitchen-speaker", "speaker", _mac(0x50), "192.0.2.50", "iot_speaker", 0),
        Device("garage-camera", "camera", _mac(0x51), "192.0.2.51", "iot_camera", 0),
        Device("thermostat", "thermostat", _mac(0x52), "192.0.2.52", "iot_thermostat", 0),
        Device("game-console", "console", _mac(0x60), "192.0.2.60", "console", 40),
        Device("office-printer", "printer", _mac(0x70), "192.0.2.70", "iot_printer", 0),
        Device("unknown-device", "unknown", _mac(0x99, True), "192.0.2.99", "android_phone", 50,
               joins_at=0.55),
        # Matches config/protected_assets.example.yaml: must never be stored.
        Device("work-laptop", "laptop", _mac(0x01), "192.0.2.10", "work_laptop", 120,
               protected=True),
    ]  # fmt: skip


def answer_ip(domain: str) -> str:
    """A stable fake 'internet' IP for a domain (hashlib, not hash(): stable across runs)."""
    digest = hashlib.sha256(domain.encode()).digest()
    net = INTERNET_NETS[digest[0] % len(INTERNET_NETS)]
    host = 2 + digest[1] % 250  # skip .0, .1 (router WAN), and broadcast
    return str(net.network_address + host)


def diurnal(hour: float) -> float:
    """Household activity by hour of day, 0..1: quiet overnight, busiest in the evening."""
    curve = [
        0.10, 0.05, 0.03, 0.03, 0.03, 0.05, 0.20, 0.55, 0.60, 0.40, 0.35, 0.40,
        0.45, 0.40, 0.40, 0.50, 0.65, 0.80, 0.90, 1.00, 1.00, 0.90, 0.60, 0.30,
    ]  # fmt: skip
    return curve[int(hour) % 24]
