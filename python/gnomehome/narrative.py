"""Plain-English incident text (FR-11): one template per detection.

Every incident answers the same questions, in the same order:

* **When** it happened (``occurred_at``) and **which device** (``device``)
* **What happened**: the facts only
* **Why it matters**: the risk, in plain words
* **What to do**: a concrete next step

Rules, from the plan's design system and safety rules:

* Strictly factual and calm. Gnome flavor belongs in empty states, never here.
* Device-supplied text (hostnames, DNS names) is quoted and labeled, and is
  never presented as fact. It's untrusted (R-04), so it's cleaned and shortened
  before it's quoted.
* A protected device appears by its label only, never by MAC or IP.
* Severity is always a word. The UI adds the icon.

Templates are pure functions of their inputs, so they're easy to test and the
same finding always reads the same way.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from gnomehome.identifiers import is_locally_administered

MITRE_URL = "https://attack.mitre.org/techniques/{}/"
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_SPACE = re.compile(r"[ \t\r\n]+")


@dataclass(frozen=True)
class Narrative:
    detection: str
    severity: str
    title: str
    occurred_at: str
    device: str
    what_happened: str
    why_it_matters: str
    next_steps: str
    mitre_technique: str | None = None
    confidence: float | None = None

    @property
    def summary(self) -> str:
        return (
            f"What happened: {self.what_happened} Why it matters: {self.why_it_matters} "
            f"What to do: {self.next_steps}"
        )


def quote_untrusted(text: str | None, max_len: int = 64) -> str | None:
    """A device-supplied string, made safe to quote inside incident text."""
    if text is None:
        return None
    cleaned = _CONTROL.sub("?", _SPACE.sub(" ", text).strip()).replace('"', "'")
    if not cleaned:
        return None
    return cleaned if len(cleaned) <= max_len else cleaned[: max_len - 1] + "…"


def describe_device(ip: str | None, vendor: str | None = None, hostname: str | None = None) -> str:
    """``the device at 192.0.2.30 (made by Example Co, calls itself "den-pc")``."""
    text = f"the device at {ip}" if ip else "a device with no known address"
    extras = []
    vendor = quote_untrusted(vendor)
    if vendor:
        extras.append(f"made by {vendor}")
    name = quote_untrusted(hostname)
    if name:
        extras.append(f'calls itself "{name}", a name the device chose')
    return f"{text} ({', '.join(extras)})" if extras else text


def protected_device(label: str) -> str:
    return f"protected device '{label}'"


def _cap(text: str) -> str:
    return text[:1].upper() + text[1:]


def times(count: int, first_ts: str, last_ts: str) -> str:
    """``once, at T`` or ``5 times between T1 and T2``."""
    if count == 1 or first_ts == last_ts:
        return f"once, at {first_ts}" if count == 1 else f"{count} times at {first_ts}"
    return f"{count} times between {first_ts} and {last_ts}"


def every(seconds: float) -> str:
    if seconds < 120:
        return f"{seconds:.0f} seconds"
    if seconds < 7200:
        return f"{seconds / 60:.0f} minutes"
    return f"{seconds / 3600:.1f} hours"


# --------------------------------------------------------------------------
# Inventory and guard
# --------------------------------------------------------------------------


def new_device(
    *,
    ip: str | None,
    mac: str,
    vendor: str | None,
    hostname: str | None,
    seen_at: str,
    source: str,
) -> Narrative:
    maker = quote_untrusted(vendor) or "unknown"
    what = (
        f"A device GnomeHome has not seen before joined the network at {seen_at} (seen by "
        f"{source}). IP {ip or 'unknown'}, MAC {mac}, vendor {maker}."
    )
    name = quote_untrusted(hostname)
    if name:
        what += f' It calls itself "{name}" (a device-supplied name, which can be false).'
    if is_locally_administered(mac):
        what += (
            " Its MAC is randomized (a phone's private Wi-Fi address), so it may be a known device "
            "using a new address."
        )
    return Narrative(
        detection="inventory.new_device",
        severity="low",
        title=f"New device on the network ({quote_untrusted(vendor) or 'unknown vendor'})",
        occurred_at=seen_at,
        device=describe_device(ip, vendor, hostname),
        what_happened=what,
        why_it_matters=(
            "Every device on the network should be one you recognize. An unknown device can be a "
            "guest, a new gadget, or someone using your Wi-Fi without permission."
        ),
        next_steps=(
            "Find it in the ASUS app's device list. If you don't recognize it, change the Wi-Fi "
            "password or block it in the router. If you do, resolve this incident."
        ),
        mitre_technique="T1200",
        confidence=0.6 if is_locally_administered(mac) else 0.9,
    )


_DRIFT = {
    "protected_mac_at_unlisted_ip": (
        "Protected device {label!r} was given an IP address that is not on its protected list.",
        "Scans exclude protected devices by IP address. If it keeps that address, a scan could "
        "reach it, which is the one thing GnomeHome must never do (risk R-12).",
        "Fix the DHCP reservation for {label!r} in the router, then rerun the zero-packet test "
        "(docs/runbooks/zero-packet-test.md) before the next scan.",
    ),
    "unknown_mac_at_protected_ip": (
        "The reserved IP address of protected device {label!r} was given to a MAC address that is "
        "not on its list. Nothing about that device was stored.",
        "Either the laptop's MAC changed (for example, a randomized Wi-Fi address), so the list "
        "no longer recognizes it, or another device took its address.",
        "If it's the laptop, add the new MAC to config/protected_assets.yaml. If not, find out "
        "which device took the address.",
    ),
}


def protected_drift(*, label: str, kind: str, source: str, seen_at: str) -> Narrative:
    what, why, todo = (part.format(label=label) for part in _DRIFT[kind])
    return Narrative(
        detection="guard.protected_drift",
        severity="medium",
        title=f"Protected device {label!r} is not where its list entry says",
        occurred_at=seen_at,
        device=protected_device(label),
        what_happened=f"{what} (Seen by {source}.)",
        why_it_matters=why,
        next_steps=todo,
        confidence=1.0,
    )


# --------------------------------------------------------------------------
# DNS and connection analytics
# --------------------------------------------------------------------------


def beaconing(
    *, device: str, domain: str, count: int, first_ts: str, last_ts: str, details: dict[str, Any]
) -> Narrative:
    name = quote_untrusted(domain, 255)
    return Narrative(
        detection="dns.beaconing",
        severity="medium",
        title=f'Regular check-ins to "{name}"',
        occurred_at=first_ts,
        device=device,
        what_happened=(
            f'{_cap(device)} looked up "{name}" {count} times between {first_ts} '
            f"and {last_ts}, about every {every(details['period_seconds'])}, varying by only "
            f"{details['jitter']:.0%}. It first contacted this domain at {details['first_seen']}, "
            "after the baseline period."
        ),
        why_it_matters=(
            "Malware often checks in with its command server on a steady timer. Some legitimate "
            "apps do too, so the domain is what decides it."
        ),
        next_steps=(
            "Check whether you recognize the domain and the app that would use it. If not, block "
            "the domain in Pi-hole and look at the device for unwanted software."
        ),
        mitre_technique="T1071.004",
        confidence=round(max(0.5, 1 - details["jitter"] / 0.15 * 0.5), 2),
    )


def dga(*, device: str, first_ts: str, last_ts: str, details: dict[str, Any]) -> Narrative:
    examples = ", ".join(f'"{quote_untrusted(x, 255)}"' for x in details["examples"][:3])
    return Narrative(
        detection="dns.dga",
        severity="high",
        title="Burst of machine-generated domain lookups",
        occurred_at=first_ts,
        device=device,
        what_happened=(
            f"Between {first_ts} and {last_ts}, {device} looked up {details['distinct_names']} "
            f"random-looking domains (for example {examples}), and "
            f"{details['nxdomain_share']:.0%} of them don't exist."
        ),
        why_it_matters=(
            "Malware that generates domain names tries many quickly to find its command server. "
            "People and normal apps rarely look up names like these."
        ),
        next_steps=(
            "Check the device for unwanted software: run a malware scan, review recently "
            "installed apps, and consider quarantining it until it's clean."
        ),
        mitre_technique="T1568.002",
        confidence=round(min(1.0, details["mean_score"] + 0.2), 2),
    )


def threat_intel(
    *, device: str, domain: str, count: int, first_ts: str, last_ts: str, details: dict[str, Any]
) -> Narrative:
    resolved, blocked = details["resolved"], details["blocked"]
    name = quote_untrusted(domain, 255)
    indicator = quote_untrusted(details["indicator"], 255)
    if resolved == 0:
        outcome = (
            "Pi-hole blocked it." if blocked == 1 else f"Pi-hole blocked all {blocked} lookups."
        )
    else:
        answered = "it was answered" if resolved == 1 else f"{resolved} lookups were answered"
        outcome = (
            f"Pi-hole doesn't block this domain, and {answered}, so the device could reach it."
        )
    return Narrative(
        detection="dns.threat_intel",
        severity="medium" if resolved == 0 else "high",
        title=f'Lookup of a known-bad domain: "{indicator}"',
        occurred_at=first_ts,
        device=device,
        what_happened=(
            f'{_cap(device)} looked up "{name}", which is on the '
            f"{', '.join(details['sources'])} threat list, {times(count, first_ts, last_ts)}. "
            f"{outcome}"
        ),
        why_it_matters=(
            "These lists track domains used for malware, phishing, and scams. A lookup usually "
            "means a link was clicked, an ad loaded, or software on the device reached out."
        ),
        next_steps=(
            "Block the domain in Pi-hole if it isn't already, and ask whoever uses the device what "
            "they were doing at that time."
            if resolved
            else "Nothing reached the domain. Ask whoever uses the device what they were doing at "
            "that time, and resolve this incident if it's explained."
        ),
        confidence=0.9,
    )


def dns_bypass(
    *, device: str, count: int, first_ts: str, last_ts: str, details: dict[str, Any]
) -> Narrative:
    methods = " and ".join(sorted(details["methods"]))
    resolvers = ", ".join(details["resolvers"])
    return Narrative(
        detection="dns.bypass",
        severity="low",
        title="Device skips Pi-hole for DNS",
        occurred_at=first_ts,
        device=device,
        what_happened=(
            f"{_cap(device)} sent DNS ({methods}) straight to {resolvers} instead of Pi-hole, "
            f"{times(count, first_ts, last_ts)}."
        ),
        why_it_matters=(
            "GnomeHome can't see, filter, or check this device's lookups against threat lists "
            "(risk R-07). Many streaming devices do this on purpose."
        ),
        next_steps=(
            "If you want it filtered, block outbound DNS (ports 53 and 853) for this device in the "
            "router. Otherwise resolve this incident."
        ),
        confidence=0.8,
    )


# --------------------------------------------------------------------------
# Risk
# --------------------------------------------------------------------------


def risk_increase(
    *,
    device: str,
    old_level: str | None,
    new_level: str,
    score: float,
    reasons: list[str],
    scored_at: str,
) -> Narrative:
    before = f"from {old_level} " if old_level else ""
    top = "; ".join(reasons[:3]) or "see `just risks` for the breakdown"
    return Narrative(
        detection="risk.increase",
        severity="high" if new_level == "critical" else "medium",
        title=f"Risk rose to {new_level}",
        occurred_at=scored_at,
        device=device,
        what_happened=(
            f"The daily risk score for {device} rose {before}to {new_level} ({score:.0f} out of "
            f"100). The biggest reasons: {top}."
        ),
        why_it_matters=(
            "High and critical scores mean known, exploitable weaknesses on a device that's "
            "reachable on your network."
        ),
        next_steps=(
            "Update the device's firmware or software, or turn off the services it doesn't need. "
            "The score drops on the next daily run once the fix is in."
        ),
        confidence=1.0,
    )


# --------------------------------------------------------------------------
# Weekly self-assessment
# --------------------------------------------------------------------------


def weekly_assessment(
    *,
    week_start: str,
    week_end: str,
    new_devices: list[str],
    new_ports: list[str],
    new_cves: list[str],
    kev_cves: int,
    high_risk_devices: int,
) -> Narrative:
    found = len(new_devices) + len(new_ports) + len(new_cves)
    if kev_cves or high_risk_devices:
        severity = "high" if kev_cves else "medium"
    else:
        severity = "medium" if new_ports or new_cves else "low"

    def listed(items: list[str], what: str) -> str:
        if not items:
            return f"no {what}"
        shown = "; ".join(items[:5])
        more = f"; and {len(items) - 5} more" if len(items) > 5 else ""
        return f"{len(items)} {what} ({shown}{more})"

    what = (
        f"For the week {week_start} to {week_end}: {listed(new_devices, 'new device(s)')}, "
        f"{listed(new_ports, 'newly exposed port(s)')}, and {listed(new_cves, 'new CVE(s)')}"
        f"{f', {kev_cves} of them known to be exploited' if kev_cves else ''}. "
        f"{high_risk_devices} device(s) are at high or critical risk."
    )
    return Narrative(
        detection="assessment.weekly",
        severity=severity,
        title="Weekly self-assessment" + ("" if found else ": nothing new"),
        occurred_at=f"{week_end}T23:59:59.999Z",
        device="the whole network",
        what_happened=what,
        why_it_matters=(
            "New devices, newly opened ports, and new vulnerabilities are how a home network's "
            "attack surface grows without anyone noticing."
        ),
        next_steps=(
            "Check that you recognize each new device, close ports that don't need to be open, "
            "and update anything with a known-exploited CVE first. `just risks` shows the details."
            if found
            else "Nothing to do this week."
        ),
        confidence=1.0,
    )
