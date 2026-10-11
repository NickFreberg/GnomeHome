"""The protected-asset guard. Every collector and responder calls this module.

From the plan ("Protected assets"): GnomeHome must never probe, capture,
spoof, quarantine, or store data about a protected device, such as the work
laptop or any future work device. Scanning a corporate device can trip its
endpoint security and alert the employer (risk R-12, the only risk we
"avoid" rather than mitigate).

How to use it
-------------
* **Active actions** (anything that sends packets or changes something:
  scans, quarantine, blocking, ARP-spoofed capture) call
  ``guard.require_allowed(action, ip=..., mac=...)``. A protected target
  raises :class:`ProtectedTargetError` and the refusal goes to the audit log.
* **Passive collection** (records about to be stored, like DNS queries or
  flows) calls ``guard.is_protected(...)``, ``guard.touches_protected(...)``,
  or ``guard.filter(...)`` and drops matches *before* storage. There's no
  audit row per dropped record, because that row would itself be stored
  activity data about the device.
* **nmap** gets an exclude file built from :meth:`ProtectedAssets.ipv4_exclude_lines`.

Fail-closed rules
-----------------
* A missing, empty, or invalid list raises :class:`ProtectedListError` at
  load time, and nothing should run without a valid list.
* An identifier that can't be parsed counts as protected.
* YAML is read with every value kept as a string, so an unquoted all-digit
  MAC can't turn into a number, and duplicate keys are errors.

Audit entries name a protected asset by its **label only**, never by MAC or
IP, because the audit log ships to Azure later and nothing about a protected
device may leave the house.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, TypeVar

import yaml

from gnomehome.identifiers import (
    InvalidIdentifier,
    IPNetwork,
    is_multicast,
    normalize_ip,
    normalize_mac,
    normalize_network,
)

FILE_VERSION = "1"

#: RFC 7042 documentation MAC range, used for every fake MAC in the repo.
EXAMPLE_MAC_PREFIXES = ("00:00:5e:00:53:", "02:00:5e:00:53:")
#: RFC 5737 / RFC 3849 documentation networks, used for every fake IP in the repo.
DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)

_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")

T = TypeVar("T")


class ProtectedListError(Exception):
    """The protected-asset list is missing or invalid. Nothing should run."""


class ProtectedTargetError(Exception):
    """An action was refused because its target is protected."""

    def __init__(self, action: str, label: str, matched_on: str) -> None:
        super().__init__(
            f"refused {action!r}: target is protected asset {label!r} (matched on {matched_on})"
        )
        self.action = action
        self.label = label
        self.matched_on = matched_on


class AuditSink(Protocol):
    """Anything that can record an audit entry (see ``gnomehome.audit.AuditLog``)."""

    def append(
        self,
        *,
        actor: str,
        action: str,
        target: str | None,
        result: str,
        details: dict[str, Any] | None = None,
    ) -> Any: ...


@dataclass(frozen=True)
class ProtectedEntry:
    label: str
    reason: str
    macs: frozenset[str]
    networks: tuple[IPNetwork, ...]


@dataclass(frozen=True)
class Match:
    entry: ProtectedEntry
    #: "mac", "ip", "unparseable-mac", or "unparseable-ip"
    matched_on: str

    @property
    def label(self) -> str:
        return self.entry.label


# Stands in for "we couldn't parse it, so treat it as protected".
_UNPARSEABLE = ProtectedEntry(
    label="unparseable-identifier",
    reason="Identifier could not be parsed, so it is treated as protected (fail closed).",
    macs=frozenset(),
    networks=(),
)


# --------------------------------------------------------------------------
# The list
# --------------------------------------------------------------------------


class _StrictLoader(yaml.BaseLoader):
    """YAML loader that keeps every scalar a string and rejects duplicate keys.

    PyYAML's default loaders follow YAML 1.1, where an unquoted MAC made only
    of digit pairs (each 59 or less) is read as a base-60 integer. A duplicate
    key would also silently drop the first value (and with it, a MAC address).
    """

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen: set[Any] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in seen:
                raise yaml.constructor.ConstructorError(
                    None, None, f"duplicate key {key!r}", key_node.start_mark
                )
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


@dataclass(frozen=True)
class ProtectedAssets:
    """The validated contents of ``protected_assets.yaml``."""

    entries: tuple[ProtectedEntry, ...]
    source: str

    @classmethod
    def load(cls, path: Path) -> ProtectedAssets:
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            raise ProtectedListError(
                f"protected-asset list not found: {path}. Nothing may scan or act without it. "
                "Run `just setup`, then swap the example values for your work laptop's "
                "real MAC addresses and reserved IP."
            ) from None
        return cls.parse(text, source=str(path))

    @classmethod
    def parse(cls, text: str, source: str = "<string>") -> ProtectedAssets:
        try:
            doc = yaml.load(text, Loader=_StrictLoader)  # noqa: S506 - BaseLoader builds only str/list/dict
        except yaml.YAMLError as exc:
            raise ProtectedListError(f"{source}: invalid YAML: {exc}") from None
        if not isinstance(doc, dict):
            raise ProtectedListError(f"{source}: expected a mapping with 'version' and 'protected'")
        _reject_unknown(doc, {"version", "protected"}, source)
        if doc.get("version") != FILE_VERSION:
            raise ProtectedListError(f"{source}: version must be {FILE_VERSION}")
        items = doc.get("protected")
        if not isinstance(items, list) or not items:
            raise ProtectedListError(
                f"{source}: 'protected' must be a non-empty list. An empty list is refused so a "
                "forgotten step can't silently disable protection."
            )
        entries = tuple(_parse_entry(item, i, source) for i, item in enumerate(items, start=1))
        labels = [e.label for e in entries]
        duplicates = sorted({label for label in labels if labels.count(label) > 1})
        if duplicates:
            raise ProtectedListError(f"{source}: duplicate label(s) {duplicates}")
        return cls(entries=entries, source=source)

    # ---------------------------------------------------------------- queries

    def match(self, *, ip: str | None = None, mac: str | None = None) -> Match | None:
        """Return the matching entry, or None. Unparseable input always matches."""
        if ip is None and mac is None:
            raise ValueError("match() needs an ip, a mac, or both")
        if mac is not None:
            try:
                normalized = normalize_mac(mac)
            except InvalidIdentifier:
                return Match(_UNPARSEABLE, "unparseable-mac")
            for entry in self.entries:
                if normalized in entry.macs:
                    return Match(entry, "mac")
        if ip is not None:
            try:
                addr = normalize_ip(ip)
            except InvalidIdentifier:
                return Match(_UNPARSEABLE, "unparseable-ip")
            for entry in self.entries:
                for net in entry.networks:
                    if addr.version == net.version and addr in net:
                        return Match(entry, "ip")
        return None

    @property
    def all_macs(self) -> frozenset[str]:
        return frozenset(mac for entry in self.entries for mac in entry.macs)

    @property
    def all_networks(self) -> tuple[IPNetwork, ...]:
        return tuple(net for entry in self.entries for net in entry.networks)

    def uses_example_values(self) -> bool:
        """True if any value comes from the documentation ranges used in the example file."""
        if any(mac.startswith(EXAMPLE_MAC_PREFIXES) for mac in self.all_macs):
            return True
        return any(
            net.version == doc.version and net.overlaps(doc)  # type: ignore[arg-type]
            for net in self.all_networks
            for doc in DOCUMENTATION_NETWORKS
        )

    def ipv4_exclude_lines(self) -> list[str]:
        """Lines for nmap's ``--excludefile``: every protected IPv4 address or CIDR.

        GnomeHome scans IPv4 only (IPv6 is disabled on the router, per the plan),
        so IPv6 entries are enforced by the guard but not written here.
        """
        lines = []
        for net in self.all_networks:
            if net.version != 4:
                continue
            lines.append(str(net.network_address) if net.prefixlen == 32 else str(net))
        return sorted(set(lines), key=_sort_key)

    def tcpdump_filter(self) -> str:
        """A capture filter matching any packet to or from a protected device.

        Used by the zero-packet test (docs/runbooks/zero-packet-test.md).
        """
        parts = []
        for net in self.all_networks:
            if net.prefixlen == net.max_prefixlen:
                parts.append(f"host {net.network_address}")
            else:
                parts.append(f"net {net}")
        parts.extend(f"ether host {mac}" for mac in sorted(self.all_macs))
        return " or ".join(parts)


def _parse_entry(item: Any, index: int, source: str) -> ProtectedEntry:
    where = f"{source}: protected entry #{index}"
    if not isinstance(item, dict):
        raise ProtectedListError(f"{where} must be a mapping with label, reason, macs, ips")
    _reject_unknown(item, {"label", "reason", "macs", "ips"}, where)
    label = item.get("label")
    if not isinstance(label, str) or not _LABEL_RE.match(label):
        raise ProtectedListError(
            f"{where}: label must be 1-64 letters, digits, spaces, dots, dashes, or underscores"
        )
    where = f"{source}: protected entry {label!r}"
    reason = item.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise ProtectedListError(f"{where}: reason is required")

    macs = item.get("macs")
    if not isinstance(macs, list) or not macs:
        raise ProtectedListError(f"{where}: macs must be a non-empty list")
    normalized_macs = set()
    for raw in macs:
        try:
            mac = normalize_mac(raw)
        except InvalidIdentifier as exc:
            raise ProtectedListError(f"{where}: {exc}") from None
        if is_multicast(mac) or mac == "00:00:00:00:00:00":
            raise ProtectedListError(f"{where}: {raw!r} is not a single device's MAC address")
        normalized_macs.add(mac)

    ips = item.get("ips")
    if not isinstance(ips, list) or not ips:
        raise ProtectedListError(
            f"{where}: ips must be a non-empty list. nmap can only exclude by IP, so every "
            "protected device needs its reserved IP (see the plan, Protected assets step 3)."
        )
    networks = []
    for raw in ips:
        try:
            networks.append(normalize_network(raw))
        except InvalidIdentifier as exc:
            raise ProtectedListError(f"{where}: {exc}") from None

    return ProtectedEntry(
        label=label,
        reason=reason.strip(),
        macs=frozenset(normalized_macs),
        networks=tuple(networks),
    )


def _reject_unknown(mapping: dict[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise ProtectedListError(f"{where}: unknown key(s) {unknown}. Allowed: {sorted(allowed)}")


def _sort_key(line: str) -> tuple[int, int]:
    net = ipaddress.ip_network(line, strict=False)
    return (int(net.network_address), net.prefixlen)


# --------------------------------------------------------------------------
# The guard
# --------------------------------------------------------------------------


class Guard:
    """Enforces the protected-asset list for one job or process."""

    def __init__(
        self, assets: ProtectedAssets, *, audit: AuditSink | None = None, actor: str = "system"
    ) -> None:
        self.assets = assets
        self.audit = audit
        self.actor = actor
        #: How many records passive filters have dropped (a count only, never identities).
        self.passive_drops = 0

    def is_protected(self, *, ip: str | None = None, mac: str | None = None) -> bool:
        return self.assets.match(ip=ip, mac=mac) is not None

    def touches_protected(
        self, *, ips: Iterable[str | None] = (), macs: Iterable[str | None] = ()
    ) -> bool:
        """True if any of these identifiers is protected. ``None`` values are skipped."""
        if any(ip is not None and self.is_protected(ip=ip) for ip in ips):
            return True
        return any(mac is not None and self.is_protected(mac=mac) for mac in macs)

    def filter(
        self,
        records: Iterable[T],
        *,
        ips: Callable[[T], Iterable[str | None]] = lambda _: (),
        macs: Callable[[T], Iterable[str | None]] = lambda _: (),
    ) -> Iterator[T]:
        """Yield only records with no protected identifier (passive collectors).

        Example for flows, which match on source *or* destination::

            kept = guard.filter(flows, ips=lambda f: (f.src_ip, f.dst_ip))
        """
        for record in records:
            if self.touches_protected(ips=ips(record), macs=macs(record)):
                self.passive_drops += 1
                continue
            yield record

    def require_allowed(
        self, action: str, *, ip: str | None = None, mac: str | None = None
    ) -> None:
        """Refuse an active action against a protected target (raises, and audits the refusal)."""
        if ip is None and mac is None:
            raise ValueError(f"{action}: require_allowed() needs the target's ip and/or mac")
        match = self.assets.match(ip=ip, mac=mac)
        if match is None:
            return
        self.record_refusal(action, match)
        raise ProtectedTargetError(action, match.label, match.matched_on)

    def record_refusal(self, action: str, match: Match) -> None:
        """Write a refusal to the audit log, by label only."""
        if self.audit is None:
            return
        self.audit.append(
            actor=self.actor,
            action="guard.refused",
            target=f"protected:{match.label}",
            result="refused",
            details={"attempted_action": action, "matched_on": match.matched_on},
        )


def load_guard(
    protected_assets_path: Path, *, audit: AuditSink | None = None, actor: str = "system"
) -> Guard:
    """Load the list and build a guard. Raises :class:`ProtectedListError` on any problem."""
    return Guard(ProtectedAssets.load(protected_assets_path), audit=audit, actor=actor)
