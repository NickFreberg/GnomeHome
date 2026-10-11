"""CPE names and version matching for vulnerability lookups (FR-04).

nmap reports software as CPE 2.2 URIs (``cpe:/a:thekelleys:dnsmasq:2.85``).
NVD's API wants CPE 2.3 formatted strings
(``cpe:2.3:a:thekelleys:dnsmasq:2.85:*:*:*:*:*:*:*``). This module converts
between them, and decides whether an NVD "vulnerable" configuration really
covers our exact product and version. NVD's own matching is broad (one CVE
can list a dozen unrelated products), so every match is re-checked here.

Only CPEs with a concrete version are looked up. A product with no version
would match every CVE that product ever had, which is noise rather than risk
(the plan's "version banners are often missing" data-quality gap).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote

_PARTS = ("a", "o", "h")
# Characters CPE 2.3 formatted strings leave unescaped inside a value.
_FS_PLAIN = re.compile(r"[A-Za-z0-9._\-]")


@dataclass(frozen=True)
class Cpe:
    part: str
    vendor: str
    product: str
    version: str
    update: str = "*"
    edition: str = "*"
    language: str = "*"

    def to_23(self) -> str:
        fields = [self.part, self.vendor, self.product, self.version, self.update, self.edition,
                  self.language, "*", "*", "*", "*"]  # fmt: skip
        return "cpe:2.3:" + ":".join(_escape(f) for f in fields)

    @property
    def has_version(self) -> bool:
        return self.version not in ("*", "-", "")


def parse_cpe22(uri: str) -> Cpe | None:
    """Parse nmap's CPE 2.2 URI. Returns None for anything else."""
    if not uri.startswith("cpe:/"):
        return None
    parts = [unquote(p).lower() for p in uri[5:].split(":")]
    if len(parts) < 3 or parts[0] not in _PARTS or not parts[1] or not parts[2]:
        return None
    parts += ["*"] * (7 - len(parts))
    values = [p if p else "*" for p in parts[:7]]
    return Cpe(*values)


def parse_cpe23(name: str) -> Cpe | None:
    """Parse a CPE 2.3 formatted string (backslash escapes are removed)."""
    if not name.startswith("cpe:2.3:"):
        return None
    fields = _split_fs(name[8:])
    if len(fields) != 11 or fields[0] not in _PARTS:
        return None
    return Cpe(*fields[:7])


def _escape(value: str) -> str:
    if value in ("*", "-"):
        return value
    return "".join(ch if _FS_PLAIN.match(ch) else "\\" + ch for ch in value)


def _split_fs(text: str) -> list[str]:
    fields, current, escaped = [], [], False
    for ch in text:
        if escaped:
            current.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(ch)
    fields.append("".join(current))
    return fields


# --------------------------------------------------------------------------
# Versions
# --------------------------------------------------------------------------

_TOKEN = re.compile(r"\d+|[a-z]+")
#: Letter tokens that mean "before the release" (1.0rc1 < 1.0). Any other letters
#: mean "after it", as in OpenSSL 1.1.1k or OpenSSH 8.9p1.
_PRERELEASE = {"alpha", "beta", "rc", "pre", "preview", "dev", "snapshot"}
_PAD = (1, 0, "")  # a missing component counts as zero: 4.8 == 4.8.0


def version_key(version: str) -> list[tuple[int, int, str]]:
    key = []
    for token in _TOKEN.findall(version.lower()):
        if token.isdigit():
            key.append((1, int(token), ""))
        elif token in _PRERELEASE:
            key.append((0, 0, token))
        else:
            key.append((1, 0, token))
    return key


def compare_versions(a: str, b: str) -> int:
    """-1, 0, or 1. ``2.9 < 2.10``, ``1.0rc1 < 1.0``, ``4.8 == 4.8.0``, ``1.1.1 < 1.1.1k``."""
    ka, kb = version_key(a), version_key(b)
    length = max(len(ka), len(kb))
    pa = ka + [_PAD] * (length - len(ka))
    pb = kb + [_PAD] * (length - len(kb))
    return (pa > pb) - (pa < pb)


@dataclass(frozen=True)
class CpeMatch:
    """One ``cpeMatch`` entry from an NVD configuration."""

    criteria: str
    vulnerable: bool
    start_including: str | None = None
    start_excluding: str | None = None
    end_including: str | None = None
    end_excluding: str | None = None


def match_service(cpe: Cpe, rule: CpeMatch) -> str | None:
    """Does this NVD rule cover our product and version?

    Returns ``"cpe_exact"`` (the rule names our version), ``"cpe_version_range"``
    (our version falls in the rule's range), or None.
    """
    if not rule.vulnerable or not cpe.has_version:
        return None
    target = parse_cpe23(rule.criteria)
    if target is None or (target.part, target.vendor, target.product) != (
        cpe.part,
        cpe.vendor,
        cpe.product,
    ):
        return None
    has_range = any(
        (rule.start_including, rule.start_excluding, rule.end_including, rule.end_excluding)
    )
    if target.version not in ("*", "-") and not has_range:
        return "cpe_exact" if compare_versions(target.version, cpe.version) == 0 else None
    if target.version == "-":
        return None  # "no version" entries don't describe ours
    checks = (
        (rule.start_including, lambda c: c >= 0),
        (rule.start_excluding, lambda c: c > 0),
        (rule.end_including, lambda c: c <= 0),
        (rule.end_excluding, lambda c: c < 0),
    )
    for bound, ok in checks:
        if bound is not None and not ok(compare_versions(cpe.version, bound)):
            return None
    return "cpe_version_range" if has_range else None
