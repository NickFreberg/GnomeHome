"""Domain helpers: the registered domain, and how machine-generated a name looks."""

from __future__ import annotations

import math
from collections import Counter

#: Second-level labels that sit under a country code (example.co.uk -> example.co.uk).
_CC_SECOND_LEVEL = {"co", "com", "net", "org", "gov", "ac", "edu", "ne", "or"}
_VOWELS = set("aeiouy")


def normalize_domain(domain: str) -> str:
    return domain.strip().rstrip(".").lower()


def registered_domain(domain: str) -> str:
    """``a.b.example.co.uk`` becomes ``example.co.uk``; ``cdn.example.com`` becomes ``example.com``.

    A small approximation of the Public Suffix List, good enough for grouping
    and scoring. No network lookup, no extra dependency.
    """
    labels = [x for x in normalize_domain(domain).split(".") if x]
    if len(labels) <= 2:
        return ".".join(labels)
    if len(labels[-1]) == 2 and labels[-2] in _CC_SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def parents(domain: str) -> list[str]:
    """The domain and every parent down to its registered domain (for feed matching)."""
    labels = normalize_domain(domain).split(".")
    stop = len(registered_domain(domain).split("."))
    return [".".join(labels[i:]) for i in range(0, len(labels) - stop + 1)]


def _entropy(text: str) -> float:
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def dga_score(domain: str) -> float:
    """0 (looks human-made) to 1 (looks machine-generated), from the main label alone.

    Algorithmically generated names (T1568.002) tend to be long, high-entropy,
    digit-heavy, and short on vowels. Each feature adds a weighted share, and
    the total is scaled down for short labels, which carry too little signal.
    """
    label = registered_domain(domain).split(".")[0].replace("-", "")
    if len(label) < 8:
        return 0.0
    letters = [c for c in label if c.isalpha()]
    entropy = _entropy(label) / math.log2(min(len(label), 36))
    digits = sum(c.isdigit() for c in label) / len(label)
    vowels = sum(c in _VOWELS for c in letters) / max(len(letters), 1)
    run = longest = 0
    for c in label:
        run = run + 1 if c.isalpha() and c not in _VOWELS else 0
        longest = max(longest, run)
    score = (
        0.35 * min(entropy, 1.0)
        + 0.25 * min(digits * 3, 1.0)
        + 0.25 * (1 - min(vowels / 0.35, 1.0))
        + 0.15 * min(longest / 6, 1.0)
    )
    length_factor = min((len(label) - 6) / 6, 1.0)
    return round(score * length_factor, 3)
