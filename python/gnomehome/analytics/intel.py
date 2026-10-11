"""Threat intel feeds: lists of known-bad domains (FR-10).

Two common formats are understood:

* ``hosts``: hosts-file lines such as ``127.0.0.1  bad.example`` or
  ``0.0.0.0 bad.example`` (abuse.ch URLhaus, many blocklists)
* ``domains``: one domain per line

Lines starting with ``#`` are comments. Anything that isn't a plausible domain
is skipped. A feed is replaced as a whole on each refresh, so domains removed
upstream stop matching.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from gnomehome.analytics.domains import normalize_domain
from gnomehome.db import transaction
from gnomehome.feeds import FeedError, HttpClient
from gnomehome.timeutil import utc_now

_DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")
_SKIP = {"localhost", "localhost.localdomain", "local", "broadcasthost", "0.0.0.0"}  # noqa: S104
FORMATS = ("hosts", "domains")


@dataclass(frozen=True)
class FeedSpec:
    name: str
    format: str
    url: str | None = None
    path: Path | None = None


def parse_feed(text: str, fmt: str) -> set[str]:
    if fmt not in FORMATS:
        raise ValueError(f"unknown feed format {fmt!r}")
    domains = set()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        candidate = fields[1] if fmt == "hosts" and len(fields) >= 2 else fields[0]
        domain = normalize_domain(candidate)
        if domain not in _SKIP and _DOMAIN.match(domain):
            domains.add(domain)
    return domains


def store_feed(conn: sqlite3.Connection, source: str, domains: set[str]) -> None:
    now = utc_now()
    with transaction(conn):
        conn.execute("DELETE FROM threat_indicator WHERE source = ?", (source,))
        conn.executemany(
            "INSERT INTO threat_indicator (indicator, kind, source, added_at) "
            "VALUES (?, 'domain', ?, ?)",
            [(d, source, now) for d in sorted(domains)],
        )


def refresh_feeds(
    conn: sqlite3.Connection, client: HttpClient, specs: list[FeedSpec]
) -> dict[str, int | str]:
    """Fetch and store every feed. Returns ``{name: count}``, or an error string per feed."""
    results: dict[str, int | str] = {}
    for spec in specs:
        try:
            if spec.url:
                text = client.get_text(spec.url)
            elif spec.path:
                text = spec.path.read_text(encoding="utf-8", errors="replace")
            else:
                raise FeedError("feed has neither url nor path")
            domains = parse_feed(text, spec.format)
            if not domains:
                raise FeedError("no domains found; keeping the previous copy")
        except (FeedError, OSError) as exc:
            results[spec.name] = f"error: {exc}"
            continue
        store_feed(conn, spec.name, domains)
        results[spec.name] = len(domains)
    return results
