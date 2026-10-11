"""The incident log as a document: ``just incident-report`` (FR-11).

Markdown for people (it reads well on GitHub, in an editor, or printed) and
JSON for tools such as the weekly check-in. Both list each incident's time,
device, what happened, why it matters, and what to do.

Incident text quotes device-supplied names, which an attacker controls. In
Markdown, every value is escaped so a name like ``[click](https://evil.test)``
or ``<img src=x>`` shows up as plain text and never becomes a link or HTML.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from typing import Any

from gnomehome.incidents import OPEN_STATUSES
from gnomehome.narrative import MITRE_URL

SEVERITY_ORDER = ("critical", "high", "medium", "low")
# Enough to stop links, images, HTML, code, tables, and emphasis. With "[" and "]"
# escaped, parentheses can't form a link, so they're left readable.
_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>|~])")
_WHITESPACE = re.compile(r"\s+")
_SCHEME = re.compile(r"(?i)\b(https?|ftp)://")
_DEFANGED = {"http": "hxxp", "https": "hxxps", "ftp": "fxp"}
_WWW = re.compile(r"(?i)\b(www)\.")

FIELDS = (
    "id",
    "created_at",
    "occurred_at",
    "status",
    "severity",
    "detection",
    "title",
    "device",
    "what_happened",
    "why_it_matters",
    "next_steps",
    "mitre_technique",
    "confidence",
    "playbook",
    "outcome",
)


@dataclass(frozen=True)
class ReportOptions:
    since: str | None = None
    include_closed: bool = False
    generated_at: str = ""


def md_escape(text: Any) -> str:
    """Plain text for Markdown: no links, no HTML, no formatting, one line.

    GitHub also turns bare ``https://...``, ``www.``, and email-like text into
    links, so those are defanged the way incident reports usually do
    (``hxxps://``, ``www[.]``, ``[@]``): nobody should be one click away from
    a domain on a threat list.
    """
    value = _WHITESPACE.sub(" ", str(text)).strip()
    value = _SCHEME.sub(lambda m: _DEFANGED[m.group(1).lower()] + "://", value)
    value = _WWW.sub(lambda m: m.group(1) + "[.]", value)
    value = value.replace("@", "[@]").replace("&", "&amp;")
    return _MD_SPECIAL.sub(r"\\\1", value)


def fetch(conn: sqlite3.Connection, options: ReportOptions) -> list[dict[str, Any]]:
    clauses, params = [], []
    if not options.include_closed:
        clauses.append(f"status IN ({', '.join('?' for _ in OPEN_STATUSES)})")
        params.extend(OPEN_STATUSES)
    if options.since:
        clauses.append("COALESCE(occurred_at, created_at) >= ?")
        params.append(options.since)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = conn.execute(
        f"SELECT {', '.join(FIELDS)}, summary FROM incident {where} "  # noqa: S608
        "ORDER BY COALESCE(occurred_at, created_at), id",
        params,
    ).fetchall()
    out = []
    for row in rows:
        item = {key: row[key] for key in FIELDS}
        # Incidents from before the structured log (migration 0005) have only a summary.
        if item["what_happened"] is None:
            item["what_happened"] = row["summary"]
        out.append(item)
    return out


def to_json(incidents: list[dict[str, Any]], options: ReportOptions) -> str:
    return json.dumps(
        {
            "generated_at": options.generated_at,
            "since": options.since,
            "include_closed": options.include_closed,
            "incidents": incidents,
        },
        indent=2,
        ensure_ascii=False,
    )


def to_markdown(
    incidents: list[dict[str, Any]],
    options: ReportOptions,
    new_domains: list[tuple[str, int]] | None = None,
) -> str:
    scope = "all incidents" if options.include_closed else "open incidents"
    if options.since:
        scope += f" since {options.since}"
    lines = [
        "# GnomeHome incident log",
        "",
        f"Generated {options.generated_at}, covering {scope}.",
        "",
    ]
    if not incidents:
        lines += ["All quiet in the garden: nothing to report.", ""]
    else:
        counts = {s: sum(i["severity"] == s for i in incidents) for s in SEVERITY_ORDER}
        lines += [
            "| Severity | Incidents |",
            "| --- | --- |",
            *(f"| {s.capitalize()} | {n} |" for s, n in counts.items() if n),
            "",
        ]
    for item in incidents:
        lines += _incident_md(item)
    if new_domains:
        lines += [
            "## New domains by device",
            "",
            "Domains each device looked up for the first time in this period. This is context, "
            "not an alert: devices meet new domains every day.",
            "",
            "| Device | New domains |",
            "| --- | --- |",
            *(f"| {md_escape(ip)} | {n} |" for ip, n in new_domains),
            "",
        ]
    return "\n".join(lines).rstrip("\n") + "\n"


def _incident_md(item: dict[str, Any]) -> list[str]:
    severity = item["severity"].upper()
    technique = item["mitre_technique"]
    mitre = (
        f"[{technique}]({MITRE_URL.format(technique.replace('.', '/'))})"
        if technique
        else "Not mapped"
    )
    confidence = f"{item['confidence']:.0%}" if item["confidence"] is not None else "Not rated"
    rows = [
        ("When", item["occurred_at"] or item["created_at"]),
        ("Device", item["device"] or "Not tied to one device"),
        ("Detection", item["detection"]),
        ("Status", item["status"].replace("_", " ")),
        ("Confidence", confidence),
    ]
    out = [
        f"## #{item['id']} {severity}: {md_escape(item['title'])}",
        "",
        "| | |",
        "| --- | --- |",
        *(f"| {k} | {md_escape(v)} |" for k, v in rows),
        f"| MITRE ATT&CK | {mitre} |",
    ]
    if item["playbook"]:
        out.append(f"| Playbook | {md_escape(item['playbook'])} |")
    if item["outcome"]:
        out.append(f"| Outcome | {md_escape(item['outcome'])} |")
    out += ["", f"**What happened.** {md_escape(item['what_happened'])}", ""]
    if item["why_it_matters"]:
        out += [f"**Why it matters.** {md_escape(item['why_it_matters'])}", ""]
    if item["next_steps"]:
        out += [f"**What to do.** {md_escape(item['next_steps'])}", ""]
    return out


def new_domain_counts(conn: sqlite3.Connection, since: str | None) -> list[tuple[str, int]]:
    rows = conn.execute(
        "SELECT src_ip, COUNT(*) FROM device_domain WHERE (? IS NULL OR first_seen >= ?) "
        "GROUP BY src_ip ORDER BY COUNT(*) DESC, src_ip",
        (since, since),
    ).fetchall()
    return [(row[0], row[1]) for row in rows]
