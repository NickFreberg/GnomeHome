"""Bring the weekly AI check-in back to the Pi: ``just checkin-fetch``.

The check-in job writes its report to the ``reports`` container. This fetches it
with a read-only SAS token, then trusts nothing in it:

* the AI's text becomes one ``ai.checkin`` incident, quoted and labeled as
  AI-written, unless it mentions a protected device, in which case it isn't stored
* each suggestion must name an allowed playbook and the address of a known,
  non-protected device; it becomes one ``ai.suggestion`` incident, which the
  playbook engine turns into an ask-first run waiting for the owner's approval
"""

from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from gnomehome import narrative
from gnomehome.agent.prompt import ALLOWED_PLAYBOOKS, MAX_REPORT, clean
from gnomehome.db import transaction
from gnomehome.incidents import open_incident
from gnomehome.protected import Guard

_WEEK = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class CheckinError(Exception):
    """The report couldn't be fetched or isn't a check-in report."""


def fetch_report(
    account: str,
    sas: str,
    week_end: str,
    opener: Callable[..., Any] = urllib.request.urlopen,
) -> dict[str, Any]:
    if not _WEEK.match(week_end):
        raise CheckinError("week_end must look like 2026-10-11")
    path = urllib.parse.quote(f"reports/checkin/week_end={week_end}.json")
    request = urllib.request.Request(
        f"https://{account}.blob.core.windows.net/{path}?{sas}",
        headers={"x-ms-version": "2023-11-03"},
    )
    try:
        with opener(request, timeout=60) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        raise CheckinError(f"no check-in report for {week_end} (HTTP {exc.code})") from None
    except urllib.error.URLError as exc:
        raise CheckinError(f"storage unreachable: {exc.reason}") from None
    except json.JSONDecodeError:
        raise CheckinError("the report isn't JSON") from None


@dataclass
class ImportResult:
    week_end: str
    report_stored: bool = False
    suggestions: int = 0
    dropped: int = 0


def import_report(conn: sqlite3.Connection, guard: Guard, report: dict[str, Any]) -> ImportResult:
    week_end = report.get("week_end")
    if (
        report.get("schema") != "gnomehome-checkin-v1"
        or not isinstance(week_end, str)
        or not _WEEK.match(week_end)
    ):
        raise CheckinError("not a GnomeHome check-in report")
    result = ImportResult(week_end)
    text = report.get("report") if isinstance(report.get("report"), str) else ""
    highlights = [h for h in report.get("highlights") or [] if isinstance(h, str)]
    if guard.text_mentions_protected(text) or any(
        guard.text_mentions_protected(h) for h in highlights
    ):
        text = "The check-in mentioned a protected device, so its text wasn't stored."
        highlights = []
    with transaction(conn):
        story = narrative.ai_checkin(
            week_end=week_end, report=clean(text, MAX_REPORT), highlights=highlights
        )
        result.report_stored = (
            open_incident(conn, story, dedup_key=f"checkin:{week_end}") is not None
        )
        for s in report.get("suggestions") or []:
            asset = _suggested_asset(conn, guard, s)
            if asset is None:
                result.dropped += 1
                continue
            device = narrative.describe_device(asset["last_ip"], asset["vendor"], asset["hostname"])
            story = narrative.ai_suggestion(
                device=device,
                playbook=s["playbook"],
                reason=str(s.get("reason", "")),
                week_end=week_end,
            )
            opened = open_incident(
                conn,
                story,
                asset_id=asset["id"],
                evidence={"playbook": s["playbook"], "week_end": week_end, "source": "ai.checkin"},
                dedup_key=f"suggestion:{week_end}:{asset['id']}:{s['playbook']}",
            )
            result.suggestions += opened is not None
    return result


def _suggested_asset(conn: sqlite3.Connection, guard: Guard, s: Any) -> sqlite3.Row | None:
    if not isinstance(s, dict) or s.get("playbook") not in ALLOWED_PLAYBOOKS:
        return None
    try:
        ip = str(ipaddress.IPv4Address(str(s.get("device_ip", ""))))
    except ValueError:
        return None
    if guard.is_protected(ip=ip):
        return None
    row = conn.execute(
        "SELECT id, last_ip, vendor, hostname, mac FROM asset WHERE last_ip = ? AND protected = 0",
        (ip,),
    ).fetchone()
    if row is None or guard.is_protected(mac=row["mac"]):
        return None
    return row


def load_report_file(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise CheckinError(f"can't read {path}: {exc}") from None
