"""Timestamps in one fixed format, shared with the Rust side.

UTC, millisecond precision, trailing ``Z``: ``2026-10-11T14:03:00.000Z``.
The fixed width means text order equals time order, so SQLite can compare
and index timestamps as plain strings.
"""

from __future__ import annotations

from datetime import UTC, datetime


def format_ts(moment: datetime) -> str:
    if moment.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    moment = moment.astimezone(UTC)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def utc_now() -> str:
    return format_ts(datetime.now(UTC))


def parse_ts(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
