"""Logic the cloud jobs reuse: manifest verification, the weekly summary, and job imports.

pyspark isn't installed here, so the Databricks jobs themselves can't run in CI.
These tests cover everything they import from the gnomehome package, and check
statically that every such import exists.
"""

from __future__ import annotations

import ast
import importlib
import json
from datetime import date
from pathlib import Path

import pytest
from helpers import EXAMPLE_PROTECTED, REPO_ROOT

from gnomehome.db import open_database
from gnomehome.export import export_day, verify_partition
from gnomehome.protected import load_guard
from gnomehome.summary import SCHEMA, build_weekly_summary, from_sqlite
from gnomehome.synthetic.generate import generate
from gnomehome.synthetic.load import load_synthetic

JOBS = sorted((REPO_ROOT / "databricks" / "src").glob("*.py"))


def test_manifest_verification_catches_tampering(tmp_path: Path):
    conn = open_database(tmp_path / "x.sqlite3")
    conn.execute(
        "INSERT INTO event (ts, kind, source, message) VALUES "
        "('2026-10-05T01:00:00.000Z', 'syslog', 'test', 'ntp ok')"
    )
    out = tmp_path / "out"
    result = export_day(conn, load_guard(EXAMPLE_PROTECTED), out, "2026-10-05", generated_at="x",
                        synthetic=False)  # fmt: skip
    manifest = json.loads(result.manifest.read_text())

    def read(path: str) -> bytes:
        return (out / path).read_bytes()

    assert verify_partition(manifest, read) == []
    (out / manifest["tables"]["event"]["file"]).write_bytes(b"tampered")
    assert verify_partition(manifest, read) == ["event: SHA-256 doesn't match the manifest"]
    assert any("guard" in p for p in verify_partition({**manifest, "guard_checked": False}, read))
    assert any("version" in p for p in verify_partition({**manifest, "export_version": 9}, read))
    conn.close()


def test_weekly_summary_from_rows():
    week_end = date(2026, 10, 11)
    asset = {"id": 1, "last_ip": "192.0.2.30", "vendor": "Example Co", "hostname": "den-pc",
             "first_seen": "2026-10-08T10:00:00.000Z"}  # fmt: skip
    old = {"id": 2, "last_ip": "192.0.2.40", "vendor": None, "hostname": None,
           "first_seen": "2026-09-01T10:00:00.000Z"}  # fmt: skip
    summary = build_weekly_summary(
        week_end=week_end,
        assets=[asset, old, {"id": 3, "protected": 1, "first_seen": "2026-10-09T00:00:00.000Z"}],
        incidents=[
            {
                "id": 7,
                "severity": "high",
                "detection": "dns.dga",
                "title": "Burst",
                "status": "open",
                "created_at": "2026-10-09T00:00:00.000Z",
                "occurred_at": None,
            },
            {
                "id": 3,
                "severity": "low",
                "detection": "x",
                "title": "Old",
                "status": "resolved",
                "created_at": "2026-09-01T00:00:00.000Z",
                "occurred_at": None,
            },
        ],
        risk_scores=[
            {"asset_id": 1, "score_date": "2026-10-04", "score": 40.0, "level": "medium"},
            {"asset_id": 1, "score_date": "2026-10-11", "score": 75.0, "level": "high"},
            {"asset_id": 2, "score_date": "2026-10-11", "score": 10.0, "level": "low"},
        ],
        device_types={"192.0.2.30": "computer"},
    )
    assert summary["schema"] == SCHEMA and summary["week_start"] == "2026-10-05"
    assert summary["devices"]["total"] == 2  # the protected device is never counted
    assert [n["type_guess"] for n in summary["devices"]["new"]] == ["computer"]
    assert summary["risk"]["changes"] == [
        {"device": summary["risk"]["top"][0]["device"], "from": "medium", "to": "high", "score": 75}
    ]
    assert summary["risk"]["levels"] == {"high": 1, "low": 1}
    assert summary["incidents"]["opened"] == 1 and summary["incidents"]["items"][0]["id"] == 7


def test_weekly_summary_from_the_synthetic_database(tmp_path: Path):
    out = tmp_path / "seed-4"
    generate(out, seed=4, start_date="2026-10-05", hours=24)
    conn = open_database(tmp_path / "dev.sqlite3")
    load_synthetic(conn, load_guard(EXAMPLE_PROTECTED), out)
    summary = from_sqlite(conn, date(2026, 10, 11))
    conn.close()
    assert summary["devices"]["total"] == 13
    assert summary["dns"]["queries"] > 1000
    text = json.dumps(summary)
    assert "192.0.2.10" not in text and "00:00:5e:00:53:01" not in text
    assert load_guard(EXAMPLE_PROTECTED).text_mentions_protected(text) is False


@pytest.mark.parametrize("job", JOBS, ids=lambda p: p.name)
def test_databricks_jobs_import_only_what_exists(job: Path):
    tree = ast.parse(job.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("gnomehome"):
            module = importlib.import_module(node.module)
            for alias in node.names:
                assert hasattr(module, alias.name), f"{job.name}: {node.module}.{alias.name}"
