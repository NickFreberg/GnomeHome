"""The nightly export and upload (Phase 6): nothing about a protected device leaves the Pi."""

from __future__ import annotations

import gzip
import hashlib
import json
import urllib.error
from pathlib import Path

import pytest
from helpers import EXAMPLE_PROTECTED

from gnomehome import cli
from gnomehome.db import open_database
from gnomehome.export import export_day, partition_files, yesterday
from gnomehome.protected import load_guard
from gnomehome.synthetic.generate import generate
from gnomehome.synthetic.load import load_synthetic
from gnomehome.upload import BlobClient, UploadError, load_sas, plan_uploads, upload_day

DAY = "2026-10-05"
LAPTOP = ("192.0.2.10", "00:00:5e:00:53:01", "00:00:5e:00:53:02", "00-00-5e-00-53-01")


@pytest.fixture(scope="module")
def synthetic(tmp_path_factory):
    root = tmp_path_factory.mktemp("export")
    out = root / "seed-3"
    generate(out, seed=3, start_date=DAY, hours=24)
    conn = open_database(root / "dev.sqlite3")
    load_synthetic(conn, load_guard(EXAMPLE_PROTECTED), out)
    yield conn, root
    conn.close()


def read_rows(path: Path) -> list[dict]:
    text = gzip.decompress(path.read_bytes()).decode()
    return [json.loads(line) for line in text.splitlines() if line]


def test_export_writes_every_table_and_a_matching_manifest(synthetic):
    conn, root = synthetic
    out = root / "export-a"
    result = export_day(conn, load_guard(EXAMPLE_PROTECTED), out, DAY,
                        generated_at="2026-10-06T02:00:00.000Z", synthetic=True)  # fmt: skip
    manifest = json.loads(result.manifest.read_text())
    assert manifest["day"] == DAY and manifest["synthetic"] and manifest["guard_checked"]
    events = conn.execute(
        "SELECT COUNT(*) FROM event WHERE ts >= ? AND ts < ?", (f"{DAY}T00", "2026-10-06T00")
    ).fetchone()[0]
    assert manifest["tables"]["event"]["rows"] == events > 1000
    assert (
        manifest["tables"]["asset"]["rows"] == 13
    )  # 12 household devices and the router, no laptop
    for name, entry in manifest["tables"].items():
        data = (out / entry["file"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == entry["sha256"], name
        assert len(read_rows(out / entry["file"])) == entry["rows"]
        assert (out / entry["file"]).stat().st_mode & 0o077 == 0  # owner only
    assert partition_files(out, DAY)[-1] == result.manifest


def test_nothing_about_the_laptop_is_exported(synthetic):
    conn, root = synthetic
    out = root / "export-b"
    export_day(conn, load_guard(EXAMPLE_PROTECTED), out, DAY,
               generated_at="2026-10-06T02:00:00.000Z", synthetic=True)  # fmt: skip
    for path in out.rglob("*.gz"):
        text = gzip.decompress(path.read_bytes()).decode().lower()
        for identifier in LAPTOP:
            assert identifier not in text, (path.name, identifier)


def test_a_row_that_slipped_past_the_collectors_is_dropped_and_counted(tmp_path):
    conn = open_database(tmp_path / "x.sqlite3")
    # Simulate a bug upstream: a syslog line naming the laptop reached the database.
    conn.execute(
        "INSERT INTO event (ts, kind, source, message) VALUES (?, 'syslog', 'test', ?)",
        (f"{DAY}T10:00:00.000Z", "DROP IN=br0 SRC=192.0.2.10 DST=203.0.113.5"),
    )
    conn.execute(
        "INSERT INTO event (ts, kind, source, src_ip, dst_ip, protocol) "
        "VALUES (?, 'flow', 'test', '192.0.2.30', '::ffff:192.0.2.10', 'tcp')",
        (f"{DAY}T11:00:00.000Z",),
    )
    conn.execute(
        "INSERT INTO event (ts, kind, source, message) VALUES (?, 'syslog', 'test', 'ntp ok')",
        (f"{DAY}T12:00:00.000Z",),
    )
    result = export_day(conn, load_guard(EXAMPLE_PROTECTED), tmp_path / "out", DAY,
                        generated_at="2026-10-06T02:00:00.000Z", synthetic=False)  # fmt: skip
    assert result.tables["event"].rows == 1
    assert result.tables["event"].dropped_protected == 2
    conn.close()


def test_exports_are_repeatable_and_old_days_are_pruned(synthetic):
    conn, root = synthetic
    out = root / "export-c"
    guard = load_guard(EXAMPLE_PROTECTED)
    first = export_day(conn, guard, out, DAY, generated_at="x", synthetic=True)
    again = export_day(conn, guard, out, DAY, generated_at="x", synthetic=True)
    assert first.tables["event"].sha256 == again.tables["event"].sha256
    stale = out / "event" / "date=2026-09-01"
    stale.mkdir()
    (out / "_manifests" / "date=2026-09-01.json").write_text("{}")
    export_day(conn, guard, out, DAY, generated_at="x", synthetic=True, keep_days=14)
    assert not stale.exists() and not (out / "_manifests" / "date=2026-09-01.json").exists()
    assert yesterday(__import__("datetime").date(2026, 10, 1)) == "2026-09-30"


# ------------------------------------------------------------------ upload


class FakeResponse:
    status = 201

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def sas_file(tmp_path: Path, token: str, mode: int = 0o640) -> Path:
    path = tmp_path / "storage_sas"
    path.write_text(token + "\n")
    path.chmod(mode)
    return path


GOOD_SAS = "?sv=2023-11-03&si=gnomehome-upload&sr=c&sig=abc%2Fdef"


def test_upload_puts_data_first_and_the_manifest_last(synthetic):
    conn, root = synthetic
    out = root / "export-d"
    export_day(conn, load_guard(EXAMPLE_PROTECTED), out, DAY, generated_at="x", synthetic=True)
    sent = []

    def opener(request, timeout):
        sent.append(request)
        return FakeResponse()

    client = BlobClient("gnomehometest", "raw", GOOD_SAS.removeprefix("?"), opener=opener)
    blobs = upload_day(client, out, DAY, "synthetic")
    assert blobs[-1] == f"synthetic/_manifests/date={DAY}.json"
    assert len(blobs) == 9
    request = sent[0]
    assert request.get_method() == "PUT"
    assert request.full_url.startswith("https://gnomehometest.blob.core.windows.net/raw/synthetic/")
    assert request.headers["X-ms-blob-type"] == "BlockBlob"
    assert "sig=" not in repr(client)  # the token never shows up in logs


def test_upload_errors_never_include_the_token(synthetic):
    conn, root = synthetic
    out = root / "export-e"
    export_day(conn, load_guard(EXAMPLE_PROTECTED), out, DAY, generated_at="x", synthetic=True)

    def opener(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 403, "Forbidden", None, None)

    client = BlobClient("gnomehometest", "raw", "sv=1&sig=SECRET", opener=opener)
    with pytest.raises(UploadError) as exc:
        upload_day(client, out, DAY, "synthetic")
    assert "SECRET" not in str(exc.value) and "403" in str(exc.value)


def test_upload_refuses_a_missing_export(tmp_path):
    client = BlobClient("gnomehometest", "raw", "sv=1&sig=x", opener=lambda *a, **k: None)
    with pytest.raises(UploadError, match="run `just export` first"):
        upload_day(client, tmp_path, DAY, "gnomehome")
    assert plan_uploads(tmp_path, DAY, "gnomehome") == []


def test_sas_token_file_checks(tmp_path):
    assert load_sas(sas_file(tmp_path, GOOD_SAS)) == GOOD_SAS.removeprefix("?")
    with pytest.raises(UploadError, match="readable by every user"):
        load_sas(sas_file(tmp_path, GOOD_SAS, 0o644))
    with pytest.raises(UploadError, match="doesn't look like a SAS"):
        load_sas(sas_file(tmp_path, "hunter2"))
    with pytest.raises(UploadError, match="reading or deleting"):
        load_sas(sas_file(tmp_path, "sv=2023-11-03&sp=rcw&sig=x"))
    with pytest.raises(UploadError, match="can't read"):
        load_sas(tmp_path / "missing")


def test_cli_export_and_unconfigured_upload(config_path, capsys):
    assert cli.main(["--config", str(config_path), "migrate"]) == 0
    assert cli.main(["--config", str(config_path), "export", "--day", DAY]) == 0
    assert f"Exported {DAY}" in capsys.readouterr().out
    assert cli.main(["--config", str(config_path), "upload", "--day", DAY, "--send"]) == 0
    assert "Upload not configured" in capsys.readouterr().out
