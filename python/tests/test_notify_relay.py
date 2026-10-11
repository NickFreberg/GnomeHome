"""Push notifications (FR-16): fixed messages only, and only the kind leaves the Pi."""

from __future__ import annotations

import json
import sqlite3
import urllib.error
from pathlib import Path

import pytest

from gnomehome import cli
from gnomehome.db import open_database
from gnomehome.notify_relay import MESSAGES, AzureMonitor, RelayError, load_secret, relay

TENANT = "00000000-0000-0000-0000-000000000001"
CLIENT = "00000000-0000-0000-0000-000000000002"
DCR = "dcr-" + "0" * 32


class FakeNotifier:
    def __init__(self):
        self.messages = []

    def notify(self, message, *, title="GnomeHome"):
        self.messages.append(message)


class Reply:
    def __init__(self, body: bytes):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self.body


def queued(conn, *kinds):
    for kind in kinds:
        conn.execute(
            "INSERT INTO notification_outbox (kind, created_at) "
            "VALUES (?, '2026-10-11T12:00:00.000Z')",
            (kind,),
        )


@pytest.fixture
def db(tmp_path: Path):
    conn = open_database(tmp_path / "x.sqlite3")
    yield conn
    conn.close()


def test_every_kind_has_a_fixed_message():
    kinds = {"approval_needed", "action_taken", "action_failed", "weekly_assessment"}
    assert set(MESSAGES) == kinds  # the same list the schema's CHECK allows


def test_local_delivery_sends_one_message_per_kind(db):
    queued(db, "action_taken", "action_taken", "approval_needed")
    notifier = FakeNotifier()
    assert relay(db, notifier).sent == 3
    assert notifier.messages == [MESSAGES["action_taken"], MESSAGES["approval_needed"]]
    assert (
        db.execute("SELECT COUNT(*) FROM notification_outbox WHERE status = 'sent'").fetchone()[0]
        == 3
    )
    assert relay(db, notifier).sent == 0


def test_azure_receives_only_the_time_and_kind(db):
    queued(db, "approval_needed")
    sent = []

    def opener(request, timeout):
        sent.append(request)
        if "oauth2" in request.full_url:
            return Reply(json.dumps({"access_token": "tok"}).encode())
        return Reply(b"")

    azure = AzureMonitor(TENANT, CLIENT, "s3cret", "https://dce.example.test", DCR, opener=opener)
    assert relay(db, FakeNotifier(), azure).sent == 1
    token, ingest = sent
    assert token.full_url == f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"
    assert ingest.full_url.startswith(
        f"https://dce.example.test/dataCollectionRules/{DCR}/streams/"
    )
    assert ingest.headers["Authorization"] == "Bearer tok"
    assert json.loads(ingest.data) == [
        {"TimeGenerated": "2026-10-11T12:00:00.000Z", "Kind": "approval_needed"}
    ]
    assert "s3cret" not in repr(azure)


def test_a_failed_push_keeps_everything_queued(db):
    queued(db, "action_failed")

    def opener(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 401, "no", None, None)

    azure = AzureMonitor(TENANT, CLIENT, "s3cret", "https://dce.example.test", DCR, opener=opener)
    with pytest.raises(RelayError) as exc:
        relay(db, FakeNotifier(), azure)
    assert "s3cret" not in str(exc.value)
    assert db.execute("SELECT status FROM notification_outbox").fetchone()[0] == "pending"


def test_secret_file_checks(tmp_path):
    path = tmp_path / "secret"
    path.write_text("abc\n")
    path.chmod(0o640)
    assert load_secret(path) == "abc"
    path.chmod(0o644)
    with pytest.raises(RelayError, match="readable by every user"):
        load_secret(path)


def test_the_schema_refuses_free_text(db):
    with pytest.raises(sqlite3.IntegrityError):
        db.execute(
            "INSERT INTO notification_outbox (kind, created_at) "
            "VALUES ('kid-tablet looked up evil.test', '2026-10-11T12:00:00.000Z')"
        )


def test_cli_notify_runs_locally(config_path, capsys):
    assert cli.main(["--config", str(config_path), "migrate"]) == 0
    assert cli.main(["--config", str(config_path), "notify"]) == 0
