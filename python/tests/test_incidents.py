import json
import sqlite3
from pathlib import Path

import pytest

from gnomehome.audit import AuditLog, verify
from gnomehome.collectors.inventory import Observation, observe_asset, record_protected_presence
from gnomehome.db import open_database
from gnomehome.incidents import (
    NewDevice,
    drift_incident,
    in_learning_window,
    list_incidents,
    new_device_incident,
    open_incident,
    resolve_incident,
)
from gnomehome.narrative import Narrative

T0 = "2026-10-11T08:00:00.000Z"
T_LATER = "2026-10-11T12:00:00.000Z"
STORY = Narrative("test", "low", "t", T0, "the device at 192.0.2.5", "w", "y", "n")


@pytest.fixture
def db(tmp_path: Path) -> sqlite3.Connection:
    conn = open_database(tmp_path / "x.sqlite3")
    yield conn
    conn.close()


def test_learning_window(db):
    assert in_learning_window(db, T0, 60)  # empty inventory: the first device is baseline
    observe_asset(db, Observation("00:00:5e:00:53:20", "192.0.2.20"), seen_at=T0)
    assert in_learning_window(db, "2026-10-11T08:59:00.000Z", 60)
    assert not in_learning_window(db, T_LATER, 60)
    assert not in_learning_window(db, T0, 0)  # 0 means alert on everything


def test_new_device_incident_is_factual_and_deduplicated(db):
    asset_id, _ = observe_asset(db, Observation("02:00:5e:00:53:21", "192.0.2.21"), seen_at=T0)
    device = NewDevice(asset_id, "192.0.2.21", "02:00:5e:00:53:21", None, "Kid's Phone", T0)
    first = new_device_incident(db, device, source="dhcp")
    assert first is not None
    assert new_device_incident(db, device, source="dhcp") is None  # already open
    row = list_incidents(db)[0]
    assert row["severity"] == "low" and row["asset_id"] == asset_id
    assert '"Kid\'s Phone" (a device-supplied name' in row["summary"]
    assert "randomized" in row["summary"]


def test_drift_incident_names_the_label_only(db):
    audit = AuditLog(db)
    opened = drift_incident(
        db, label="Work laptop", kind="protected_mac_at_unlisted_ip", source="dhcp", audit=audit
    )
    assert opened is not None
    assert drift_incident(db, label="Work laptop", kind="protected_mac_at_unlisted_ip",
                          source="dhcp", audit=audit) is None  # fmt: skip
    row = list_incidents(db)[0]
    assert row["asset_id"] is None and row["severity"] == "medium"
    assert json.loads(row["evidence"])["label"] == "Work laptop"
    text = " ".join(str(v) for v in tuple(row))
    assert "192.0.2" not in text and "00:00:5e" not in text
    assert (
        db.execute("SELECT COUNT(*) FROM audit_log WHERE action='guard.drift_detected'").fetchone()[
            0
        ]
        == 2
    )
    assert verify(db).ok


def test_resolve_reopens_dedup_and_is_audited(db):
    audit = AuditLog(db)
    incident_id = open_incident(db, STORY, dedup_key="k")
    assert resolve_incident(db, incident_id, audit=audit, actor="user:local")
    assert not resolve_incident(db, incident_id, audit=audit, actor="user:local")
    assert list_incidents(db) == []
    assert len(list_incidents(db, include_closed=True)) == 1
    # Once resolved, the same condition can raise a fresh incident.
    assert open_incident(db, STORY, dedup_key="k") is not None


def test_protected_presence_is_existence_only_and_never_updated(db):
    record_protected_presence(db, "00-00-5E-00-53-01", T0)
    record_protected_presence(db, "00:00:5e:00:53:01", T_LATER)
    row = db.execute("SELECT * FROM asset").fetchone()
    assert row["protected"] == 1
    assert row["first_seen"] == row["last_seen"] == T0  # no presence timeline
    assert row["last_ip"] is None and row["vendor"] is None and row["hostname"] is None


def test_observations_can_arrive_out_of_order(db):
    mac = "00:00:5e:00:53:30"
    observe_asset(db, Observation(mac, "192.0.2.30"), seen_at=T_LATER)
    observe_asset(db, Observation(mac, "192.0.2.31"), seen_at=T0)  # an older log line
    row = db.execute("SELECT * FROM asset").fetchone()
    assert row["first_seen"] == T0 and row["last_seen"] == T_LATER
    assert row["last_ip"] == "192.0.2.30"  # the newest sighting wins
