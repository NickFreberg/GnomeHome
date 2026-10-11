"""Phase 6 ML logic: daily features, anomaly detection, and the device classifier."""

from __future__ import annotations

import json
from collections import Counter

import pytest
from helpers import EXAMPLE_PROTECTED

from gnomehome.db import open_database
from gnomehome.ml.anomaly import detect, robust_z
from gnomehome.ml.classifier import DeviceProfile, classify, profiles_from_rows
from gnomehome.ml.features import FEATURES, DeviceDay, daily_features, fill_missing_days
from gnomehome.protected import load_guard
from gnomehome.synthetic.generate import generate
from gnomehome.synthetic.household import build_household
from gnomehome.synthetic.load import load_synthetic

# ------------------------------------------------------------------ features


def dns(ts: str, ip: str, domain: str, status: str = "forwarded") -> dict:
    return {"ts": ts, "src_ip": ip, "domain": domain, "status": status}


def flow(ts: str, ip: str, dst: str, port: int = 443, out: int = 100, inn: int = 1000) -> dict:
    return {"ts": ts, "src_ip": ip, "dst_ip": dst, "dst_port": port, "bytes_out": out,
            "bytes_in": inn}  # fmt: skip


def test_daily_features_count_what_they_say():
    days = daily_features(
        [
            dns("2026-10-11T02:00:00.000Z", "192.0.2.5", "a.example.test"),
            dns("2026-10-11T12:00:00.000Z", "192.0.2.5", "b.example.test", "nxdomain"),
            dns("2026-10-11T13:00:00.000Z", "192.0.2.5", "ads.test", "blocked"),
            dns("2026-10-12T13:00:00.000Z", "192.0.2.5", "ads.test"),
        ],
        [
            flow("2026-10-11T12:00:00.000Z", "192.0.2.5", "203.0.113.5", out=500),
            flow("2026-10-11T12:01:00.000Z", "192.0.2.5", "8.8.8.8", port=53),
            flow("2026-10-11T12:02:00.000Z", "192.0.2.5", "192.0.2.2", port=53),  # Pi-hole
        ],
        known_domains={"192.0.2.5": {"ads.test"}},
        pihole_ip="192.0.2.2",
    )
    first, second = days
    assert (first.device, first.day) == ("192.0.2.5", "2026-10-11")
    v = first.values
    assert v["dns_queries"] == 3 and v["distinct_domains"] == 2  # example.test counts once
    assert v["new_domains"] == 1  # ads.test was already known
    assert v["nxdomain_share"] == pytest.approx(1 / 3)
    assert v["blocked_share"] == pytest.approx(1 / 3)
    assert v["night_share"] == pytest.approx(1 / 3)
    assert v["flows"] == 3 and v["bytes_out"] == 700 and v["distinct_destinations"] == 3
    assert v["dns_bypass_flows"] == 1
    assert second.values["new_domains"] == 0
    assert set(v) == set(FEATURES)


def test_local_time_decides_the_day_and_silent_days_are_filled():
    rows = [dns("2026-10-11T03:00:00.000Z", "192.0.2.5", "a.test"),
            dns("2026-10-13T12:00:00.000Z", "192.0.2.5", "a.test")]  # fmt: skip
    shifted = daily_features(rows, [], utc_offset_hours=-5)
    assert shifted[0].day == "2026-10-10"  # 3 a.m. UTC is the evening before, 5 hours west
    filled = fill_missing_days(daily_features(rows, []))
    assert [d.day for d in filled] == ["2026-10-11", "2026-10-12", "2026-10-13"]
    assert filled[1].values["dns_queries"] == 0


# ------------------------------------------------------------------ anomaly detection


def series(device: str, values: list[float], feature: str = "bytes_out") -> list[DeviceDay]:
    return [
        DeviceDay(device, f"2026-10-{i + 1:02d}", {**dict.fromkeys(FEATURES, 0.0), feature: v})
        for i, v in enumerate(values)
    ]


def test_robust_z_ignores_one_old_spike_and_has_floors():
    z, median = robust_z(5e6, [5e6, 5.1e6, 4.9e6, 900e6, 5e6], 20e6)
    assert median == 5e6 and z == 0
    z, _ = robust_z(1, [0, 0, 0, 0, 0], 5.0)
    assert z == pytest.approx(0.2)  # a single byte from a silent device isn't news


def test_detect_flags_a_big_rise_against_the_trailing_history():
    days = series("192.0.2.30", [5e6, 6e6, 5.5e6, 4e6, 6.5e6, 5e6, 1.5e9])
    found = detect(days)
    assert [(a.day, a.feature, a.severity) for a in found] == [("2026-10-07", "bytes_out", "high")]
    assert "1.5 GB, against a usual 5.2 MB" in found[0].reason
    assert "times as much" in found[0].reason


def test_detect_needs_history_and_ignores_drops():
    assert detect(series("192.0.2.30", [5e6, 1.5e9])) == []  # too little history
    assert detect(series("192.0.2.30", [5e8] * 6 + [0.0])) == []  # a quiet day isn't flagged


# ------------------------------------------------------------------ classifier


def test_each_kind_of_clue_counts():
    camera = classify(DeviceProfile("d", vendor="Example Camera Co", open_ports={554, 80}))
    assert camera.label == "camera" and camera.confidence > 0.9
    assert "streams video (RTSP, port 554)" in camera.evidence
    printer = classify(DeviceProfile("d", os_type="printer"))
    assert printer.label == "printer"
    pc = classify(DeviceProfile("d", os_name="Microsoft Windows 11", open_ports={445}))
    assert pc.label == "computer"
    console = classify(DeviceProfile("d", domains=Counter({"matchmaking.game-network.test": 50})))
    assert console.label == "console"


def test_too_little_evidence_is_unknown_and_names_count_for_little():
    assert classify(DeviceProfile("d")).label == "unknown"
    # A device can call itself anything: its name alone isn't enough.
    liar = classify(DeviceProfile("d", hostname="security-camera"))
    assert liar.label == "unknown"
    # And a name can't outvote real evidence.
    printer = classify(DeviceProfile("d", hostname="camera", open_ports={631, 9100}))
    assert printer.label == "printer"


@pytest.fixture(scope="module")
def synthetic_db(tmp_path_factory):
    out = tmp_path_factory.mktemp("synth") / "seed-5"
    generate(out, seed=5, start_date="2026-10-05", hours=24)
    conn = open_database(out.parent / "dev.sqlite3")
    load_synthetic(conn, load_guard(EXAMPLE_PROTECTED), out)
    yield conn
    conn.close()


def test_classifier_on_the_synthetic_household(synthetic_db):
    rows = lambda sql: [dict(r) for r in synthetic_db.execute(sql)]  # noqa: E731
    profiles = profiles_from_rows(
        rows("SELECT * FROM asset WHERE protected = 0"),
        rows("SELECT * FROM service"),
        rows("SELECT src_ip, domain FROM event WHERE kind = 'dns'"),
    )
    got = {p.device: classify(p).label for p in profiles}
    expected = {"laptop": "computer", "unknown": "phone"}
    for device in build_household():
        if device.protected:
            assert device.ip not in got  # never stored, so never classified
            continue
        want = expected.get(device.kind, device.kind)
        if device.name == "streaming-stick":
            want = "unknown"  # no DNS (it bypasses Pi-hole) and no open ports: honestly unknown
        assert got[device.ip] == want, device.name
    assert got["192.0.2.1"] == "network"  # the router, from the scan


def test_anomalies_on_a_synthetic_week(tmp_path):
    out = tmp_path / "seed-7"
    generate(out, seed=7, start_date="2026-10-01", hours=24 * 7)
    dns_rows = [
        {"ts": q["ts"], "src_ip": q["client_ip"], "domain": q["domain"], "status": q["status"]}
        for q in map(json.loads, (out / "dns" / "queries.jsonl").read_text().splitlines())
        if q["label"] != "protected"
    ]
    flow_rows = [
        {"ts": f["start"], "src_ip": f["src_ip"], "dst_ip": f["dst_ip"], "dst_port": f["dst_port"],
         "bytes_out": f["bytes_out"], "bytes_in": f["bytes_in"]}
        for f in map(json.loads, (out / "flows" / "flows.jsonl").read_text().splitlines())
        if f["label"] != "protected"
    ]  # fmt: skip
    found = detect(fill_missing_days(daily_features(dns_rows, flow_rows)), leave_one_out=True)
    flagged = {(a.device, a.feature) for a in found}
    assert ("192.0.2.30", "bytes_out") in flagged  # the family laptop's overnight upload
    exfil = next(a for a in found if a.feature == "bytes_out")
    assert exfil.severity == "high"
    iot = {"192.0.2.50", "192.0.2.51", "192.0.2.52", "192.0.2.70"}
    assert not {d for d, _ in flagged} & iot  # steady IoT check-ins are never anomalies
    assert all(a.device != "192.0.2.10" for a in found)
