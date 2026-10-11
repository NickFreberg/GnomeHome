"""The nmap job, driven by a fake nmap: proves protected assets are never targeted.

No real nmap runs here (see test_nmap_integration.py for the loopback-only test).
"""

from __future__ import annotations

import fcntl
import json
import shutil
import sqlite3
from pathlib import Path

import pytest
from helpers import EXAMPLE_PROTECTED, FIXTURES, write_config

from gnomehome.audit import verify
from gnomehome.collectors.arp_cache import ArpEntry
from gnomehome.collectors.nmap_discovery import (
    GuardViolation,
    ScanRefused,
    discovery_argv,
    run_scan,
    service_argv,
    target_problems,
)
from gnomehome.config import load_config
from gnomehome.db import open_database
from gnomehome.protected import ProtectedAssets, ProtectedListError

NMAP = FIXTURES / "nmap"
PRIVATE_TARGET = 'scan_targets = ["10.99.0.0/24"]'  # hygiene: allow (fake private target)


class FakeNmapRunner:
    """Writes fixture XML instead of scanning, and remembers what it was asked to do."""

    def __init__(self, discovery: str = "discovery.xml", service: str = "service.xml", hook=None):
        self.discovery = NMAP / discovery
        self.service = NMAP / service
        self.hook = hook
        self.calls: list[list[str]] = []
        self.exclude_contents: list[list[str]] = []
        self.hosts_contents: list[list[str]] = []

    def run(self, argv: list[str], xml_path: Path) -> None:
        self.calls.append(list(argv))
        self.exclude_contents.append(
            Path(argv[argv.index("--excludefile") + 1]).read_text().split()
        )
        if "-iL" in argv:
            self.hosts_contents.append(Path(argv[argv.index("-iL") + 1]).read_text().split())
        shutil.copy(self.discovery if "-sn" in argv else self.service, xml_path)
        if self.hook:
            self.hook(argv)

    def version(self) -> str:
        return "7.95-fake"


@pytest.fixture
def config(tmp_path: Path):
    path = write_config(tmp_path, {'scan_targets = ["192.0.2.0/24"]': PRIVATE_TARGET})
    shutil.copy(EXAMPLE_PROTECTED, path.parent / "protected_assets.yaml")
    return load_config(path)


class RecordingNotifier:
    """Stands in for alerts so tests never pop real notifications."""

    def __init__(self) -> None:
        self.messages: list[str] = []

    def notify(self, message: str, **_: object) -> None:
        self.messages.append(message)


def scan(config, runner=None, arp=(), notifier=None, **kwargs):
    runner = runner or FakeNmapRunner()
    kwargs.setdefault("allow_example_values", True)  # tests use the fake example list
    result = run_scan(
        config,
        runner=runner,
        arp_reader=lambda: list(arp),
        say=lambda _: None,
        notifier=notifier or RecordingNotifier(),
        **kwargs,
    )
    return result, runner


def db(config) -> sqlite3.Connection:
    conn = sqlite3.connect(config.paths.db_path)
    conn.row_factory = sqlite3.Row
    return conn


# ------------------------------------------------------------------ happy path


def test_service_scan_writes_assets_and_services(config):
    result, runner = scan(config)
    assert len(runner.calls) == 2
    assert result.hosts_up == 3  # the scanner itself has no MAC and is skipped
    assert len(result.new_devices) == 3
    conn = db(config)
    assets = {r["mac"]: r for r in conn.execute("SELECT * FROM asset")}
    assert set(assets) == {"00:00:5e:00:53:a1", "00:00:5e:00:53:b2", "02:00:5e:00:53:c3"}
    router = assets["00:00:5e:00:53:a1"]
    assert router["vendor"] == "Example Router Co"
    assert router["last_ip"] == "192.0.2.1"
    assert router["os_guess"] == "Linux 4.15 - 5.19"
    assert router["device_type"] == "WAP"
    assert assets["02:00:5e:00:53:c3"]["mac_randomized"] == 1
    services = conn.execute(
        "SELECT port, product, cpe FROM service JOIN asset ON asset.id = service.asset_id "
        "WHERE asset.mac = '00:00:5e:00:53:a1' ORDER BY port"
    ).fetchall()
    assert [tuple(s) for s in services] == [
        (53, "dnsmasq", "cpe:/a:thekelleys:dnsmasq:2.90"),
        (80, "Example httpd", None),
        (443, "Example httpd", None),
    ]
    run = conn.execute("SELECT * FROM scan_run").fetchone()
    assert run["status"] == "success" and run["hosts_up"] == 3 and run["services_seen"] == 5


def test_scan_is_audited_and_chain_verifies(config):
    scan(config)
    conn = sqlite3.connect(config.paths.db_path)
    actions = [r[0] for r in conn.execute("SELECT action FROM audit_log ORDER BY seq")]
    assert actions == ["scan.service.start", "scan.service.finish"]
    assert verify(conn).ok


def test_rescan_updates_last_seen_but_not_first_seen(config):
    scan(config)
    first = dict(db(config).execute("SELECT mac, first_seen FROM asset").fetchall())
    result, _ = scan(config)
    assert result.new_devices == []
    rows = db(config).execute("SELECT mac, first_seen, last_seen FROM asset").fetchall()
    assert all(r["first_seen"] == first[r["mac"]] for r in rows)
    assert all(r["last_seen"] >= r["first_seen"] for r in rows)


def test_discovery_mode_runs_one_phase_and_stores_no_services(config):
    result, runner = scan(config, mode="discovery")
    assert len(runner.calls) == 1 and "-sn" in runner.calls[0]
    assert result.hosts_up == 3
    assert db(config).execute("SELECT COUNT(*) FROM service").fetchone()[0] == 0


# ------------------------------------------------------------------ never touch protected assets


def test_every_nmap_call_uses_the_exclude_file_with_every_protected_ip(config):
    _, runner = scan(config)
    for argv, excluded in zip(runner.calls, runner.exclude_contents, strict=True):
        assert "--excludefile" in argv
        assert "192.0.2.10" in excluded


def test_service_scan_only_targets_hosts_found_in_discovery(config):
    _, runner = scan(config)
    assert runner.hosts_contents == [["192.0.2.1", "192.0.2.20", "192.0.2.30"]]
    assert "-Pn" in runner.calls[1]


def test_protected_host_in_discovery_stops_before_service_scan(config):
    runner = FakeNmapRunner(discovery="discovery_with_protected.xml")
    with pytest.raises(GuardViolation, match="Work laptop"):
        scan(config, runner=runner)
    assert len(runner.calls) == 1  # no service scan
    conn = db(config)
    assert conn.execute("SELECT COUNT(*) FROM asset").fetchone()[0] == 0  # nothing stored
    assert conn.execute("SELECT status FROM scan_run").fetchone()[0] == "aborted"
    violation = conn.execute(
        "SELECT target, details FROM audit_log WHERE action = 'guard.violation'"
    ).fetchone()
    assert violation["target"] == "protected:Work laptop"
    audit_text = " ".join(str(v) for row in conn.execute("SELECT * FROM audit_log") for v in row)
    assert "192.0.2.99" not in audit_text and "00:00:5e:00:53:01" not in audit_text.lower()
    assert verify(conn).ok


def test_drift_ip_from_arp_cache_is_excluded(config):
    arp = [ArpEntry("192.0.2.77", "00:00:5e:00:53:02", "en0")]  # laptop's dock at an odd IP
    result, runner = scan(config, arp=arp)
    assert "192.0.2.77" in result.excluded
    assert all("192.0.2.77" in excluded for excluded in runner.exclude_contents)
    drift = (
        db(config)
        .execute("SELECT target FROM audit_log WHERE action = 'guard.drift_detected'")
        .fetchone()
    )
    assert drift[0] == "protected:Work laptop"


def test_tampered_exclude_file_stops_the_next_phase(config):
    def wipe_exclusions(argv):
        if "-sn" in argv:
            Path(argv[argv.index("--excludefile") + 1]).write_text("")

    runner = FakeNmapRunner(hook=wipe_exclusions)
    with pytest.raises(GuardViolation, match="exclude file is missing"):
        scan(config, runner=runner)
    assert len(runner.calls) == 1
    assert db(config).execute("SELECT COUNT(*) FROM asset").fetchone()[0] == 0
    assert db(config).execute("SELECT status FROM scan_run").fetchone()[0] == "aborted"
    reasons = (
        db(config)
        .execute("SELECT details FROM audit_log WHERE action = 'guard.violation'")
        .fetchall()
    )
    assert len(reasons) == 1 and "exclude file is missing" in reasons[0][0]


def test_protected_rows_from_before_are_scrubbed_at_startup(config):
    scan(config)
    conn = db(config)
    # Pretend the router turns out to be a work device: add it to the list.
    listed = Path(config.paths.protected_assets)
    listed.write_text(
        listed.read_text().replace(
            '      - "00:00:5e:00:53:02"   # Dock / Ethernet adapter (FAKE)',
            '      - "00:00:5e:00:53:02"\n      - "00:00:5e:00:53:a1"',
        )
    )
    with pytest.raises(GuardViolation):  # the router now shows up as protected in discovery
        scan(config)
    router = conn.execute("SELECT * FROM asset WHERE mac = '00:00:5e:00:53:a1'").fetchone()
    assert router["protected"] == 1 and router["vendor"] is None
    services = conn.execute(
        "SELECT COUNT(*) FROM service WHERE asset_id = ?", (router["id"],)
    ).fetchone()[0]
    assert services == 0


# ------------------------------------------------------------------ refusals (nothing sent)


def test_missing_protected_list_refuses(config):
    Path(config.paths.protected_assets).unlink()
    runner = FakeNmapRunner()
    with pytest.raises(ProtectedListError):
        scan(config, runner=runner)
    assert runner.calls == []


def test_example_values_are_refused_for_real_scans(config):
    runner = FakeNmapRunner()
    with pytest.raises(ScanRefused, match="example values"):
        scan(config, runner=runner, allow_example_values=False)
    assert runner.calls == []


def test_example_targets_are_refused(tmp_path):
    path = write_config(tmp_path)  # example config: TEST-NET target
    shutil.copy(EXAMPLE_PROTECTED, path.parent / "protected_assets.yaml")
    runner = FakeNmapRunner()
    with pytest.raises(ScanRefused, match="not a private home network"):
        scan(load_config(path), runner=runner)
    assert runner.calls == []


@pytest.mark.parametrize(
    ("target", "message"),
    [
        ("8.8.8.0/24", "not a private"),
        ("192.0.2.0/24", "not a private"),
        ("10.0.0.0/16", "more than max_target_hosts"),  # hygiene: allow
        ("2001:db8::/64", "only IPv4"),
    ],
)
def test_target_problems(target, message):
    assets = ProtectedAssets.load(EXAMPLE_PROTECTED)
    assert any(message in p for p in target_problems([target], assets, 1024))


def test_protected_ip_as_a_target_is_refused():
    assets = ProtectedAssets.parse(
        'version: 1\nprotected:\n  - label: L\n    reason: r\n    macs: ["00:00:5e:00:53:01"]\n'
        '    ips: ["10.99.0.10"]\n'  # hygiene: allow
    )
    single = "10.99.0.10/32"  # hygiene: allow
    assert any("protected" in p for p in target_problems([single], assets, 1024))
    assert target_problems(["10.99.0.0/24"], assets, 1024) == []  # hygiene: allow


def test_concurrent_scans_are_refused(config):
    config.paths.run_dir.mkdir(parents=True, exist_ok=True)
    with open(config.paths.run_dir / "scan.lock", "w") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        runner = FakeNmapRunner()
        with pytest.raises(ScanRefused, match="already running"):
            scan(config, runner=runner)
        assert runner.calls == []


# ------------------------------------------------------------------ dry run and command lines


def test_dry_run_sends_nothing_and_writes_nothing(config):
    runner = FakeNmapRunner()
    result, _ = scan(config, runner=runner, dry_run=True, allow_example_values=False)
    assert runner.calls == []
    assert not config.paths.db_path.exists()
    assert result.excluded == ["192.0.2.10"]
    assert len(result.commands) == 2
    assert any("example values" in p for p in result.problems)


def test_mac_commands_use_sudo_and_never_lose_the_exclude_file(config):
    exclude, hosts, out = Path("/x/exclude"), Path("/x/hosts"), Path("/x/out.xml")
    phase1 = discovery_argv(config, exclude, out)
    phase2 = service_argv(config, exclude, hosts, out)
    assert phase1[:2] == ["/usr/bin/sudo", "/opt/homebrew/bin/nmap"]
    assert phase1[2] == "-sn"
    assert phase1[-1] == "10.99.0.0/24"  # hygiene: allow
    for argv in (phase1, phase2):
        assert argv[argv.index("--excludefile") + 1] == "/x/exclude"
        assert argv[argv.index("-e") + 1] == "en0"
        assert "-n" in argv
    assert {"-sS", "-sV", "-O", "-Pn"} <= set(phase2)
    assert phase2[phase2.index("-iL") + 1] == "/x/hosts"


def test_pi_commands_use_capabilities_not_sudo(tmp_path):
    path = write_config(
        tmp_path,
        {'platform = "mac"': 'platform = "pi"', 'scan_targets = ["192.0.2.0/24"]': PRIVATE_TARGET},
    )
    argv = discovery_argv(load_config(path), Path("/x/e"), Path("/x/o"))
    assert argv[:2] == ["/usr/bin/nmap", "--privileged"]
    assert "sudo" not in " ".join(argv)


def test_scan_targets_are_recorded_in_scan_run(config):
    scan(config)
    targets = db(config).execute("SELECT targets FROM scan_run").fetchone()[0]
    assert json.loads(targets) == ["10.99.0.0/24"]  # hygiene: allow


# ------------------------------------------------------------------ new-device alerts


def test_first_scan_is_the_baseline_and_raises_no_alerts(config):
    notifier = RecordingNotifier()
    result, _ = scan(config, notifier=notifier)
    assert result.baseline and len(result.new_devices) == 3
    assert result.incidents_opened == 0 and notifier.messages == []
    assert db(config).execute("SELECT COUNT(*) FROM incident").fetchone()[0] == 0


def test_devices_appearing_after_the_learning_window_raise_one_alert(config):
    conn = open_database(config.paths.db_path)  # an inventory that started two days ago
    conn.execute(
        "INSERT INTO asset (mac, first_seen, last_seen) VALUES "
        "('00:00:5e:00:53:77', '2026-10-01T00:00:00.000Z', '2026-10-01T00:00:00.000Z')"
    )
    conn.close()
    notifier = RecordingNotifier()
    result, _ = scan(config, notifier=notifier)
    assert not result.baseline and result.incidents_opened == 3
    assert len(notifier.messages) == 1  # one banner per run, not per device
    titles = [r[0] for r in db(config).execute("SELECT title FROM incident ORDER BY id")]
    assert "New device on the network (Example Router Co)" in titles
