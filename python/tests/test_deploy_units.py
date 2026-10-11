"""The Pi's systemd, tmpfiles, rsyslog, and logrotate files, rendered from config."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from helpers import write_config

from gnomehome.config import load_config
from gnomehome.deploy_units import RenderError, render_pi_files, write_files


@pytest.fixture
def files(tmp_path: Path) -> dict[str, str]:
    return render_pi_files(load_config(write_config(tmp_path)))


def test_every_template_renders_with_no_placeholders_left(files):
    assert set(files) == {
        "gnomehome-discover.service", "gnomehome-discover.timer",
        "gnomehome-scan.service", "gnomehome-scan.timer",
        "gnomehome-syslog.service", "gnomehome-syslog.timer",
        "gnomehome-enrich.service", "gnomehome-enrich.timer",
        "gnomehome-analyze.service", "gnomehome-analyze.timer",
        "gnomehome-flows.service", "gnomehome-flows.timer",
        "gnomehome-dnstail.service",
        "gnomehome-export.service", "gnomehome-export.timer",
        "tmpfiles-gnomehome.conf", "rsyslog-gnomehome.conf", "logrotate-gnomehome",
    }  # fmt: skip
    for name, content in files.items():
        assert "${" not in content, name


def test_services_run_the_venv_command_as_the_service_user(files):
    for job in ("discover", "scan", "syslog", "analyze", "flows"):
        unit = files[f"gnomehome-{job}.service"]
        assert f"ExecStart=/opt/gnomehome/.venv/bin/gnomehome {job}\n" in unit
        assert "User=gnomehome\n" in unit
        assert "Environment=GNOMEHOME_CONFIG=/etc/gnomehome/gnomehome.toml\n" in unit
        assert "NoNewPrivileges=yes" in unit and "ProtectSystem=strict" in unit
        assert "ReadWritePaths=/run/gnomehome /var/lib/gnomehome /var/lib/gnomehome/scans" in unit


def test_raw_socket_rights_only_for_the_nmap_jobs(files):
    for job in ("discover", "scan"):
        unit = files[f"gnomehome-{job}.service"]
        assert "AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN" in unit
        assert "SuccessExitStatus=75" in unit
    for job in ("syslog", "analyze", "flows", "dnstail", "enrich", "export"):
        unit = files[f"gnomehome-{job}.service"]
        assert "AmbientCapabilities" not in unit, job
        assert "CapabilityBoundingSet=\n" in unit, job
    syslog = files["gnomehome-syslog.service"]
    assert "CapabilityBoundingSet=\n" in syslog
    assert "PrivateNetwork=yes" in syslog
    assert "/var/log/gnomehome" in syslog  # may read the router log


def test_timers_follow_the_config_schedules(tmp_path: Path):
    path = write_config(tmp_path, {"discovery_every_minutes = 10": "discovery_every_minutes = 7"})
    files = render_pi_files(load_config(path))
    assert "OnUnitActiveSec=7min" in files["gnomehome-discover.timer"]
    assert "OnUnitActiveSec=240min" in files["gnomehome-scan.timer"]
    assert "OnUnitActiveSec=1min" in files["gnomehome-syslog.timer"]
    assert "OnUnitActiveSec=60min" in files["gnomehome-analyze.timer"]
    assert "OnUnitActiveSec=1min" in files["gnomehome-flows.timer"]


def test_dns_tailer_is_long_running_offline_and_small(files):
    unit = files["gnomehome-dnstail.service"]
    assert "Type=simple" in unit
    assert "ExecStart=/opt/gnomehome/bin/gnomehome-dnstail\n" in unit
    assert "SupplementaryGroups=pihole\n" in unit
    assert "PrivateNetwork=yes" in unit
    assert "ReadOnlyPaths=/etc/gnomehome /opt/gnomehome /var/log/pihole\n" in unit
    # The tighter limit comes after the shared 256M one, so it wins.
    assert unit.rindex("MemoryMax=64M") > unit.index("MemoryMax=256M")
    assert "WantedBy=multi-user.target" in unit


def test_flows_may_reach_only_the_router(files):
    unit = files["gnomehome-flows.service"]
    assert "IPAddressAllow=192.0.2.1\nIPAddressDeny=any\n" in unit
    assert "PrivateNetwork" not in unit


def test_rsyslog_accepts_only_the_router_and_logrotate_keeps_retention(files):
    rsyslog = files["rsyslog-gnomehome.conf"]
    assert 'if $fromhost-ip == "192.0.2.1" then' in rsyslog
    assert 'file="/var/log/gnomehome/router.log"' in rsyslog
    assert 'fileGroup="gnomehome"' in rsyslog
    logrotate = files["logrotate-gnomehome"]
    assert logrotate.startswith("# Rendered")
    assert "/var/log/gnomehome/router.log {" in logrotate
    assert "rotate 30" in logrotate


def test_tmpfiles_creates_the_writable_dirs(files):
    assert "d /var/lib/gnomehome 0750 gnomehome gnomehome -" in files["tmpfiles-gnomehome.conf"]
    assert "d /run/gnomehome 0750 gnomehome gnomehome -" in files["tmpfiles-gnomehome.conf"]


def test_mac_table_has_no_deploy_keys(tmp_path: Path):
    with pytest.raises(RenderError, match="install_dir"):
        render_pi_files(load_config(write_config(tmp_path)), platform="mac")


def test_missing_router_ip_is_reported(tmp_path: Path):
    config = load_config(write_config(tmp_path, {'router_ip = "192.0.2.1"\n': ""}))
    with pytest.raises(RenderError, match="router_ip"):
        render_pi_files(config)


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="systemd-analyze not installed")
def test_units_pass_systemd_analyze_verify(files, tmp_path: Path):
    out = tmp_path / "units"
    paths = [p for p in write_files(files, out) if p.suffix in (".service", ".timer")]
    proc = subprocess.run(
        ["systemd-analyze", "verify", "--man=no", *map(str, paths)],
        capture_output=True,
        text=True,
        check=False,
    )
    # The gnomehome command isn't installed here, so that complaint is expected.
    # Anything else (unknown keys, bad values, syntax) fails the test.
    problems = [
        line
        for line in (proc.stdout + proc.stderr).splitlines()
        if line.strip() and "is not executable: No such file or directory" not in line
    ]
    assert problems == []


def test_enrichment_runs_daily_and_scores_even_if_a_feed_fails(files):
    assert "OnCalendar=*-*-* 03:30:00" in files["gnomehome-enrich.timer"]
    unit = files["gnomehome-enrich.service"]
    assert "ExecStart=-/opt/gnomehome/.venv/bin/gnomehome enrich" in unit
    assert "ExecStart=-/opt/gnomehome/.venv/bin/gnomehome intel" in unit
    assert "ExecStart=/opt/gnomehome/.venv/bin/gnomehome score" in unit
    assert "AmbientCapabilities" not in unit


def test_export_runs_nightly_and_uploads_only_when_configured(files):
    assert "OnCalendar=*-*-* 02:00:00" in files["gnomehome-export.timer"]
    unit = files["gnomehome-export.service"]
    assert "ExecStart=/opt/gnomehome/.venv/bin/gnomehome export\n" in unit
    assert "ExecStart=/opt/gnomehome/.venv/bin/gnomehome upload --send\n" in unit
