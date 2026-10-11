from pathlib import Path

import pytest
from helpers import write_config

from gnomehome.config import ConfigError, load_config, platform_mismatch


def test_example_config_loads_with_mac_paths_relative_to_config_dir(config_path: Path):
    config = load_config(config_path)
    root = config_path.parent.parent
    assert config.platform == "mac"
    assert config.paths.data_dir == root / "data"
    assert config.paths.db_path == root / "data" / "gnomehome.sqlite3"
    assert config.paths.protected_assets == config_path.parent / "protected_assets.yaml"
    assert config.paths.interface == "en0"
    assert config.paths.nmap_privilege == "sudo"
    assert config.paths.arp_command == ("/usr/sbin/arp", "-an")
    assert config.paths.pihole_log is None
    assert config.network.scan_targets == ("192.0.2.0/24",)


def test_platform_pi_selects_pi_table(tmp_path: Path):
    path = write_config(tmp_path, {'platform = "mac"': 'platform = "pi"'})
    config = load_config(path)
    assert config.platform == "pi"
    assert config.paths.data_dir == Path("/var/lib/gnomehome")
    assert config.paths.interface == "eth0"
    assert config.paths.nmap_privilege == "capabilities"
    assert config.paths.pihole_log == Path("/var/log/pihole/pihole.log")


def test_schedules_and_retention_come_from_config(config_path: Path):
    config = load_config(config_path)
    assert config.schedules.discovery_every_minutes == 10
    assert config.schedules.service_scan_every_minutes == 240
    assert config.retention.dns_days == 30
    assert config.retention.scan_days == 90


def test_env_var_overrides_location(config_path: Path, monkeypatch):
    monkeypatch.setenv("GNOMEHOME_CONFIG", str(config_path))
    assert load_config().path == config_path.resolve()


def test_missing_file_explains_how_to_fix(tmp_path: Path):
    with pytest.raises(ConfigError, match="just setup"):
        load_config(tmp_path / "nope.toml")


def test_tilde_expands_to_home(tmp_path: Path):
    path = write_config(tmp_path, {'data_dir = "../data"': 'data_dir = "~/gnomehome-data"'})
    assert load_config(path).paths.data_dir == Path.home() / "gnomehome-data"


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        ('platform = "mac"', 'platform = "windows"', "platform must be one of"),
        ("top_ports = 1000", "top_portz = 1000", "unknown key"),
        ('interface = "en0"', 'interface = "en0"\nnmap_extra_args = "-sU"', "unknown key"),
        ("[api]", "[apii]", "unknown key"),
        ('interface = "en0"', 'interface = "-oN /tmp/x"', "not a valid interface"),
        ('nmap_path = "/opt/homebrew/bin/nmap"', 'nmap_path = "nmap"', "absolute path"),
        ('arp_command = ["/usr/sbin/arp", "-an"]', 'arp_command = ["arp", "-an"]', "absolute"),
        ('nmap_privilege = "sudo"', 'nmap_privilege = "root"', "nmap_privilege"),
        ("timing = 3", "timing = 9", "between 0 and 5"),
        ("top_ports = 1000", "top_ports = true", "must be a int"),
        ('host_timeout = "5m"', 'host_timeout = "5 minutes"', "host_timeout"),
        ('scan_targets = ["192.0.2.0/24"]', 'scan_targets = ["not-a-net"]', "not an IP"),
        ('scan_targets = ["192.0.2.0/24"]', "scan_targets = []", "non-empty"),
        ('enrich_daily_at = "03:30"', 'enrich_daily_at = "3:30am"', "24-hour"),
        ('self_assessment_weekly = "Sun 09:00"', 'self_assessment_weekly = "Sunday"', "Sun 09:00"),
    ],
)
def test_invalid_values_are_rejected(tmp_path: Path, old: str, new: str, message: str):
    path = write_config(tmp_path, {old: new})
    with pytest.raises(ConfigError, match=message):
        load_config(path)


def test_missing_active_platform_table_is_an_error(tmp_path: Path):
    path = write_config(tmp_path, {"[platforms.mac]": "[platforms.macbook]"})
    with pytest.raises(ConfigError):
        load_config(path)


def test_broken_inactive_platform_table_is_caught_early(tmp_path: Path):
    # platform = "mac", but the Pi table has a typo: caught now, not on deploy day.
    path = write_config(tmp_path, {'interface = "eth0"': 'interfac = "eth0"'})
    with pytest.raises(ConfigError, match=r"platforms\.pi"):
        load_config(path)


def test_platform_mismatch_warning(config_path: Path, monkeypatch):
    config = load_config(config_path)
    monkeypatch.setattr("sys.platform", "darwin")
    assert platform_mismatch(config) is None
    monkeypatch.setattr("sys.platform", "linux")
    assert "mac" in (platform_mismatch(config) or "")
