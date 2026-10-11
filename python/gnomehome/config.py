"""Load and validate GnomeHome's one config file.

Every path, interface name, and schedule lives in ``config/gnomehome.toml``.
The ``platform`` key (``"mac"`` or ``"pi"``) picks which ``[platforms.<name>]``
table supplies the machine-specific values, so the code never hardcodes a
Linux (or macOS) path.

Rules:

* Relative paths resolve against the folder that holds the config file, and
  ``~`` means the home folder.
* ``GNOMEHOME_CONFIG`` overrides the config file location.
* Unknown keys are errors, so a typo can't silently fall back to a default.
* Anything that ends up on an nmap command line is validated here, and there
  is deliberately no way to pass raw extra arguments to nmap.
"""

from __future__ import annotations

import ipaddress
import os
import re
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ENV_VAR = "GNOMEHOME_CONFIG"
DEFAULT_CONFIG_PATH = Path("config") / "gnomehome.toml"
PLATFORMS = ("mac", "pi")
NMAP_PRIVILEGE_MODES = ("sudo", "capabilities", "none")
ALERT_CHANNELS = ("log", "macos")
SCHEDULERS = ("manual", "launchd", "systemd")

_INTERFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,14}$")
_NMAP_TIME_RE = re.compile(r"^[1-9][0-9]*(ms|s|m|h)$")
_DAILY_RE = re.compile(r"^([01][0-9]|2[0-3]):[0-5][0-9]$")
_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_WEEKLY_RE = re.compile(r"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ([01][0-9]|2[0-3]):[0-5][0-9]$")


class ConfigError(Exception):
    """The config file is missing or invalid."""


@dataclass(frozen=True)
class NetworkConfig:
    #: Subnets the scan job may target. The scan job further requires RFC1918.
    scan_targets: tuple[str, ...]
    #: What counts as "inside the house" for analytics.
    lan_cidrs: tuple[str, ...]
    #: The router's LAN address: the only sender rsyslog accepts on the Pi.
    router_ip: str | None = None


@dataclass(frozen=True)
class ScanConfig:
    top_ports: int = 1000
    service_detection: bool = True
    os_detection: bool = True
    timing: int = 3
    host_timeout: str = "5m"
    max_retries: int = 2
    reverse_dns: bool = False
    max_target_hosts: int = 1024


@dataclass(frozen=True)
class SchedulesConfig:
    discovery_every_minutes: int = 10
    service_scan_every_minutes: int = 240
    syslog_every_minutes: int = 1
    enrich_daily_at: str = "03:30"
    upload_nightly_at: str = "02:00"
    retention_daily_at: str = "04:00"
    self_assessment_weekly: str = "Sun 09:00"


@dataclass(frozen=True)
class RetentionConfig:
    dns_days: int = 30
    syslog_days: int = 30
    flow_days: int = 30
    scan_days: int = 90
    dhcp_days: int = 90


@dataclass(frozen=True)
class AlertsConfig:
    #: Devices first seen this soon after the inventory started are the baseline: no alert.
    learning_minutes: int = 60


@dataclass(frozen=True)
class EnrichmentConfig:
    #: Look each software version up at NVD again after this long (the plan: daily).
    nvd_refresh_hours: int = 24
    #: Refresh the KEV catalog after this long.
    feed_refresh_hours: int = 20


@dataclass(frozen=True)
class ApiConfig:
    bind: str = "127.0.0.1:8787"


@dataclass(frozen=True)
class SyntheticConfig:
    seed: int = 42
    days: int = 1
    start_date: str = "2026-10-05"


@dataclass(frozen=True)
class PlatformConfig:
    """Everything that differs between the Mac and the Pi."""

    data_dir: Path
    db_path: Path
    dev_db_path: Path
    run_dir: Path
    scans_dir: Path
    synthetic_dir: Path
    protected_assets: Path
    interface: str
    nmap_path: Path
    nmap_privilege: str
    sudo_path: Path
    arp_command: tuple[str, ...]
    pihole_ftl_db: Path
    pihole_log: Path | None
    scheduler: str
    alert_channels: tuple[str, ...] = ("log",)
    osascript_path: Path | None = None
    #: Where rsyslog writes the router's messages (Pi only; router syslog goes to the Pi).
    router_syslog_path: Path | None = None
    # Deploy-only keys, used to render the Pi's systemd units.
    install_dir: Path | None = None
    service_user: str | None = None
    config_file: Path | None = None
    #: A file holding the free NVD API key (never in git). Optional: without it,
    #: lookups are slower (NVD allows 5 requests per 30 seconds).
    nvd_api_key_file: Path | None = None


@dataclass(frozen=True)
class Config:
    path: Path
    platform: str
    network: NetworkConfig
    paths: PlatformConfig
    scan: ScanConfig = field(default_factory=ScanConfig)
    schedules: SchedulesConfig = field(default_factory=SchedulesConfig)
    retention: RetentionConfig = field(default_factory=RetentionConfig)
    alerts: AlertsConfig = field(default_factory=AlertsConfig)
    enrichment: EnrichmentConfig = field(default_factory=EnrichmentConfig)
    api: ApiConfig = field(default_factory=ApiConfig)
    synthetic: SyntheticConfig = field(default_factory=SyntheticConfig)
    #: Every platform table, so the Pi's files can be rendered on the Mac.
    platforms: dict[str, PlatformConfig] = field(default_factory=dict)


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------


def resolve_config_path(path: str | os.PathLike[str] | None = None) -> Path:
    """Explicit argument, then ``$GNOMEHOME_CONFIG``, then ``config/gnomehome.toml``."""
    if path is not None:
        return Path(path)
    env = os.environ.get(ENV_VAR)
    if env:
        return Path(env)
    return DEFAULT_CONFIG_PATH


def load_config(path: str | os.PathLike[str] | None = None) -> Config:
    config_path = resolve_config_path(path)
    try:
        raw = config_path.read_bytes()
    except FileNotFoundError:
        raise ConfigError(
            f"config file not found: {config_path}. Run `just setup` to create it from "
            f"config/gnomehome.example.toml, or set {ENV_VAR}."
        ) from None
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{config_path}: invalid TOML: {exc}") from None
    return parse_config(data, config_path)


def parse_config(data: dict[str, Any], config_path: Path) -> Config:
    """Validate a parsed TOML document. Split out from loading for tests."""
    _reject_unknown(
        data,
        {
            "platform",
            "network",
            "scan",
            "schedules",
            "retention",
            "alerts",
            "enrichment",
            "api",
            "synthetic",
            "platforms",
        },
        "top level",
    )
    platform = data.get("platform")
    if platform not in PLATFORMS:
        raise ConfigError(f"platform must be one of {PLATFORMS}, got {platform!r}")

    base_dir = config_path.resolve().parent
    platforms = _table(data, "platforms", required=True)
    _reject_unknown(platforms, set(PLATFORMS), "[platforms]")
    if platform not in platforms:
        raise ConfigError(f'platform = "{platform}" but there is no [platforms.{platform}] table')
    # Validate every platform table present, not just the active one, so a
    # broken Pi section is caught on the Mac before deploy day.
    parsed = {
        name: _parse_platform(_table(platforms, name, required=True), name, base_dir)
        for name in platforms
    }

    return Config(
        path=config_path.resolve(),
        platform=platform,
        network=_parse_network(_table(data, "network", required=True)),
        paths=parsed[platform],
        scan=_parse_scan(_table(data, "scan")),
        schedules=_parse_schedules(_table(data, "schedules")),
        retention=_parse_retention(_table(data, "retention")),
        alerts=_parse_alerts(_table(data, "alerts")),
        enrichment=_parse_enrichment(_table(data, "enrichment")),
        api=_parse_api(_table(data, "api")),
        synthetic=_parse_synthetic(_table(data, "synthetic")),
        platforms=parsed,
    )


# --------------------------------------------------------------------------
# Section parsers
# --------------------------------------------------------------------------


def _parse_network(table: dict[str, Any]) -> NetworkConfig:
    where = "[network]"
    _reject_unknown(table, {"scan_targets", "lan_cidrs", "router_ip"}, where)
    router_ip = _get(table, "router_ip", str, None, where)
    if router_ip is not None:
        try:
            router_ip = str(ipaddress.IPv4Address(router_ip))
        except ValueError:
            raise ConfigError(f"{where} router_ip {router_ip!r} is not an IPv4 address") from None
    return NetworkConfig(
        scan_targets=_cidr_list(table, "scan_targets", where),
        lan_cidrs=_cidr_list(table, "lan_cidrs", where),
        router_ip=router_ip,
    )


def _parse_scan(table: dict[str, Any]) -> ScanConfig:
    where = "[scan]"
    d = ScanConfig()
    _reject_unknown(table, set(d.__dataclass_fields__), where)
    host_timeout = _get(table, "host_timeout", str, d.host_timeout, where)
    if not _NMAP_TIME_RE.match(host_timeout):
        raise ConfigError(f'{where} host_timeout must look like "30s", "5m", or "1h"')
    return ScanConfig(
        top_ports=_int_range(table, "top_ports", d.top_ports, 1, 65535, where),
        service_detection=_get(table, "service_detection", bool, d.service_detection, where),
        os_detection=_get(table, "os_detection", bool, d.os_detection, where),
        timing=_int_range(table, "timing", d.timing, 0, 5, where),
        host_timeout=host_timeout,
        max_retries=_int_range(table, "max_retries", d.max_retries, 0, 10, where),
        reverse_dns=_get(table, "reverse_dns", bool, d.reverse_dns, where),
        max_target_hosts=_int_range(table, "max_target_hosts", d.max_target_hosts, 1, 65536, where),
    )


def _parse_schedules(table: dict[str, Any]) -> SchedulesConfig:
    where = "[schedules]"
    d = SchedulesConfig()
    _reject_unknown(table, set(d.__dataclass_fields__), where)
    values: dict[str, Any] = {}
    for key in ("discovery_every_minutes", "service_scan_every_minutes", "syslog_every_minutes"):
        values[key] = _int_range(table, key, getattr(d, key), 1, 7 * 24 * 60, where)
    for key in ("enrich_daily_at", "upload_nightly_at", "retention_daily_at"):
        value = _get(table, key, str, getattr(d, key), where)
        if not _DAILY_RE.match(value):
            raise ConfigError(f'{where} {key} must be a 24-hour time like "03:30"')
        values[key] = value
    weekly = _get(table, "self_assessment_weekly", str, d.self_assessment_weekly, where)
    if not _WEEKLY_RE.match(weekly):
        raise ConfigError(f'{where} self_assessment_weekly must look like "Sun 09:00"')
    values["self_assessment_weekly"] = weekly
    return SchedulesConfig(**values)


def _parse_retention(table: dict[str, Any]) -> RetentionConfig:
    where = "[retention]"
    d = RetentionConfig()
    _reject_unknown(table, set(d.__dataclass_fields__), where)
    return RetentionConfig(
        **{
            key: _int_range(table, key, getattr(d, key), 1, 3650, where)
            for key in d.__dataclass_fields__
        }
    )


def _parse_alerts(table: dict[str, Any]) -> AlertsConfig:
    where = "[alerts]"
    _reject_unknown(table, {"learning_minutes"}, where)
    default = AlertsConfig().learning_minutes
    return AlertsConfig(
        learning_minutes=_int_range(table, "learning_minutes", default, 0, 30 * 24 * 60, where)
    )


def _parse_enrichment(table: dict[str, Any]) -> EnrichmentConfig:
    where = "[enrichment]"
    d = EnrichmentConfig()
    _reject_unknown(table, set(d.__dataclass_fields__), where)
    return EnrichmentConfig(
        nvd_refresh_hours=_int_range(
            table, "nvd_refresh_hours", d.nvd_refresh_hours, 1, 24 * 30, where
        ),
        feed_refresh_hours=_int_range(
            table, "feed_refresh_hours", d.feed_refresh_hours, 1, 24 * 7, where
        ),
    )


def _parse_api(table: dict[str, Any]) -> ApiConfig:
    where = "[api]"
    _reject_unknown(table, {"bind"}, where)
    return ApiConfig(bind=_get(table, "bind", str, ApiConfig().bind, where))


def _parse_synthetic(table: dict[str, Any]) -> SyntheticConfig:
    where = "[synthetic]"
    d = SyntheticConfig()
    _reject_unknown(table, set(d.__dataclass_fields__), where)
    start_date = _get(table, "start_date", str, d.start_date, where)
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", start_date):
        raise ConfigError(f'{where} start_date must look like "2026-10-05"')
    return SyntheticConfig(
        seed=_get(table, "seed", int, d.seed, where),
        days=_int_range(table, "days", d.days, 1, 30, where),
        start_date=start_date,
    )


_PLATFORM_PATH_KEYS = (
    "data_dir",
    "db_path",
    "dev_db_path",
    "run_dir",
    "scans_dir",
    "synthetic_dir",
    "protected_assets",
    "pihole_ftl_db",
)


def _parse_platform(table: dict[str, Any], name: str, base_dir: Path) -> PlatformConfig:
    where = f"[platforms.{name}]"
    _reject_unknown(
        table,
        {
            *_PLATFORM_PATH_KEYS,
            "interface",
            "nmap_path",
            "nmap_privilege",
            "sudo_path",
            "arp_command",
            "pihole_log",
            "scheduler",
            "alert_channels",
            "osascript_path",
            "router_syslog_path",
            "install_dir",
            "service_user",
            "config_file",
            "nvd_api_key_file",
        },
        where,
    )
    paths = {
        key: _resolve(_require(table, key, str, where), base_dir) for key in _PLATFORM_PATH_KEYS
    }

    interface = _require(table, "interface", str, where)
    if not _INTERFACE_RE.match(interface):
        raise ConfigError(f"{where} interface {interface!r} is not a valid interface name")

    nmap_privilege = _require(table, "nmap_privilege", str, where)
    if nmap_privilege not in NMAP_PRIVILEGE_MODES:
        raise ConfigError(f"{where} nmap_privilege must be one of {NMAP_PRIVILEGE_MODES}")

    scheduler = _require(table, "scheduler", str, where)
    if scheduler not in SCHEDULERS:
        raise ConfigError(f"{where} scheduler must be one of {SCHEDULERS}")

    arp_command = table.get("arp_command")
    if (
        not isinstance(arp_command, list)
        or not arp_command
        or not all(isinstance(part, str) and part for part in arp_command)
    ):
        raise ConfigError(f'{where} arp_command must be a list like ["/usr/sbin/arp", "-an"]')

    arp_binary = _absolute_str(arp_command[0], f"{where} arp_command[0]")

    pihole_log = table.get("pihole_log")
    if pihole_log is not None and not isinstance(pihole_log, str):
        raise ConfigError(f"{where} pihole_log must be a string path")

    channels = table.get("alert_channels", ["log"])
    if (
        not isinstance(channels, list)
        or not channels
        or not all(isinstance(c, str) and c in ALERT_CHANNELS for c in channels)
    ):
        raise ConfigError(f"{where} alert_channels must be a non-empty list from {ALERT_CHANNELS}")
    osascript = table.get("osascript_path")
    if "macos" in channels:
        if name != "mac":
            raise ConfigError(f'{where} the "macos" alert channel only works on the Mac')
        if osascript is None:
            raise ConfigError(f'{where} the "macos" alert channel needs osascript_path')

    service_user = _get(table, "service_user", str, None, where)
    if service_user is not None and not _USER_RE.match(service_user):
        raise ConfigError(f"{where} service_user {service_user!r} is not a valid user name")

    def optional_path(key: str) -> Path | None:
        value = _get(table, key, str, None, where)
        return _resolve(value, base_dir) if value is not None else None

    def optional_absolute(key: str) -> Path | None:
        value = _get(table, key, str, None, where)
        return _absolute_str(value, f"{where} {key}") if value is not None else None

    return PlatformConfig(
        **paths,
        interface=interface,
        nmap_path=_absolute(table, "nmap_path", where),
        nmap_privilege=nmap_privilege,
        sudo_path=_absolute(table, "sudo_path", where),
        arp_command=(str(arp_binary), *arp_command[1:]),
        pihole_log=_resolve(pihole_log, base_dir) if pihole_log else None,
        scheduler=scheduler,
        alert_channels=tuple(dict.fromkeys(channels)),
        osascript_path=optional_absolute("osascript_path"),
        router_syslog_path=optional_path("router_syslog_path"),
        install_dir=optional_absolute("install_dir"),
        service_user=service_user,
        config_file=optional_absolute("config_file"),
        nvd_api_key_file=optional_path("nvd_api_key_file"),
    )


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _table(data: dict[str, Any], key: str, *, required: bool = False) -> dict[str, Any]:
    value = data.get(key)
    if value is None:
        if required:
            raise ConfigError(f"missing [{key}] table")
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"{key} must be a table like [{key}]")
    return value


def _reject_unknown(table: dict[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(set(table) - allowed)
    if unknown:
        raise ConfigError(f"{where}: unknown key(s) {unknown}. Allowed: {sorted(allowed)}")


def _get(table: dict[str, Any], key: str, kind: type, default: Any, where: str) -> Any:
    if key not in table:
        return default
    value = table[key]
    # bool is a subclass of int in Python; don't accept true/false where a number is expected.
    if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
        raise ConfigError(f"{where} {key} must be a {kind.__name__}, got {value!r}")
    return value


def _require(table: dict[str, Any], key: str, kind: type, where: str) -> Any:
    if key not in table:
        raise ConfigError(f"{where} is missing required key {key!r}")
    return _get(table, key, kind, None, where)


def _int_range(
    table: dict[str, Any], key: str, default: int, low: int, high: int, where: str
) -> int:
    value = _get(table, key, int, default, where)
    if not low <= value <= high:
        raise ConfigError(f"{where} {key} must be between {low} and {high}, got {value}")
    return value


def _cidr_list(table: dict[str, Any], key: str, where: str) -> tuple[str, ...]:
    value = table.get(key)
    if not isinstance(value, list) or not value:
        raise ConfigError(f"{where} {key} must be a non-empty list of CIDRs (your LAN subnet)")
    out = []
    for item in value:
        if not isinstance(item, str):
            raise ConfigError(f"{where} {key} entries must be strings, got {item!r}")
        try:
            out.append(str(ipaddress.ip_network(item, strict=False)))
        except ValueError:
            raise ConfigError(f"{where} {key}: {item!r} is not an IP address or CIDR") from None
    return tuple(out)


def _resolve(value: str, base_dir: Path) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = base_dir / path
    return Path(os.path.normpath(path))


def _absolute(table: dict[str, Any], key: str, where: str) -> Path:
    return _absolute_str(_require(table, key, str, where), f"{where} {key}")


def _absolute_str(value: str, label: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ConfigError(f"{label} must be an absolute path (got {value!r})")
    return path


def platform_mismatch(config: Config) -> str | None:
    """A warning if the config's platform doesn't match the machine we're on."""
    if sys.platform == "darwin":
        running = "mac"
    elif sys.platform.startswith("linux"):
        running = "linux"
    else:
        running = sys.platform
    if config.platform == "mac" and running != "mac":
        return f'config says platform = "mac" but this machine is {running}'
    if config.platform == "pi" and running != "linux":
        return f'config says platform = "pi" but this machine is {running}'
    return None
