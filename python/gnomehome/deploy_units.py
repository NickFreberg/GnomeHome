"""Render the Pi's systemd, tmpfiles, rsyslog, and logrotate files from config.

The templates live in ``deploy/pi/templates/`` (Linux-only pieces stay in
deploy/pi). Every path, user, schedule, and the router's IP come from the
config's ``[platforms.pi]`` table and shared sections, so nothing is
hardcoded, and the files can be rendered on the Mac and copied over.

Templates use ``${name}`` placeholders (Python's ``string.Template``), and a
literal dollar sign is written ``$$``.
"""

from __future__ import annotations

from pathlib import Path
from string import Template

from gnomehome.config import Config

TEMPLATES_DIR = Path(__file__).resolve().parents[2] / "deploy" / "pi" / "templates"
HARDENING = "_hardening.conf.in"


class RenderError(Exception):
    """The config is missing something the Pi's files need."""


def render_pi_files(
    config: Config, *, platform: str = "pi", templates: Path = TEMPLATES_DIR
) -> dict[str, str]:
    """Return ``{file name: content}`` for every template."""
    p = config.platforms.get(platform)
    if p is None:
        raise RenderError(f"no [platforms.{platform}] table in {config.path}")
    missing = [
        key
        for key in (
            "install_dir",
            "service_user",
            "config_file",
            "router_syslog_path",
            "pihole_log",
            "pihole_log_group",
        )
        if getattr(p, key) is None
    ]
    if config.network.router_ip is None:
        missing.append("[network] router_ip")
    if missing:
        raise RenderError(f"[platforms.{platform}] needs: {', '.join(missing)}")

    writable_dirs = sorted(
        {p.data_dir, p.db_path.parent, p.dev_db_path.parent, p.scans_dir, p.run_dir}, key=str
    )
    readonly = sorted({p.install_dir, p.protected_assets.parent, p.config_file.parent}, key=str)
    for path in (*writable_dirs, *readonly, p.router_syslog_path, p.pihole_log):
        if any(ch.isspace() for ch in str(path)):
            raise RenderError(f"paths used in systemd units can't contain spaces: {path}")

    values = {
        "user": p.service_user,
        "install_dir": str(p.install_dir),
        "config_file": str(p.config_file),
        "writable": " ".join(str(d) for d in writable_dirs),
        "readonly": " ".join(str(d) for d in readonly),
        "router_syslog_path": str(p.router_syslog_path),
        "router_syslog_dir": str(p.router_syslog_path.parent),
        "router_ip": config.network.router_ip,
        "pihole_log_dir": str(p.pihole_log.parent),
        "pihole_log_group": p.pihole_log_group,
        "discover_every": str(config.schedules.discovery_every_minutes),
        "scan_every": str(config.schedules.service_scan_every_minutes),
        "syslog_every": str(config.schedules.syslog_every_minutes),
        "analyze_every": str(config.schedules.analyze_every_minutes),
        "flows_every": str(config.schedules.flows_every_minutes),
        "enrich_at": config.schedules.enrich_daily_at,
        "upload_at": config.schedules.upload_nightly_at,
        "syslog_days": str(config.retention.syslog_days),
        "tmpfiles_lines": "\n".join(
            f"d {d} 0750 {p.service_user} {p.service_user} -" for d in writable_dirs
        ),
    }
    values["hardening"] = _render(templates / HARDENING, values).rstrip("\n")

    rendered = {}
    for template in sorted(templates.glob("*.in")):
        if template.name == HARDENING:
            continue
        rendered[template.name.removesuffix(".in")] = _render(template, values)
    return rendered


def write_files(files: dict[str, str], out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for name, content in files.items():
        path = out_dir / name
        path.write_text(content)
        written.append(path)
    return written


def _render(template: Path, values: dict[str, str]) -> str:
    try:
        return Template(template.read_text()).substitute(values)
    except (KeyError, ValueError) as exc:
        raise RenderError(f"{template.name}: bad or unknown placeholder {exc}") from None
