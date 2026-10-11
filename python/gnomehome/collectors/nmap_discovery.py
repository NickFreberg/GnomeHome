"""nmap discovery job: ``just discover`` (hosts only) and ``just scan`` (hosts + services).

It must never send a packet to a protected asset. The layers, in order:

1. The protected list loads or nothing runs. A real scan refuses example values.
2. Targets must be private (RFC1918), reasonably sized, and not a protected IP.
3. Passive drift check: the ARP cache (no packets sent) can add IPs to this run's exclusions.
4. Every nmap run gets ``--excludefile`` listing every protected IPv4. nmap drops
   those addresses before sending anything, including during host discovery.
5. Right before each nmap call, the arguments and the exclude file are checked
   again (and the phase-2 host list too), so a bug or a tampered file can't slip through.
6. If host discovery reports a protected host anyway, the job stops before the
   service scan, stores nothing, and records a ``guard.violation``.
7. The inventory writer refuses protected hosts (and the schema refuses their data).

There's deliberately no way to pass extra nmap arguments.
"""

from __future__ import annotations

import fcntl
import ipaddress
import json
import logging
import os
import re
import subprocess
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from gnomehome.audit import AuditLog
from gnomehome.collectors.arp_cache import ArpEntry, check_drift, read_arp_cache
from gnomehome.collectors.inventory import record_hosts
from gnomehome.config import Config
from gnomehome.db import open_database, transaction
from gnomehome.db.scrub import scrub_protected
from gnomehome.nmap_xml import NmapHost, NmapRun, parse_nmap_xml
from gnomehome.protected import Guard, ProtectedAssets
from gnomehome.timeutil import utc_now

log = logging.getLogger(__name__)

ACTOR = "system:scan"
RFC1918 = tuple(ipaddress.IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


class ScanRefused(Exception):
    """A precondition failed. Nothing was sent."""


class GuardViolation(Exception):
    """A protected host showed up, or the exclusions weren't in place. The run was stopped."""


class NmapFailed(Exception):
    """nmap exited with an error."""


class NmapRunner(Protocol):
    def run(self, argv: list[str], xml_path: Path) -> None:
        """Run nmap. ``argv`` already contains ``-oX xml_path``."""

    def version(self) -> str | None: ...


class SubprocessNmapRunner:
    """Runs the real nmap. Its normal output (progress) goes to your terminal."""

    def __init__(self, nmap_path: Path) -> None:
        self.nmap_path = nmap_path

    def run(self, argv: list[str], xml_path: Path) -> None:
        proc = subprocess.run(argv, check=False)
        if proc.returncode != 0:
            raise NmapFailed(f"nmap exited with code {proc.returncode}")
        if not xml_path.exists():
            raise NmapFailed(f"nmap did not write {xml_path}")

    def version(self) -> str | None:
        try:
            out = subprocess.run(
                [str(self.nmap_path), "--version"], capture_output=True, text=True, check=False
            ).stdout
        except OSError:
            return None
        match = re.search(r"Nmap version (\S+)", out)
        return match[1] if match else None


@dataclass
class ScanResult:
    mode: str
    dry_run: bool = False
    scan_id: int | None = None
    hosts_up: int = 0
    services_seen: int = 0
    new_devices: list[tuple[str | None, str, str | None]] = field(default_factory=list)
    excluded: list[str] = field(default_factory=list)
    commands: list[list[str]] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# Preconditions
# --------------------------------------------------------------------------


def target_problems(targets: Sequence[str], assets: ProtectedAssets, max_hosts: int) -> list[str]:
    """Reasons these targets can't be scanned (an empty list means OK)."""
    problems = []
    for target in targets:
        net = ipaddress.ip_network(target, strict=False)
        if not isinstance(net, ipaddress.IPv4Network):
            problems.append(f"{target}: only IPv4 targets are scanned (IPv6 is off on the router)")
            continue
        if not any(net.subnet_of(private) for private in RFC1918):
            problems.append(
                f"{target}: not a private home network range (must be inside 10.0.0.0/8, "
                "172.16.0.0/12, or 192.168.0.0/16). Example values must be replaced."
            )
            continue
        if net.num_addresses > max_hosts:
            problems.append(
                f"{target}: {net.num_addresses} addresses is more than max_target_hosts "
                f"({max_hosts})"
            )
        if net.num_addresses == 1 and assets.match(ip=str(net.network_address)):
            problems.append(f"{target}: is a protected device's IP")
        elif any(
            net.subnet_of(p) for p in assets.all_networks if isinstance(p, ipaddress.IPv4Network)
        ):
            problems.append(f"{target}: lies entirely inside a protected range")
    return problems


def protected_list_problems(assets: ProtectedAssets) -> list[str]:
    problems = []
    for entry in assets.entries:
        if not any(net.version == 4 for net in entry.networks):
            problems.append(
                f"protected device {entry.label!r} has no IPv4 address, so nmap can't exclude it"
            )
    return problems


# --------------------------------------------------------------------------
# Command lines
# --------------------------------------------------------------------------


def _prefix(config: Config) -> list[str]:
    p = config.paths
    if p.nmap_privilege == "sudo":
        return [str(p.sudo_path), str(p.nmap_path)]
    if p.nmap_privilege == "capabilities":
        return [str(p.nmap_path), "--privileged"]
    return [str(p.nmap_path), "--unprivileged"]


def _common(config: Config, exclude_file: Path, xml_out: Path) -> list[str]:
    args = ["-e", config.paths.interface, f"-T{config.scan.timing}"]
    args += ["--max-retries", str(config.scan.max_retries)]
    if not config.scan.reverse_dns:
        args.append("-n")
    args += ["--excludefile", str(exclude_file), "-oX", str(xml_out), "--stats-every", "30s"]
    return args


def discovery_argv(config: Config, exclude_file: Path, xml_out: Path) -> list[str]:
    """Phase 1: host discovery only (``-sn``: no port scan). ARP on the local network."""
    return [
        *_prefix(config),
        "-sn",
        *_common(config, exclude_file, xml_out),
        *config.network.scan_targets,
    ]


def service_argv(config: Config, exclude_file: Path, hosts_file: Path, xml_out: Path) -> list[str]:
    """Phase 2: ports, services, and OS for only the hosts found up in phase 1."""
    raw = config.paths.nmap_privilege != "none"
    args = [*_prefix(config), "-sS" if raw else "-sT"]
    if config.scan.service_detection:
        args.append("-sV")
    if config.scan.os_detection and raw:
        args += ["-O", "--osscan-limit"]
    args += ["--top-ports", str(config.scan.top_ports), "--host-timeout", config.scan.host_timeout]
    # -Pn: these hosts were just found up, so skip discovering them again.
    args += ["-Pn", *_common(config, exclude_file, xml_out), "-iL", str(hosts_file)]
    return args


# --------------------------------------------------------------------------
# The boundary check (layer 5)
# --------------------------------------------------------------------------


def check_before_running(
    argv: Sequence[str], exclude_file: Path, required: Sequence[str], guard: Guard
) -> None:
    """Refuse to start nmap unless the exclusions are really in place."""
    if argv.count("--excludefile") != 1:
        raise GuardViolation("nmap command has no (or more than one) --excludefile")
    index = argv.index("--excludefile")
    if index + 1 >= len(argv) or argv[index + 1] != str(exclude_file):
        raise GuardViolation("nmap command points at the wrong exclude file")
    present = set(exclude_file.read_text().split())
    missing = sorted(set(required) - present)
    if missing:
        raise GuardViolation(
            f"exclude file is missing {len(missing)} protected address(es); refusing to run nmap"
        )
    if "-iL" in argv:
        hosts_file = Path(argv[argv.index("-iL") + 1])
        for line in hosts_file.read_text().split():
            if guard.is_protected(ip=line):
                raise GuardViolation("phase-2 host list contains a protected IP; refusing to run")


# --------------------------------------------------------------------------
# The job
# --------------------------------------------------------------------------


@contextmanager
def _scan_lock(run_dir: Path) -> Iterator[None]:
    run_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    with open(run_dir / "scan.lock", "w") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ScanRefused("another scan is already running") from None
        yield


def _write_private(path: Path, lines: Sequence[str]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write("".join(f"{line}\n" for line in lines))
    os.chmod(path, 0o600)


def run_scan(
    config: Config,
    *,
    mode: str = "service",
    dry_run: bool = False,
    runner: NmapRunner | None = None,
    arp_reader: Callable[[], list[ArpEntry]] | None = None,
    allow_example_values: bool = False,
    say: Callable[[str], None] = print,
) -> ScanResult:
    """Run (or, with ``dry_run``, describe) a discovery or service scan."""
    if mode not in ("discovery", "service"):
        raise ValueError(f"mode must be 'discovery' or 'service', got {mode!r}")
    paths = config.paths
    result = ScanResult(mode=mode, dry_run=dry_run)

    # Layer 1: the list loads, or ProtectedListError propagates and nothing runs.
    assets = ProtectedAssets.load(paths.protected_assets)
    result.problems += protected_list_problems(assets)
    if assets.uses_example_values() and not allow_example_values:
        result.problems.append(
            "config/protected_assets.yaml still has example values. Put in your work laptop's "
            "real MACs and reserved IP first."
        )
    # Layer 2.
    result.problems += target_problems(
        config.network.scan_targets, assets, config.scan.max_target_hosts
    )

    exclude_file = paths.run_dir / "nmap-exclude.txt"
    hosts_file = paths.run_dir / "nmap-live-hosts.txt"
    required = assets.ipv4_exclude_lines()

    if dry_run:
        result.excluded = required
        result.commands = [discovery_argv(config, exclude_file, paths.scans_dir / "DISCOVERY.xml")]
        if mode == "service":
            result.commands.append(
                service_argv(config, exclude_file, hosts_file, paths.scans_dir / "SERVICE.xml")
            )
        return result

    if result.problems:
        raise ScanRefused("; ".join(result.problems))

    runner = runner or SubprocessNmapRunner(paths.nmap_path)
    with _scan_lock(paths.run_dir):
        conn = open_database(paths.db_path)
        try:
            return _run_locked(
                config, conn, assets, mode, runner, arp_reader, result, say,
                exclude_file=exclude_file, hosts_file=hosts_file, required=required,
            )  # fmt: skip
        finally:
            conn.close()


def _run_locked(
    config: Config,
    conn,
    assets: ProtectedAssets,
    mode: str,
    runner: NmapRunner,
    arp_reader: Callable[[], list[ArpEntry]] | None,
    result: ScanResult,
    say: Callable[[str], None],
    *,
    exclude_file: Path,
    hosts_file: Path,
    required: list[str],
) -> ScanResult:
    paths = config.paths
    audit = AuditLog(conn)
    guard = Guard(assets, audit=audit, actor=ACTOR)
    scrub_protected(conn, assets, audit=audit, actor=ACTOR)

    # Layer 3: passive drift check.
    entries = arp_reader() if arp_reader else read_arp_cache(paths.arp_command, paths.interface)
    drift = check_drift(entries, assets)
    for warning in drift.warnings:
        say(f"WARNING: {warning}")
    for label, kind in drift.findings:
        audit.append(
            actor=ACTOR,
            action="guard.drift_detected",
            target=f"protected:{label}",
            result="success",
            details={"kind": kind},
        )

    # Layer 4: the exclude file.
    result.excluded = sorted(set(required) | set(drift.extra_excludes))
    _write_private(exclude_file, result.excluded)

    started = utc_now()
    scan_id = conn.execute(
        "INSERT INTO scan_run (kind, started_at, status, targets, nmap_version) "
        "VALUES (?, ?, 'running', ?, ?)",
        (mode, started, json.dumps(list(config.network.scan_targets)), runner.version()),
    ).lastrowid
    result.scan_id = scan_id
    audit.append(
        actor=ACTOR,
        action=f"scan.{mode}.start",
        target=None,
        result="success",
        details={
            "scan_id": scan_id,
            "targets": len(config.network.scan_targets),
            "excluded": len(result.excluded),
        },
    )

    def finish(status: str, error: str | None = None) -> None:
        conn.execute(
            "UPDATE scan_run SET status = ?, finished_at = ?, hosts_up = ?, assets_new = ?, "
            "services_seen = ?, error = ? WHERE id = ?",
            (
                status,
                utc_now(),
                result.hosts_up,
                len(result.new_devices),
                result.services_seen,
                error,
                scan_id,
            ),
        )
        audit.append(
            actor=ACTOR,
            action=f"scan.{mode}.finish",
            target=None,
            result="success" if status == "success" else "failure",
            details={
                "scan_id": scan_id,
                "status": status,
                "hosts_up": result.hosts_up,
                "new_devices": len(result.new_devices),
                "services": result.services_seen,
            },
        )

    def run_phase(argv: list[str], xml_path: Path, phase: str) -> NmapRun:
        try:
            check_before_running(argv, exclude_file, result.excluded, guard)  # layer 5
        except GuardViolation as exc:
            audit.append(
                actor=ACTOR,
                action="guard.violation",
                target=None,
                result="failure",
                details={"phase": phase, "scan_id": scan_id, "reason": str(exc)},
            )
            finish("aborted", str(exc))
            say(f"STOPPED before {phase}: {exc}. Nothing was sent for this phase.")
            raise
        result.commands.append(argv)
        runner.run(argv, xml_path)
        return parse_nmap_xml(xml_path.read_bytes())

    def stop_if_protected(run: NmapRun, phase: str) -> None:
        # Layer 6.
        for host in run.hosts:
            if not guard.touches_protected(ips=[host.ip], macs=[host.mac]):
                continue
            match = assets.match(ip=host.ip, mac=host.mac) if (host.ip or host.mac) else None
            label = match.label if match else "unknown"
            audit.append(
                actor=ACTOR,
                action="guard.violation",
                target=f"protected:{label}",
                result="failure",
                details={"phase": phase, "scan_id": scan_id},
            )
            finish("aborted", f"protected host in {phase} results")
            say(
                f"STOPPED: protected device {label!r} appeared in {phase} results at "
                f"{host.ip} ({host.mac}). Nothing from this run was stored and no service scan "
                "ran. Its IP is probably not the reserved one: fix the DHCP reservation, then "
                "run the zero-packet test again (docs/runbooks/zero-packet-test.md)."
            )
            raise GuardViolation(f"protected device {label!r} appeared in {phase} results")

    stamp = started.replace(":", "").replace("-", "").replace(".", "")
    paths.scans_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        xml = paths.scans_dir / f"{stamp}-discovery.xml"
        discovery = run_phase(discovery_argv(config, exclude_file, xml), xml, "discovery")
        stop_if_protected(discovery, "discovery")
        live = [h for h in discovery.hosts if h.status == "up"]
        hosts: list[NmapHost] = live

        if mode == "service":
            targets = [h.ip for h in live if h.ip and h.mac]
            if targets:
                _write_private(hosts_file, targets)
                xml = paths.scans_dir / f"{stamp}-service.xml"
                services = run_phase(
                    service_argv(config, exclude_file, hosts_file, xml), xml, "service"
                )
                stop_if_protected(services, "service")
                hosts = _merge(live, services)

        with transaction(conn):
            inventory = record_hosts(
                conn,
                guard,
                hosts,
                scan_id=scan_id,
                now=utc_now(),
                with_services=mode == "service",
            )
        result.hosts_up = inventory.hosts_seen
        result.services_seen = inventory.services_seen
        result.new_devices = inventory.new_devices
        finish("success")
    except GuardViolation:
        raise
    except Exception as exc:
        finish("failed", str(exc)[:500])
        raise
    return result


def _merge(discovered: list[NmapHost], scanned: NmapRun) -> list[NmapHost]:
    """Prefer phase-2 details, keeping phase-1 MAC and vendor when phase 2 lacks them."""
    by_ip = {h.ip: h for h in scanned.hosts if h.ip}
    merged = []
    for host in discovered:
        detail = by_ip.get(host.ip)
        if detail is None:
            merged.append(host)
            continue
        merged.append(
            NmapHost(
                status=host.status,
                ip=host.ip,
                mac=detail.mac or host.mac,
                vendor=detail.vendor or host.vendor,
                hostname=detail.hostname or host.hostname,
                services=detail.services,
                os_name=detail.os_name,
                os_accuracy=detail.os_accuracy,
                device_type=detail.device_type,
            )
        )
    return merged
