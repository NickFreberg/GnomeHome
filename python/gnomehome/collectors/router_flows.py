"""Router connection pulls: ``just flows`` (every minute on the Pi). FR-08.

Reads the router's connection table over SSH, keeps each open connection in
``conntrack_open``, and when a connection disappears from the table, stores it
as one ``flow`` event with its totals. Connections shorter than the pull
interval can be missed, which the plan accepts.

SSH is locked down:

* key-only (``BatchMode=yes``) with a pinned host key (``StrictHostKeyChecking=yes``
  and GnomeHome's own ``known_hosts`` file)
* one fixed, read-only command (``cat /proc/net/nf_conntrack``), never built
  from data

Protected devices: a connection is dropped before storage if *any* of its four
addresses (original source and destination, reply source and destination) is
protected. That covers the laptop starting a connection, being the target, and
being reached through a port forward.

Risk R-06: a stock firmware update can break this. Phases 1 to 3 don't depend on it.
"""

from __future__ import annotations

import ipaddress
import json
import sqlite3
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field

from gnomehome.config import Config
from gnomehome.conntrack import ConnEntry, parse_table
from gnomehome.db import transaction
from gnomehome.protected import Guard

COMMAND = "cat /proc/net/nf_conntrack"


class FlowPullError(Exception):
    """The connection table couldn't be read. Open connections are left as they are."""


@dataclass
class FlowResult:
    entries: int = 0
    opened: int = 0
    closed: int = 0
    dropped_protected: int = 0
    ignored_non_lan: int = 0


@dataclass
class SshFetcher:
    """Runs the one fixed command on the router."""

    ssh_path: str
    user: str
    host: str
    port: int
    key_file: str
    known_hosts: str
    timeout: float = 30
    runner: Callable[..., subprocess.CompletedProcess] = field(default=subprocess.run)

    def argv(self, command: str = COMMAND) -> list[str]:
        return [
            self.ssh_path,
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={self.known_hosts}",
            "-o", "ConnectTimeout=10",
            "-i", self.key_file,
            "-p", str(self.port),
            f"{self.user}@{self.host}",
            command,
        ]  # fmt: skip

    def run(self, command: str) -> str:
        """Run one fixed command on the router. Callers never build it from untrusted text."""
        try:
            proc = self.runner(self.argv(command), capture_output=True, text=True,
                               timeout=self.timeout, check=False)  # fmt: skip
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise FlowPullError(f"ssh to the router failed: {exc}") from None
        if proc.returncode != 0:
            raise FlowPullError(f"ssh exited {proc.returncode}: {proc.stderr.strip()[:200]}")
        return proc.stdout

    def __call__(self) -> str:
        return self.run(COMMAND)


def fetcher_from_config(config: Config) -> SshFetcher:
    p = config.paths
    missing = [k for k in ("router_ssh_user", "router_ssh_key", "router_known_hosts")
               if getattr(p, k) is None]  # fmt: skip
    if config.network.router_ip is None:
        missing.append("[network] router_ip")
    if missing:
        raise FlowPullError(f"router SSH isn't configured: missing {', '.join(missing)}")
    return SshFetcher(
        ssh_path=str(p.ssh_path),
        user=str(p.router_ssh_user),
        host=str(config.network.router_ip),
        port=p.router_ssh_port,
        key_file=str(p.router_ssh_key),
        known_hosts=str(p.router_known_hosts),
    )


def process_snapshot(
    conn: sqlite3.Connection,
    guard: Guard,
    entries: list[ConnEntry],
    *,
    seen_at: str,
    lan_cidrs: tuple[str, ...],
    source: str = "router",
    synthetic: bool = False,
) -> FlowResult:
    """Apply one snapshot of the table. Call outside a transaction."""
    lans = [ipaddress.ip_network(c) for c in lan_cidrs]
    result = FlowResult(entries=len(entries))
    current: dict[str, ConnEntry] = {}
    for entry in entries:
        ips = (entry.src_ip, entry.dst_ip, entry.reply_src_ip, entry.reply_dst_ip)
        if guard.touches_protected(ips=ips):
            result.dropped_protected += 1
            continue
        if not any(_in(ip, lans) for ip in ips if ip):
            result.ignored_non_lan += 1  # the router's own traffic
            continue
        current[entry.key] = entry

    with transaction(conn):
        for key, e in current.items():
            existed = conn.execute(
                "SELECT 1 FROM conntrack_open WHERE flow_key = ?", (key,)
            ).fetchone()
            conn.execute(
                """
                INSERT INTO conntrack_open (flow_key, protocol, src_ip, src_port, dst_ip, dst_port,
                    first_seen, last_seen, bytes_out, bytes_in, packets_out, packets_in, state)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (flow_key) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    bytes_out = MAX(conntrack_open.bytes_out, excluded.bytes_out),
                    bytes_in = MAX(conntrack_open.bytes_in, excluded.bytes_in),
                    packets_out = MAX(conntrack_open.packets_out, excluded.packets_out),
                    packets_in = MAX(conntrack_open.packets_in, excluded.packets_in),
                    state = excluded.state
                """,
                (key, e.protocol, e.src_ip, e.src_port, e.dst_ip, e.dst_port, seen_at, seen_at,
                 e.bytes_out, e.bytes_in, e.packets_out, e.packets_in, e.state),
            )  # fmt: skip
            result.opened += existed is None

        gone = [
            row
            for row in conn.execute("SELECT * FROM conntrack_open").fetchall()
            if row["flow_key"] not in current
        ]
        for row in gone:
            conn.execute("DELETE FROM conntrack_open WHERE flow_key = ?", (row["flow_key"],))
            if guard.touches_protected(ips=(row["src_ip"], row["dst_ip"])):
                result.dropped_protected += 1
                continue
            asset = conn.execute(
                "SELECT id FROM asset WHERE last_ip = ? AND protected = 0", (row["src_ip"],)
            ).fetchone()
            conn.execute(
                """
                INSERT INTO event (ts, kind, source, synthetic, asset_id, src_ip, src_port, dst_ip,
                    dst_port, protocol, status, bytes_out, bytes_in, packets_out, packets_in, attrs)
                VALUES (?, 'flow', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (row["first_seen"], source, int(synthetic), asset[0] if asset else None,
                 row["src_ip"], row["src_port"], row["dst_ip"], row["dst_port"], row["protocol"],
                 row["state"], row["bytes_out"], row["bytes_in"], row["packets_out"],
                 row["packets_in"], json.dumps({"end": row["last_seen"]})),
            )  # fmt: skip
            result.closed += 1
    return result


def pull_flows(
    conn: sqlite3.Connection,
    guard: Guard,
    fetch: Callable[[], str],
    *,
    seen_at: str,
    lan_cidrs: tuple[str, ...],
) -> FlowResult:
    """Fetch one snapshot and apply it. On a failed fetch, nothing changes."""
    text = fetch()  # raises FlowPullError
    return process_snapshot(conn, guard, parse_table(text), seen_at=seen_at, lan_cidrs=lan_cidrs)


def _in(ip: str, networks: list) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in networks)
