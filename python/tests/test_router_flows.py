"""Router connection table: parsing, the fixed SSH command, and the flow lifecycle."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from helpers import EXAMPLE_PROTECTED

from gnomehome.collectors.router_flows import (
    COMMAND,
    FlowPullError,
    SshFetcher,
    process_snapshot,
    pull_flows,
)
from gnomehome.conntrack import parse_line, parse_table
from gnomehome.db import open_database
from gnomehome.protected import load_guard
from gnomehome.synthetic.generate import generate

LAN = ("192.0.2.0/24",)
TCP = (
    "ipv4     2 tcp      6 431999 ESTABLISHED src=192.0.2.21 dst=203.0.113.15 sport=51234 "
    "dport=443 packets=12 bytes=3456 src=203.0.113.15 dst=198.51.100.1 sport=443 dport=51234 "
    "packets=10 bytes=9876 [ASSURED] mark=0 zone=0 use=2"
)


def test_parse_tcp_line_with_both_directions():
    e = parse_line(TCP)
    assert (e.protocol, e.state, e.src_ip, e.dst_ip, e.src_port, e.dst_port) == (
        "tcp", "ESTABLISHED", "192.0.2.21", "203.0.113.15", 51234, 443
    )  # fmt: skip
    assert (e.bytes_out, e.bytes_in, e.reply_dst_ip) == (3456, 9876, "198.51.100.1")


def test_parse_older_format_udp_without_counters():
    e = parse_line(
        "udp      17 29 src=192.0.2.41 dst=198.51.100.53 sport=40000 dport=53 [UNREPLIED] "
        "src=198.51.100.53 dst=198.51.100.1 sport=53 dport=40000 mark=0 use=2"
    )
    assert e.protocol == "udp" and e.state is None and e.bytes_out == 0 and e.dst_port == 53


def test_icmp_has_no_ports_and_junk_is_skipped():
    icmp = parse_line(
        "ipv4 2 icmp 1 29 src=192.0.2.5 dst=198.51.100.9 type=8 code=0 id=1 "
        "src=198.51.100.9 dst=198.51.100.1 type=0 code=0 id=1 mark=0 use=2"
    )
    assert icmp.src_port is None
    assert parse_table("garbage\n\n" + TCP + "\nipv4 2 tcp 6 1 ESTABLISHED\n") == [parse_line(TCP)]


def test_ssh_runs_one_fixed_command_with_a_pinned_host_key():
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout=TCP, stderr="")

    fetch = SshFetcher("/usr/bin/ssh", "admin", "192.0.2.1", 22, "/k", "/kh", runner=runner)
    assert fetch() == TCP
    argv = calls[0]
    assert argv[-1] == COMMAND == "cat /proc/net/nf_conntrack"
    assert argv[-2] == "admin@192.0.2.1"
    joined = " ".join(argv)
    assert "BatchMode=yes" in joined and "StrictHostKeyChecking=yes" in joined
    assert "UserKnownHostsFile=/kh" in joined


def test_ssh_failure_raises():
    def runner(argv, **kwargs):
        return subprocess.CompletedProcess(
            argv, 255, stdout="", stderr="Host key verification failed."
        )

    with pytest.raises(FlowPullError, match="Host key verification failed"):
        SshFetcher("/usr/bin/ssh", "admin", "192.0.2.1", 22, "/k", "/kh", runner=runner)()


@pytest.fixture
def db(tmp_path: Path):
    conn = open_database(tmp_path / "x.sqlite3")
    yield conn, load_guard(EXAMPLE_PROTECTED)
    conn.close()


def flow_line(src, dst, sport, bytes_out, reply_src=None, reply_dst="198.51.100.1"):
    return parse_line(
        f"ipv4 2 tcp 6 431999 ESTABLISHED src={src} dst={dst} sport={sport} dport=443 "
        f"packets=1 bytes={bytes_out} src={reply_src or dst} dst={reply_dst} sport=443 "
        f"dport={sport} packets=1 bytes=10 [ASSURED] mark=0 use=2"
    )


def test_a_connection_becomes_one_flow_when_it_closes(db):
    conn, guard = db
    a = flow_line("192.0.2.21", "203.0.113.15", 50000, 100)
    process_snapshot(conn, guard, [a], seen_at="2026-10-05T00:01:00.000Z", lan_cidrs=LAN)
    bigger = flow_line("192.0.2.21", "203.0.113.15", 50000, 5000)
    r2 = process_snapshot(conn, guard, [bigger], seen_at="2026-10-05T00:02:00.000Z", lan_cidrs=LAN)
    assert r2.opened == 0 and r2.closed == 0
    r3 = process_snapshot(conn, guard, [], seen_at="2026-10-05T00:03:00.000Z", lan_cidrs=LAN)
    assert r3.closed == 1
    event = conn.execute("SELECT * FROM event WHERE kind = 'flow'").fetchone()
    assert event["ts"] == "2026-10-05T00:01:00.000Z" and event["bytes_out"] == 5000
    assert '"end": "2026-10-05T00:02:00.000Z"' in event["attrs"]
    assert conn.execute("SELECT COUNT(*) FROM conntrack_open").fetchone()[0] == 0


def test_protected_device_flows_are_dropped_in_every_direction(db):
    conn, guard = db
    entries = [
        flow_line("192.0.2.10", "203.0.113.15", 50001, 100),  # laptop starts it
        flow_line("192.0.2.21", "192.0.2.10", 50002, 100),  # laptop is the target
        flow_line("203.0.113.9", "198.51.100.1", 50003, 100, reply_src="192.0.2.10"),  # forward
        flow_line("192.0.2.21", "203.0.113.16", 50004, 100),  # ordinary
    ]
    result = process_snapshot(
        conn, guard, entries, seen_at="2026-10-05T00:01:00.000Z", lan_cidrs=LAN
    )
    assert result.dropped_protected == 3 and result.opened == 1
    keys = [r[0] for r in conn.execute("SELECT flow_key FROM conntrack_open")]
    assert keys == ["tcp|192.0.2.21|50004|203.0.113.16|443"]


def test_a_failed_pull_changes_nothing(db):
    conn, guard = db
    process_snapshot(conn, guard, [flow_line("192.0.2.21", "203.0.113.15", 50000, 1)],
                     seen_at="2026-10-05T00:01:00.000Z", lan_cidrs=LAN)  # fmt: skip

    def broken():
        raise FlowPullError("router unreachable")

    with pytest.raises(FlowPullError):
        pull_flows(conn, guard, broken, seen_at="2026-10-05T00:02:00.000Z", lan_cidrs=LAN)
    assert conn.execute("SELECT COUNT(*) FROM conntrack_open").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM event").fetchone()[0] == 0


def test_replaying_synthetic_router_snapshots(tmp_path: Path, db):
    conn, guard = db
    out = tmp_path / "synth"
    generate(out, seed=3, start_date="2026-10-05", hours=1)
    blocks = (out / "flows" / "conntrack_snapshots.txt").read_text().split("# snapshot ")[1:]
    for block in blocks:
        stamp, _, body = block.partition("\n")
        process_snapshot(conn, guard, parse_table(body), seen_at=stamp.strip(), lan_cidrs=LAN)
    flows = conn.execute("SELECT * FROM event WHERE kind = 'flow'").fetchall()
    assert flows
    assert all("192.0.2.10" not in (f["src_ip"], f["dst_ip"]) for f in flows)
    assert any(f["dst_ip"] == "8.8.8.8" or f["dst_port"] == 443 for f in flows)
