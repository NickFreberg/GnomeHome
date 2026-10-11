"""Write a complete synthetic dataset to a folder.

Layout::

    <out>/household.json              the devices (with first-seen times)
    <out>/labels.json                 ground truth for every scenario
    <out>/threat_feed.txt             fake known-bad domains (for Phase 4 matching)
    <out>/dns/pihole.log              raw, as Pi-hole writes it
    <out>/dns/queries.jsonl           one normalized record per query
    <out>/flows/conntrack_snapshots.txt   raw, as the router's table would read
    <out>/flows/flows.jsonl           one normalized record per connection
    <out>/router/syslog.log           raw, as rsyslog on the Pi writes the router's syslog
    <out>/nmap/services.xml           a service scan in nmap's XML format (protected laptop absent)
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from gnomehome.synthetic import dns, flows, router, services
from gnomehome.synthetic.household import build_household
from gnomehome.timeutil import format_ts


@dataclass(frozen=True)
class GenerateResult:
    out_dir: Path
    devices: int
    queries: int
    flows: int
    snapshots: int
    router_lines: int


def generate(
    out_dir: Path,
    *,
    seed: int,
    start_date: str,
    hours: int,
    snapshot_seconds: int = 60,
) -> GenerateResult:
    start = datetime.fromisoformat(start_date).replace(tzinfo=UTC)
    span = timedelta(hours=hours)
    devices = build_household()
    # Separate, string-seeded streams: stable across runs and Python versions,
    # and changing the flow logic doesn't reshuffle the DNS data.
    queries, dns_scenarios = dns.generate_queries(
        random.Random(f"{seed}:dns"), devices, start, hours
    )
    flow_list, flow_scenarios = flows.generate_flows(
        random.Random(f"{seed}:flows"), devices, queries, start, hours
    )

    router_lines, router_scenarios = router.generate_router_log(
        random.Random(f"{seed}:router"), devices, start, hours
    )

    for sub in ("dns", "flows", "router", "nmap"):
        (out_dir / sub).mkdir(parents=True, exist_ok=True)

    household = [
        {**d.to_dict(), "first_seen": format_ts(start + span * d.joins_at)} for d in devices
    ]
    _write_json(out_dir / "household.json", household)

    new_device = next(d for d in devices if d.joins_at > 0)
    labels = {
        "seed": seed,
        "start": format_ts(start),
        "end": format_ts(start + span),
        "note": "Ground truth for detection tests. Never load labels into the database.",
        "scenarios": {
            **dns_scenarios,
            **flow_scenarios,
            **router_scenarios,
            "new_device": {
                "device": new_device.name,
                "mac": new_device.mac,
                "first_seen": format_ts(start + span * new_device.joins_at),
            },
            "protected": {
                "device": "work-laptop",
                "rule": "Drop every query and flow from or to this device before storage.",
            },
            "benign_periodic": {
                "note": "IoT check-ins on fixed schedules: expected beaconing false positives.",
                "schedules": {p: s for p, s in dns.PERIODIC.items()},
            },
        },
    }
    _write_json(out_dir / "labels.json", labels)
    (out_dir / "threat_feed.txt").write_text(
        "# Fake threat feed (reserved .test TLD)\n" + "".join(f"{d}\n" for d in dns.THREAT_FEED)
    )

    with open(out_dir / "dns" / "pihole.log", "w") as log:
        for line in dns.pihole_log_lines(queries):
            log.write(line + "\n")
    with open(out_dir / "dns" / "queries.jsonl", "w") as out:
        for q in queries:
            out.write(json.dumps(dns.query_record(q), sort_keys=True) + "\n")

    snapshots = 0
    with open(out_dir / "flows" / "conntrack_snapshots.txt", "w") as out:
        for line in flows.conntrack_snapshots(flow_list, start, hours, snapshot_seconds):
            snapshots += line.startswith("# snapshot")
            out.write(line + "\n")
    with open(out_dir / "flows" / "flows.jsonl", "w") as out:
        for flow in flow_list:
            out.write(json.dumps(flows.flow_record(flow), sort_keys=True) + "\n")

    (out_dir / "nmap" / "services.xml").write_bytes(
        services.service_scan_xml(devices, start + timedelta(minutes=30))
    )
    with open(out_dir / "router" / "syslog.log", "w") as out:
        for line in router.router_log_lines(router_lines):
            out.write(line + "\n")

    return GenerateResult(
        out_dir, len(devices), len(queries), len(flow_list), snapshots, len(router_lines)
    )


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
