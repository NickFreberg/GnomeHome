"""Proof that protected MACs and IPs are refused, and that the list fails closed."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml
from helpers import EXAMPLE_PROTECTED, TESTDATA

from gnomehome.protected import (
    Guard,
    ProtectedAssets,
    ProtectedListError,
    ProtectedTargetError,
    load_guard,
)

VECTORS = yaml.safe_load((TESTDATA / "guard_vectors.yaml").read_text())
ASSETS = ProtectedAssets.parse(VECTORS["protected_list"], source="vectors")


class RecordingAudit:
    """Stands in for the audit log: remembers every append."""

    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    def append(self, **row: Any) -> None:
        self.rows.append(row)


# ------------------------------------------------------------ shared vectors


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["name"])
def test_guard_vectors(case):
    matched = ASSETS.match(ip=case.get("ip"), mac=case.get("mac")) is not None
    assert matched == case["protected"]


@pytest.mark.parametrize(
    "case", [c for c in VECTORS["cases"] if c["protected"]], ids=lambda c: c["name"]
)
def test_active_action_against_protected_target_is_refused_and_audited(case):
    audit = RecordingAudit()
    guard = Guard(ASSETS, audit=audit, actor="test")
    with pytest.raises(ProtectedTargetError):
        guard.require_allowed("quarantine", ip=case.get("ip"), mac=case.get("mac"))
    assert len(audit.rows) == 1
    row = audit.rows[0]
    assert row["action"] == "guard.refused"
    assert row["result"] == "refused"
    assert row["details"]["attempted_action"] == "quarantine"


@pytest.mark.parametrize(
    "case", [c for c in VECTORS["cases"] if not c["protected"]], ids=lambda c: c["name"]
)
def test_unprotected_target_is_allowed_and_not_audited(case):
    audit = RecordingAudit()
    Guard(ASSETS, audit=audit).require_allowed("scan", ip=case.get("ip"), mac=case.get("mac"))
    assert audit.rows == []


# ------------------------------------------------------------ guard behavior


def test_refusal_audit_names_label_but_never_identifiers():
    audit = RecordingAudit()
    guard = Guard(ASSETS, audit=audit)
    with pytest.raises(ProtectedTargetError) as excinfo:
        guard.require_allowed("block", ip="192.0.2.10", mac="00:00:5e:00:53:01")
    assert excinfo.value.label == "Work laptop"
    flat = repr(audit.rows)
    assert "protected:Work laptop" in flat
    for identifier in ("192.0.2.10", "00:00:5e:00:53:01", "00-00-5e-00-53-01", "192.0.2.64"):
        assert identifier.lower() not in flat.lower()


def test_unparseable_target_is_refused_without_echoing_it():
    audit = RecordingAudit()
    with pytest.raises(ProtectedTargetError):
        Guard(ASSETS, audit=audit).require_allowed("scan", ip="$(rm -rf ~)")
    assert "rm -rf" not in repr(audit.rows)
    assert audit.rows[0]["target"] == "protected:unparseable-identifier"


def test_require_allowed_needs_a_target():
    with pytest.raises(ValueError, match="needs"):
        Guard(ASSETS).require_allowed("scan")


def test_passive_filter_drops_flows_matching_source_or_destination():
    flows = [
        {"src": "192.0.2.10", "dst": "198.51.100.7"},  # laptop is the source
        {"src": "192.0.2.23", "dst": "192.0.2.10"},  # laptop is the destination
        {"src": "192.0.2.23", "dst": "198.51.100.7"},  # unrelated: kept
        {"src": "192.0.2.24", "dst": None},  # missing field: kept, not an error
    ]
    guard = Guard(ASSETS)
    kept = list(guard.filter(flows, ips=lambda f: (f["src"], f["dst"])))
    assert kept == flows[2:]
    assert guard.passive_drops == 2


def test_passive_filter_by_mac():
    leases = [{"mac": "0:0:5e:0:53:2"}, {"mac": "00:00:5e:00:53:30"}]
    kept = list(Guard(ASSETS).filter(leases, macs=lambda r: (r["mac"],)))
    assert kept == [{"mac": "00:00:5e:00:53:30"}]


# ------------------------------------------------------------ nmap and tcpdump helpers


def test_nmap_exclude_lines_cover_every_protected_ipv4():
    assert ASSETS.ipv4_exclude_lines() == ["192.0.2.10", "192.0.2.64/30"]


def test_ipv6_entries_are_guarded_but_not_written_to_ipv4_exclude_file():
    assets = ProtectedAssets.parse(_list_yaml(ips=["192.0.2.10", "2001:db8::10"]), source="test")
    assert assets.ipv4_exclude_lines() == ["192.0.2.10"]
    assert Guard(assets).is_protected(ip="2001:db8::10")


def test_tcpdump_filter_lists_hosts_nets_and_macs():
    assert ASSETS.tcpdump_filter() == (
        "host 192.0.2.10 or net 192.0.2.64/30 "
        "or ether host 00:00:5e:00:53:01 or ether host 00:00:5e:00:53:02"
    )


def test_example_values_are_detected():
    assert ProtectedAssets.load(EXAMPLE_PROTECTED).uses_example_values()
    real_looking = _list_yaml(macs=["aa:bb:cc:00:00:01"], ips=["10.20.30.40"])  # hygiene: allow
    assert not ProtectedAssets.parse(real_looking).uses_example_values()


# ------------------------------------------------------------ loader fails closed


def _list_yaml(
    *, label: str = "Work laptop", macs: list[str] | None = None, ips: list[str] | None = None
) -> str:
    macs = macs if macs is not None else ["00:00:5e:00:53:01"]
    ips = ips if ips is not None else ["192.0.2.10"]
    mac_lines = "".join(f"\n      - {m}" for m in macs) if macs else " []"
    ip_lines = "".join(f"\n      - {i}" for i in ips) if ips else " []"
    return (
        "version: 1\nprotected:\n"
        f"  - label: {label}\n    reason: test\n    macs:{mac_lines}\n    ips:{ip_lines}\n"
    )


def test_example_file_loads():
    guard = load_guard(EXAMPLE_PROTECTED)
    assert guard.is_protected(mac="00-00-5E-00-53-01")
    assert guard.is_protected(ip="192.0.2.10")


def test_missing_file_is_refused(tmp_path: Path):
    with pytest.raises(ProtectedListError, match="not found"):
        load_guard(tmp_path / "protected_assets.yaml")


def test_unquoted_all_digit_mac_stays_a_string():
    # In YAML 1.1 this unquoted value is a base-60 integer. The strict loader keeps it a string.
    assets = ProtectedAssets.parse(_list_yaml(macs=["10:20:30:40:50:58"]))  # hygiene: allow
    assert Guard(assets).is_protected(mac="10-20-30-40-50-58")  # hygiene: allow


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "expected a mapping"),
        ("- just\n- a list\n", "expected a mapping"),
        ("version: 2\nprotected: []\n", "version must be 1"),
        ("version: 1\nprotected: []\n", "non-empty"),
        ("version: 1\n", "non-empty"),
        ("version: 1\nprotected: [}\n", "invalid YAML"),
        (_list_yaml() + "extra: true\n", "unknown key"),
        (_list_yaml().replace("macs:", "mac:"), "unknown key"),
        (_list_yaml(macs=[]), "macs must be a non-empty list"),
        (_list_yaml(ips=[]), "ips must be a non-empty list"),
        (_list_yaml(macs=["not-a-mac"]), "not a MAC"),
        (_list_yaml(macs=["ff:ff:ff:ff:ff:ff"]), "single device"),
        (_list_yaml(ips=["192.0.2.300"]), "not an IP"),
        (_list_yaml(label="Work laptop; DROP TABLE"), "label must be"),
        (_list_yaml().replace("reason: test", "reason: ''"), "reason is required"),
        (_list_yaml() + _list_yaml().split("protected:\n")[1], "duplicate label"),
        (
            _list_yaml().replace("    macs:", "    macs:\n      - 00:00:5e:00:53:09\n    macs:", 1),
            "duplicate key",
        ),
    ],
)
def test_invalid_lists_are_refused(text: str, message: str):
    with pytest.raises(ProtectedListError, match=message):
        ProtectedAssets.parse(text)


@pytest.mark.parametrize("case", VECTORS["text_cases"], ids=lambda c: c["name"])
def test_text_vectors(case):
    assert Guard(ASSETS).text_mentions_protected(case["text"]) is case["protected"]
