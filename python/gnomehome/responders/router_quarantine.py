"""Quarantine a device at the router with a temporary iptables rule (FR-13).

The Rust playbook engine runs this as a helper with fixed arguments
(``gnomehome quarantine --mac ... --block --run-id ...``), because router
control lives on the Python side. It can also be run by hand.

How it works: over the same locked-down SSH as the connection pull (key only,
pinned host key), it inserts one rule at the top of the router's FORWARD
chain that drops everything from the device's MAC, so it can't reach the
internet. Releasing deletes the same rule. The rule also disappears if the
router reboots, which makes a stuck quarantine impossible.

Safety:

* The guard refuses a protected device (and audits the refusal by label)
  before anything is sent. The schema refuses it too.
* The command is built only from a MAC that passed normalization, so it can
  only contain hex digits and colons. Nothing device-supplied reaches the
  router's shell.
* Dry run unless ``[response] mode = "live"`` and ``router.quarantine`` is in
  ``live_actions``. The engine's ``--live`` flag alone isn't enough.

Limit: traffic between two devices on the same Wi-Fi or LAN switch doesn't
pass through FORWARD, so this stops internet access, not local traffic.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from gnomehome.audit import AuditLog
from gnomehome.config import Config
from gnomehome.identifiers import normalize_mac
from gnomehome.protected import Guard

ACTION = "router.quarantine"


def block_command(mac: str) -> str:
    rule = _rule(mac)
    # -C checks whether the rule exists, so blocking twice adds it only once.
    return f"iptables -C FORWARD {rule} 2>/dev/null || iptables -I FORWARD 1 {rule}"


def release_command(mac: str) -> str:
    rule = _rule(mac)
    # Delete every copy, and succeed when there's none left.
    return f"while iptables -D FORWARD {rule} 2>/dev/null; do :; done; true"


def _rule(mac: str) -> str:
    normalized = normalize_mac(mac)  # raises on anything that isn't a MAC
    if any(c not in "0123456789abcdef:" for c in normalized):
        raise ValueError("unexpected characters in a normalized MAC")
    return f"-m mac --mac-source {normalized.upper()} -j DROP"


def live_allowed(config: Config) -> bool:
    return config.response.mode == "live" and ACTION in config.response.live_actions


@dataclass
class QuarantineResult:
    mac: str
    block: bool
    dry_run: bool
    command: str


def quarantine(
    guard: Guard,
    audit: AuditLog,
    mac: str,
    *,
    block: bool,
    run: Callable[[str], str] | None,
    run_id: str | None = None,
    live: bool = False,
) -> QuarantineResult:
    """Block or release one device. ``run`` sends a command to the router (None in dry run).

    Raises ``ProtectedTargetError`` for a protected device, after auditing the refusal.
    """
    normalized = normalize_mac(mac)
    guard.require_allowed(ACTION, mac=normalized)
    command = block_command(normalized) if block else release_command(normalized)
    dry_run = not live or run is None
    details = {"run_id": run_id, "dry_run": dry_run, "block": block}
    try:
        if live and run is not None:
            run(command)
    except Exception as exc:
        audit.append(actor="system:playbook", action=ACTION, target=f"device:{normalized}",
                     result="failure", details={**details, "error": str(exc)[:200]})  # fmt: skip
        raise
    audit.append(actor="system:playbook", action=ACTION, target=f"device:{normalized}",
                 result="success", details=details)  # fmt: skip
    return QuarantineResult(normalized, block, dry_run, command)
