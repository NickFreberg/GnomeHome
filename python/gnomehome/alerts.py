"""Deliver alerts. Phase 2 channels: ``log`` (all platforms) and ``macos`` (the Mac).

Push notifications to the Azure mobile app arrive in Phase 7 (FR-16), and the
plan asks for minimal payloads there too. Banners carry a fixed, generic message
and never device-supplied text such as hostnames. The details live in the
incident log (``just incidents``).

The macOS banner runs ``osascript`` with the title and message passed as
*arguments* to a fixed script, never spliced into the script text, so no
string can turn into AppleScript code.
"""

from __future__ import annotations

import logging
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from gnomehome.config import Config

log = logging.getLogger(__name__)

TITLE = "GnomeHome"
NEW_DEVICE_MESSAGE = "New device on your network. Run `just incidents` for details."
DRIFT_MESSAGE = "A protected device needs attention. Run `just incidents` for details."
FINDING_MESSAGE = "New security finding on your network. Run `just incidents` for details."

_APPLESCRIPT = (
    "on run argv",
    "display notification (item 2 of argv) with title (item 1 of argv)",
    "end run",
)


class Notifier:
    def __init__(
        self,
        channels: Sequence[str],
        *,
        osascript_path: Path | None = None,
        out: Callable[[str], None] = print,
        runner: Callable[..., Any] = subprocess.run,
    ) -> None:
        self.channels = tuple(channels)
        self.osascript_path = osascript_path
        self.out = out
        self.runner = runner

    def notify(self, message: str, *, title: str = TITLE) -> None:
        for channel in self.channels:
            if channel == "log":
                self.out(f"ALERT: {message}")
            elif channel == "macos":
                self._macos(title, message)

    def macos_argv(self, title: str, message: str) -> list[str]:
        if self.osascript_path is None:
            raise ValueError("the macos channel needs osascript_path")
        argv = [str(self.osascript_path)]
        for line in _APPLESCRIPT:
            argv += ["-e", line]
        return [*argv, title, message]

    def _macos(self, title: str, message: str) -> None:
        # A failed banner must never fail the job that raised the alert.
        try:
            self.runner(
                self.macos_argv(title, message), capture_output=True, timeout=10, check=False
            )
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            log.warning("could not show the macOS notification: %s", exc)


def notifier_from_config(config: Config, *, log_only: bool = False) -> Notifier:
    channels = ("log",) if log_only else config.paths.alert_channels
    return Notifier(channels, osascript_path=config.paths.osascript_path)
