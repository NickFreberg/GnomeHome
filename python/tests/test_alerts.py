import subprocess
from pathlib import Path

from gnomehome.alerts import NEW_DEVICE_MESSAGE, Notifier

OSASCRIPT = Path("/usr/bin/osascript")


class Recorder:
    def __init__(self, fail: Exception | None = None) -> None:
        self.calls: list[list[str]] = []
        self.fail = fail

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        if self.fail:
            raise self.fail


def test_log_channel_prints_the_message():
    lines: list[str] = []
    Notifier(["log"], out=lines.append).notify(NEW_DEVICE_MESSAGE)
    assert lines == [f"ALERT: {NEW_DEVICE_MESSAGE}"]


def test_macos_banner_passes_text_only_as_arguments():
    runner = Recorder()
    hostile = '" & do shell script "rm -rf ~" & "'
    Notifier(["macos"], osascript_path=OSASCRIPT, runner=runner).notify(hostile, title="GnomeHome")
    argv = runner.calls[0]
    assert argv[0] == str(OSASCRIPT)
    script_lines = [argv[i + 1] for i, part in enumerate(argv) if part == "-e"]
    assert script_lines == [
        "on run argv",
        "display notification (item 2 of argv) with title (item 1 of argv)",
        "end run",
    ]
    assert argv[-2:] == ["GnomeHome", hostile]  # data, never part of the script
    assert all(hostile not in line for line in script_lines)


def test_failed_banner_never_raises():
    for error in (OSError("no osascript"), subprocess.TimeoutExpired("osascript", 10)):
        Notifier(["macos"], osascript_path=OSASCRIPT, runner=Recorder(fail=error)).notify("x")


def test_both_channels():
    lines: list[str] = []
    runner = Recorder()
    Notifier(["log", "macos"], osascript_path=OSASCRIPT, out=lines.append, runner=runner).notify(
        "m"
    )
    assert len(lines) == 1 and len(runner.calls) == 1
