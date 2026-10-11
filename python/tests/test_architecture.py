"""Architecture rules from the plan, enforced as tests.

These read the source code rather than running it, so a future change that
breaks a rule fails `just test` even if nobody notices in review.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from helpers import REPO_ROOT

PACKAGE = REPO_ROOT / "python" / "gnomehome"

# Absolute OS paths belong in config/gnomehome.toml, never in code (portability rule).
_OS_PATH = re.compile(
    r"^/(etc|var|run|usr|opt|proc|sys|dev|home|root|bin|sbin|tmp|Users|Library|private|Volumes)(/|$)"
)


def _python_files() -> list[Path]:
    return sorted(PACKAGE.rglob("*.py"))


def test_no_hardcoded_os_paths_in_code():
    offenders = []
    for path in _python_files():
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and _OS_PATH.match(node.value)
            ):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}: {node.value!r}")
    assert not offenders, "Move these paths into config/gnomehome.toml:\n" + "\n".join(offenders)


# Folders whose modules collect data or take action. Each module must import
# the shared guard (python/gnomehome/protected.py). Add new folders here.
GUARDED_PACKAGES = ("collectors", "responders")


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def test_every_collector_and_responder_imports_the_guard():
    missing = []
    for package in GUARDED_PACKAGES:
        for path in sorted((PACKAGE / package).glob("*.py")):
            if path.name == "__init__.py":
                continue
            if "gnomehome.protected" not in _imports(path):
                missing.append(str(path.relative_to(REPO_ROOT)))
    assert not missing, "These modules must import gnomehome.protected:\n" + "\n".join(missing)
