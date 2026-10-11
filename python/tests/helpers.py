"""Helpers shared by the tests (importable as ``helpers``)."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_CONFIG = REPO_ROOT / "config" / "gnomehome.example.toml"
EXAMPLE_PROTECTED = REPO_ROOT / "config" / "protected_assets.example.yaml"
TESTDATA = REPO_ROOT / "testdata"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def write_config(tmp_path: Path, replacements: dict[str, str] | None = None) -> Path:
    """Copy the example config into ``tmp_path/config/`` with optional text replacements.

    Because relative paths resolve against the config file's folder, the
    example's ``../data`` lands in ``tmp_path/data``.
    """
    config_dir = tmp_path / "config"
    config_dir.mkdir(exist_ok=True)
    text = EXAMPLE_CONFIG.read_text()
    for old, new in (replacements or {}).items():
        assert old in text, f"replacement target not found in example config: {old!r}"
        text = text.replace(old, new)
    path = config_dir / "gnomehome.toml"
    path.write_text(text)
    return path
