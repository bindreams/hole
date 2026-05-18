"""Test harness for the Hole macOS DMG.

Locates the DMG produced by `cargo xtask build hole-dmg`, mounts it, and
exposes the installed `Hole.app` to pytest fixtures so we can assert that
its code signature is internally consistent (the symptom that produces
"Hole.app is damaged and can't be opened" on Gatekeeper-quarantined
installs — see issue #364).

Usage: `uv run --directory dmg-installer pytest -v`
"""

from pathlib import Path

_PKG_DIR = Path(__file__).resolve().parent


class DmgTestError(Exception):
    """Raised when DMG test setup fails."""


def _find_repo_root() -> Path:
    p = _PKG_DIR
    while p != p.parent:
        if (p / ".git").exists():
            return p
        p = p.parent
    raise DmgTestError("could not find repo root (no .git/ directory found)")


def find_built_dmg(repo_root: Path) -> Path:
    bundle_dir = repo_root / "target" / "release" / "bundle" / "dmg"
    matches = sorted(bundle_dir.glob("*.dmg"))
    if not matches:
        raise DmgTestError(
            f"no .dmg found in {bundle_dir}; run `cargo xtask build hole-dmg` first"
        )
    if len(matches) > 1:
        raise DmgTestError(
            f"multiple .dmg files in {bundle_dir}: {[p.name for p in matches]}; "
            "remove stale ones before running tests"
        )
    return matches[0]
