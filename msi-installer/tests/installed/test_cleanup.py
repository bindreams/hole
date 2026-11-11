"""Uninstall what an interrupted lifecycle run left (a step timeout or Ctrl-C skips the fixture's teardown).

Run through `cargo xtask run hole-msi-cleanup`. Idempotent: on a machine with nothing installed it only checks that.
It uninstalls only a Hole the lifecycle suite marked as its own (`INSTALLED_MARKER`), so a developer's own install is
reported, never removed.
"""

from pathlib import Path

import pytest
from support import (
    INSTALL_DIR,
    SERVICE,
    assert_nothing_installed,
    ensure_uninstalled,
    is_elevated,
    log_dir,
    marker_path,
)
from support import msi_path, service_registered  # noqa: F401 (fixtures)

pytestmark = pytest.mark.cleanup


def test_cleanup_leaves_nothing_installed(msi_path: Path):
    if not (service_registered() or INSTALL_DIR.exists()):
        assert_nothing_installed()
        marker_path().unlink(missing_ok=True)
        return
    assert marker_path().exists(), (
        f"Hole is installed ({SERVICE} service or {INSTALL_DIR}) but the suite did not install it: not uninstalling it"
    )
    assert is_elevated(), "uninstalling needs an elevated shell"
    ensure_uninstalled(msi_path, log_dir() / "msi-cleanup-uninstall.log")
    marker_path().unlink(missing_ok=True)
