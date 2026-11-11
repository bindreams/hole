"""The Windows installer lifecycle against the MSI under test, in order: install, verify, E2E, uninstall, verify.

Installs Hole system-wide: run it only through `cargo xtask run hole-msi-install-tests` from an elevated shell (see
CONTRIBUTING.md, "Windows installer"). The uninstall and its verification are the `installed_hole` fixture's teardown,
so they run after a failed test too.
"""

from pathlib import Path

import pytest
from support import BIN_DIR, E2E_MEDIUM, RUN_AT_MEDIUM, VERIFY_GSUDO, installed_hole, machine_path_has_bin_dir, run_ps
from support import e2e_environment, msi_path, service_registered  # noqa: F401 (fixtures)

from conftest import canonical_windows_bindir

pytestmark = pytest.mark.system_wide


def test_installed_files_match_canonical_bindir(installed_hole: Path):
    present = {p.name for p in (installed_hole / "bin").iterdir() if p.is_file()}
    assert not canonical_windows_bindir() - present, "files the installer must install are missing"


def test_bridge_service_registered(installed_hole: Path):
    assert service_registered(), "HoleBridge service not registered"


def test_machine_path_has_bin_dir(installed_hole: Path):
    assert machine_path_has_bin_dir(), f"{BIN_DIR} not in the Machine PATH"


def test_gsudo_deelevation_contract(installed_hole: Path, e2e_environment: dict[str, str]):
    """De-elevation preserves what the E2E needs: Medium integrity, env, PATH (npm), streamed stdout, the exit code.

    The child exits 7 only when every contract check passes: a nonzero sentinel that also proves the exit code
    survives the launcher. Fails here, loudly, rather than as an opaque session timeout in the E2E.
    """
    env = {**e2e_environment, "HOLE_SELFTEST_CANARY": "canary-ok"}
    code = run_ps(RUN_AT_MEDIUM, {"Script": str(VERIFY_GSUDO)}, env=env)
    assert code == 7, f"gsudo de-elevation contract failed (exit {code}); see the child output above"


def test_dashboard_e2e_at_medium_integrity(installed_hole: Path, e2e_environment: dict[str, str]):
    """WebDriverIO smoke test of the INSTALLED binary: the dashboard loads the bundled frontend (#372).

    `e2e-medium.ps1` checks inside the de-elevated child that `HOLE_TEST_APP_PATH` arrived and points at a real
    binary, rather than letting wdio fall back to the uninstalled workspace build.
    """
    env = {**e2e_environment, "HOLE_TEST_APP_PATH": str(BIN_DIR / "hole.exe")}
    code = run_ps(RUN_AT_MEDIUM, {"Script": str(E2E_MEDIUM)}, env=env)
    assert code == 0, f"the dashboard E2E failed (exit {code})"
