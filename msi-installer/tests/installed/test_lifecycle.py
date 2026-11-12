"""The Windows installer lifecycle against the MSI under test, in order: install, verify, E2E, uninstall, verify.

The uninstall and its verification are the `installed_hole` fixture's teardown, so they run after a failed test too.
"""

from pathlib import Path

import pytest
from support import (
    BIN_DIR,
    DASHBOARD_E2E_TIMEOUT_SECONDS,
    E2E_MEDIUM,
    GSUDO_SELFTEST_TIMEOUT_SECONDS,
    RUN_AT_MEDIUM,
    VERIFY_GSUDO,
    installed_hole,
    machine_path_has_bin_dir,
    run_ps,
)
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


@pytest.fixture(scope="module")
def gsudo_deelevation_verified(installed_hole: Path, e2e_environment: dict[str, str]) -> None:
    """Run the gsudo self-test once; fail every test that needs it, by name, when it does not pass.

    The child exits 7 only when every contract check passes: a nonzero sentinel that also proves the exit code
    survives the launcher. A module fixture caches its failure, so the dashboard E2E fails at once instead of wedging
    a second time on the same broken launcher.
    """
    env = {**e2e_environment, "HOLE_SELFTEST_CANARY": "canary-ok"}
    code = run_ps(
        RUN_AT_MEDIUM,
        {"Script": str(VERIFY_GSUDO)},
        env=env,
        timeout_seconds=GSUDO_SELFTEST_TIMEOUT_SECONDS,
        phase="the gsudo de-elevation self-test",
    )
    assert code == 7, f"gsudo self-test failed (exit {code}); see the child output above"


def test_gsudo_deelevation_contract(gsudo_deelevation_verified: None):
    """De-elevation preserves what the E2E needs: Medium integrity, env, PATH (npm), streamed stdout, the exit code."""


def test_dashboard_e2e_at_medium_integrity(
    installed_hole: Path, e2e_environment: dict[str, str], gsudo_deelevation_verified: None
):
    """WebDriverIO smoke test of the INSTALLED binary: the dashboard loads the bundled frontend.

    `e2e-medium.ps1` checks inside the de-elevated child that `HOLE_TEST_APP_PATH` arrived and points at a real
    binary, rather than letting wdio fall back to the uninstalled workspace build. It needs the gsudo self-test to
    pass (`gsudo_deelevation_verified`).
    """
    env = {**e2e_environment, "HOLE_TEST_APP_PATH": str(BIN_DIR / "hole.exe")}
    code = run_ps(
        RUN_AT_MEDIUM,
        {"Script": str(E2E_MEDIUM)},
        env=env,
        timeout_seconds=DASHBOARD_E2E_TIMEOUT_SECONDS,
        phase="the dashboard E2E",
    )
    assert code == 0, f"the dashboard E2E failed (exit {code})"
