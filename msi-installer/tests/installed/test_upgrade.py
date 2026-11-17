"""The upgrade over a running bridge service, and the uninstall that follows it on the shipped Restart Manager default.

A separate file, run after `test_lifecycle.py`: the upgrade refuses a machine with Hole on it, and the lifecycle's
module fixture keeps Hole installed until its last test.
"""

from collections.abc import Iterator
from pathlib import Path

import pytest
from support import (
    RESTART_MANAGER_DISABLED,
    RESTART_MANAGER_PROPERTY,
    SERVICE,
    RestartManager,
    assert_custom_action_ran,
    assert_msiexec_stopped_a_running_bridge,
    assert_stop_came_from_the_uninstall,
    install_msi,
    install_run,
    log_dir,
    missing_canonical_files,
    take_cli_log_baseline,
    wait_until_service_running,
)
from support import msi_path, service_registered  # noqa: F401 (fixtures)
from windows_installer import installed_hole_product_codes, msi_product_code, set_msi_property

import msi_installer

pytestmark = pytest.mark.system_wide


@pytest.fixture
def previous_hole(msi_path: Path, request: pytest.FixtureRequest) -> Iterator[str]:
    """Install a second MSI linked from the same staged files, with its bridge running; yield its ProductCode.

    That MSI is patched to carry `MSIRESTARTMANAGERCONTROL=Disable` in its own Property table: the upgrade's nested
    removal of it reads its package's properties, not the outer command line, and would otherwise have Restart Manager
    stop the bridge before the old `BridgeUninstall` ran.

    Teardown uninstalls whichever of the two products remains, with Restart Manager on, and checks Restart Manager shut
    the service down.
    """
    logs = log_dir()
    previous_msi = msi_installer.link_msi(logs / "hole-previous.msi")
    set_msi_property(previous_msi, RESTART_MANAGER_PROPERTY, RESTART_MANAGER_DISABLED)
    with install_run(
        request,
        previous_msi,
        install_log=logs / "msi-upgrade-previous-install.log",
        uninstall_log=logs / "msi-upgrade-uninstall.log",
        restart_manager=RestartManager.ON,
        installed_later=[msi_path],
    ) as (previous_code, _):
        yield previous_code


def test_upgrade_over_a_running_bridge(msi_path: Path, previous_hole: str):
    """The old product's `BridgeUninstall` stops the running service; the new one is registered and RUNNING after."""
    log = log_dir() / "msi-upgrade-install.log"
    cli_log_baseline = take_cli_log_baseline()
    install_msi(msi_path, log, RestartManager.OFF)

    assert installed_hole_product_codes() == [msi_product_code(msi_path)], "the upgrade must leave only the new product"
    assert service_registered(), f"{SERVICE} service not registered after the upgrade"
    wait_until_service_running()
    assert not missing_canonical_files(), "files the installer must install are missing after the upgrade"
    assert_msiexec_stopped_a_running_bridge(cli_log_baseline, log)
    assert_stop_came_from_the_uninstall(cli_log_baseline)
    assert_custom_action_ran(log, "BridgeUninstall")
