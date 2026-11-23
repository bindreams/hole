"""The installed product connects: the `HoleBridge` service the MSI registered starts a proxy and passes traffic.

Every other test that starts a proxy runs a bridge built for the test, as a child of the test. This one asks the
service, which the service manager started from the installed `hole.exe`, through the installed `hole.exe` CLI, for a
server behind each bundled plugin and for one with no plugin.

A separate file with its own install and its own `msiexec` logs: a failed connect then cannot change what the dashboard
E2E or the upgrade meets.
The connection itself is `connect_journey`, shared with the macOS installer suite. It needs the `ss_plugin_server`
example built (`cargo build -p plugin-e2e --example ss_plugin_server`) and the working tree's `galoshes` and `ex-ray`
builds, which serve the other end.
"""

from pathlib import Path

import pytest
from connect_journey import SERVER_IDS, SERVERS, connect_and_fetch
from connect_journey import ss_server, target  # noqa: F401 (fixtures)
from support import BRIDGE_LOG, InstalledCli, take_log_baseline
from support import installed_hole, msi_path  # noqa: F401 (fixtures)

pytestmark = pytest.mark.system_wide

# This module's install and uninstall logs (`installed_hole`).
MSIEXEC_LOG_STEM = "msi-connect"


@pytest.fixture
def hole(installed_hole: Path) -> InstalledCli:
    return InstalledCli(take_log_baseline(BRIDGE_LOG))


@pytest.mark.parametrize(("plugin", "ss_server"), SERVERS, indirect=["ss_server"], ids=SERVER_IDS)
def test_installed_service_connects(
    hole: InstalledCli, ss_server: dict, target: tuple[int, str], plugin: str | None, tmp_path: Path
):
    connect_and_fetch(hole, ss_server, plugin, target, tmp_path)
