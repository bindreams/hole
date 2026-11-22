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

import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest
from connect_journey import SERVER_IDS, SERVERS, connect_and_fetch
from connect_journey import ss_server, target  # noqa: F401 (fixtures)
from support import BIN_DIR, BRIDGE_LOG, HOLE_CLI_TIMEOUT_SECONDS, LogBaseline, hole_command_report, take_log_baseline
from support import installed_hole, msi_path  # noqa: F401 (fixtures)

pytestmark = pytest.mark.system_wide

# This module's install and uninstall logs (`installed_hole`).
MSIEXEC_LOG_STEM = "msi-connect"


@dataclass(frozen=True)
class InstalledCli:
    """The installed `hole.exe`, run from this elevated process: the bridge's socket admits Administrators."""

    # The service's log as the test found it: a failure shows what the log gained since.
    bridge_log: LogBaseline

    def run(self, *args: str) -> subprocess.CompletedProcess[str]:
        command = [str(BIN_DIR / "hole.exe"), *args]
        try:
            # `hole` writes UTF-8; the default decoding is the ANSI code page.
            return subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=HOLE_CLI_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as e:
            # Returned as a failed command, not raised: the journey reports those, and a stop that hangs after a
            # failed start must not replace that failure.
            return subprocess.CompletedProcess(
                command,
                returncode=-1,
                stdout=e.stdout if isinstance(e.stdout, str) else "",
                stderr=(e.stderr if isinstance(e.stderr, str) else "")
                + f"\n(killed: no exit within {HOLE_CLI_TIMEOUT_SECONDS}s)",
            )

    def report(self, what: str, result: subprocess.CompletedProcess[str]) -> str:
        return hole_command_report(what, result, self.bridge_log)


@pytest.fixture
def hole(installed_hole: Path) -> InstalledCli:
    return InstalledCli(take_log_baseline(BRIDGE_LOG))


@pytest.mark.parametrize(("plugin", "ss_server"), SERVERS, indirect=["ss_server"], ids=SERVER_IDS)
def test_installed_service_connects(
    hole: InstalledCli, ss_server: dict, target: tuple[int, str], plugin: str | None, tmp_path: Path
):
    connect_and_fetch(hole, ss_server, plugin, target, tmp_path)
