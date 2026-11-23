"""A script that runs the installed `hole` with its output piped gets what the command printed, before it exits.

A pipe is how every script, CI step and test of this suite reads a command. `hole` is a GUI-subsystem program that
leaves through `process::exit`, with a relay behind its stdout and stderr, so a command's text can be lost after the
command has finished. The command's exit code was always right; the text is what these tests read, together with the
`gui-cli.log` the command writes. `HOLE_LOG_DIR` puts that log in a folder of the test's own.
"""

import os
from pathlib import Path

import pytest
from support import BRIDGE_LOG, InstalledCli, take_log_baseline
from support import installed_hole, msi_path  # noqa: F401 (fixtures)

pytestmark = pytest.mark.system_wide

# This module's install and uninstall logs (`installed_hole`).
MSIEXEC_LOG_STEM = "msi-cli-output"

# How many times the error case runs. On the shipped 0.7.1 a run loses its stderr or its log line about one time in
# four, so one run proves little; this many make a miss as unlikely as a lost run is likely. A fixed `hole` loses
# nothing, so the count is a sample size, not a retry.
ERROR_RUNS = 24


@pytest.fixture
def hole(installed_hole: Path, tmp_path: Path) -> InstalledCli:
    return InstalledCli(take_log_baseline(BRIDGE_LOG), {**os.environ, "HOLE_LOG_DIR": str(tmp_path)})


def test_a_result_reaches_a_pipe(hole: InstalledCli):
    status = hole.run("bridge", "status")
    assert status.returncode == 0 and status.stdout.strip() == "installed (running)", hole.report(
        "`hole bridge status` did not print that the installed bridge is running", status
    )

    stopped = hole.run("proxy", "stop")
    assert stopped.returncode == 0 and stopped.stdout.strip() == "proxy stopped", hole.report(
        "`hole proxy stop` did not print that the proxy stopped", stopped
    )


def test_an_error_reaches_stderr_and_the_log(hole: InstalledCli, tmp_path: Path):
    absent = tmp_path / "absent.json"
    for run in range(1, ERROR_RUNS + 1):
        log = tmp_path / "gui-cli.log"
        log.unlink(missing_ok=True)

        failed = hole.run("proxy", "start", "--config-file", str(absent))

        what = f"run {run}: `hole proxy start` of a config file that does not exist"
        assert failed.returncode == 1, hole.report(f"{what} did not exit 1", failed)
        assert "failed to read" in failed.stderr and "absent.json" in failed.stderr, hole.report(
            f"{what} did not say on stderr that it could not read the file", failed
        )
        logged = log.read_text(encoding="utf-8", errors="replace") if log.exists() else ""
        assert "failed to read" in logged and "absent.json" in logged, hole.report(
            f"{what} did not write that to gui-cli.log (which holds {logged!r})", failed
        )
