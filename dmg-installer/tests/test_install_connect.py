"""Install the built Hole.app's bridge as root and connect through each bundled plugin and without one.

Every other test that starts a plugin runs the bridge from the build's staging
directory, where the plugins sit beside `hole`. This one runs the bridge the way
a user's machine does: `hole bridge install` copies the `hole` binary to
/Library/PrivilegedHelperTools and launchd runs that copy as root. A start that
names a bundled plugin must still find it.

The connection itself is `connect_journey`, shared with the Windows installer suite: a SOCKS-only start that fetches
a local page, and a full tunnel that fetches pages from outside the machine and, for a plugin that carries UDP, sends
one QUIC Version Negotiation trigger through it.

Elevation is `sudo -n`, where the GUI uses osascript; both run the same
`hole bridge install` as root with SUDO_USER set. IPC goes through the `hole
proxy` CLI under sudo: a fresh `hole` group membership does not reach this
process until its next login.
"""

import re
import subprocess
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from connect_journey import (
    SERVER_IDS,
    SERVERS,
    connect_and_fetch,
    full_tunnel_journey,
    report_teardown_failure,
    run_far_side,
)
from connect_journey import ss_server, target  # noqa: F401 (fixtures)
from macos_machine import MacMachine

from dmg_installer.installed_bridge import (
    HELPER_PATH,
    LAUNCHD_LABEL,
    PLIST_PATH,
    Preexisting,
    SOCKET_PATH,
    bridge_log,
    describe,
    job_state,
    sudo,
    tear_down,
)

pytestmark = pytest.mark.install_e2e

# JSON for `BridgeRequest::Status`.
STATUS_REQUEST = '"Status"'

# Helpers ==============================================================================================================


def read_job() -> str:
    """The bridge's launchd job as `launchctl print` shows it."""
    r = sudo("launchctl", "print", f"system/{LAUNCHD_LABEL}")
    if r.returncode != 0:
        pytest.fail(
            f"cannot read the bridge's launchd job: {describe(r)}\n=== bridge log ===\n{bridge_log()}", pytrace=False
        )
    return r.stdout


def job_exit(job: str) -> str | None:
    """How launchd records the job's last end, `None` while it has not ended, which includes a job with no exit record yet."""
    if (killed := re.search(r"last terminating signal = (.*)", job)) is not None:
        return f"terminated by signal: {killed.group(1).strip()}"
    if (code := re.search(r"last exit code = (.*)", job)) is None or "never exited" in code.group(1):
        return None
    return f"exit code {code.group(1).strip()}"


def job_program(job: str) -> str | None:
    """The executable launchd runs for the job."""
    program = re.search(r"^\s*program = (.*)$", job, re.MULTILINE)
    return program.group(1).strip() if program is not None else None


def emit(request: pytest.FixtureRequest, text: str) -> None:
    """Write to stderr past pytest's capture, which drops it on an interrupt and a SIGKILL never flushes."""
    capture = request.config.pluginmanager.getplugin("capturemanager")
    with capture.global_and_fixture_disabled():
        print(text, file=sys.stderr, flush=True)


@dataclass
class Bridge:
    hole: Path

    def run(self, *args: str) -> subprocess.CompletedProcess[str]:
        """Run the installed app's `hole` as root."""
        return sudo(str(self.hole), *args)

    def report(self, what: str, result: subprocess.CompletedProcess[str]) -> str:
        return f"{what}: {describe(result)}\n=== bridge log ===\n{bridge_log()}"

    def fail(self, what: str, result: subprocess.CompletedProcess[str]) -> None:
        pytest.fail(self.report(what, result), pytrace=False)


# Fixtures =============================================================================================================


@pytest.fixture(scope="module")
def bridge(
    request: pytest.FixtureRequest, installed_app: Path, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[Bridge]:
    """Install the app's bridge, wait until it answers, uninstall on teardown."""
    leftovers = [p for p in (HELPER_PATH, PLIST_PATH, SOCKET_PATH) if p.exists()]
    if leftovers:
        pytest.fail(f"refusing to install over an existing Hole bridge: {leftovers}", pytrace=False)
    preexisting = Preexisting.snapshot()

    # The fixture quarantines its copy; strip it so a Gatekeeper verdict on the
    # copied helper cannot stand in for what this test measures.
    subprocess.run(["xattr", "-dr", "com.apple.quarantine", str(installed_app)], check=True)
    b = Bridge(hole=installed_app / "Contents" / "MacOS" / "hole")

    log_dir = tmp_path_factory.mktemp("install-log")
    user_data_dir = Path.home() / "Library" / "Application Support" / "hole"
    ready = False
    try:
        # The arguments the GUI's install runs (`setup::elevated_bridge_args`).
        r = b.run("bridge", "install", "--log-dir", str(log_dir), "--repair-user-data-dir", str(user_data_dir))
        if r.returncode != 0:
            b.fail("hole bridge install failed", r)

        status_file = tmp_path_factory.mktemp("status") / "status.json"
        last_report = None
        while True:
            # `ipc-send` deletes its request file, so write it for every attempt.
            status_file.write_text(STATUS_REQUEST)
            r = b.run("bridge", "ipc-send", "--request-file", str(status_file))
            if r.returncode == 0:
                break
            job = read_job()
            # A bridge that exited (a launchd job with KeepAlive restarts it) will not answer: fail with its log.
            if (exit_code := job_exit(job)) is not None:
                b.fail(f"the installed bridge exited ({exit_code}) before answering", r)
            # A step timeout kills this process before teardown, so print evidence as it changes.
            report = f"=== bridge not ready; launchd state: {job_state(job)}; last ipc-send: {describe(r)}"
            if report != last_report:
                emit(request, report)
                last_report = report
            # Readiness is a Status round trip no event announces (`bridge run --service`, the launchd job, rejects
            # `--ready-notify`); re-poll until it answers. The CI step timeout bounds a bridge that never does.
            time.sleep(0.5)

        job = read_job()
        if job_program(job) != str(HELPER_PATH):
            pytest.fail(
                f"the bridge runs {job_program(job)!r}, not the installed copy {HELPER_PATH}:\n{job}\n"
                f"=== bridge log ===\n{bridge_log()}",
                pytrace=False,
            )
        ready = True
        yield b
    finally:
        log = bridge_log()  # before the teardown removes it
        problems = tear_down(b.hole, preexisting)
        if problems:
            report_teardown_failure("\n".join([*problems, f"=== bridge log ===\n{log}"]), primary_ok=ready)


# Tests ================================================================================================================


@pytest.mark.parametrize(("plugin", "ss_server"), SERVERS, indirect=["ss_server"], ids=SERVER_IDS)
def test_installed_bridge_connects(
    bridge: Bridge, ss_server: dict, target: tuple[int, str], plugin: str | None, tmp_path: Path
) -> None:
    connect_and_fetch(bridge, ss_server, plugin, target, tmp_path)


@pytest.mark.parametrize(("plugin", "kind"), SERVERS, ids=SERVER_IDS)
def test_installed_bridge_carries_a_full_tunnel(bridge: Bridge, plugin: str | None, kind: str, tmp_path: Path) -> None:
    """The default of `hole proxy start`: every route in the tunnel, DNS pointed at Hole, pages from outside the machine.

    The far side runs on this machine, so its own dials leave through the default interface, not the routing table the
    tunnel now owns. It is reached at the interface's own address, so the product installs the host route that keeps its
    connection to the server out of the tunnel, and the case checks that it is installed and removed. The system
    delivers to an address of its own locally, so nothing crosses that route.

    The far side's dials are bound to `en0`, and a runner has no default route in that scope: the case adds one for its
    duration and deletes it after, if it added it (`MacMachine.scoped_default_route`). That route also changes what the
    product's own interface-bound sockets see (bindreams/hole#1414), so a macOS journey of a Bypass rule runs without
    it. The case needs the internet.
    """
    machine = MacMachine()
    with machine.scoped_default_route(), run_far_side(kind, tmp_path, machine) as server:
        full_tunnel_journey(bridge, server, plugin, machine, tmp_path)
