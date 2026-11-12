"""Install the built Hole.app's bridge as root and connect through each bundled plugin.

Every other test that starts a plugin runs the bridge from the build's staging
directory, where the plugins sit beside `hole`. This one runs the bridge the way
a user's machine does: `hole bridge install` copies the `hole` binary to
/Library/PrivilegedHelperTools and launchd runs that copy as root. A start that
names a bundled plugin must still find it.

Elevation is `sudo -n`, where the GUI uses osascript; both run the same
`hole bridge install` as root with SUDO_USER set. IPC goes through the `hole
proxy` CLI under sudo: a fresh `hole` group membership does not reach this
process until its next login.
"""

import http.server
import json
import os
import re
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

import dmg_installer
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

REPO_ROOT = dmg_installer._find_repo_root()

pytestmark = pytest.mark.install_e2e

# The `hole proxy start` default.
SOCKS_PORT = 4073

# JSON for `BridgeRequest::Status`.
STATUS_REQUEST = '"Status"'

# Failure bound on one curl through the tunnel.
CURL_MAX_SECONDS = 60

# (plugin name in the server entry, fixture binary that serves it)
PLUGINS = [("v2ray-plugin", "ex-ray"), ("galoshes", "galoshes")]

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


def report_teardown_failure(report: str, primary_ok: bool) -> None:
    """Fail on a teardown problem only when nothing failed before it; otherwise that failure stays the reported one."""
    if primary_ok:
        pytest.fail(report, pytrace=False)
    print(f"teardown after an earlier failure:\n{report}", file=sys.stderr)


@dataclass
class Bridge:
    hole: Path

    def hole_as_root(self, *args: str) -> subprocess.CompletedProcess[str]:
        return sudo(str(self.hole), *args)

    def fail(self, what: str, r: subprocess.CompletedProcess[str]) -> None:
        pytest.fail(f"{what}: {describe(r)}\n=== bridge log ===\n{bridge_log()}", pytrace=False)


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
        r = b.hole_as_root("bridge", "install", "--log-dir", str(log_dir), "--repair-user-data-dir", str(user_data_dir))
        if r.returncode != 0:
            b.fail("hole bridge install failed", r)

        status_file = tmp_path_factory.mktemp("status") / "status.json"
        last_report = None
        while True:
            # `ipc-send` deletes its request file, so write it for every attempt.
            status_file.write_text(STATUS_REQUEST)
            r = b.hole_as_root("bridge", "ipc-send", "--request-file", str(status_file))
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


@pytest.fixture
def target() -> Iterator[tuple[int, str]]:
    """A local HTTP server for the tunnel to reach: (port, expected body)."""
    body = f"hole-install-e2e-{os.getpid()}"

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], body
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


@pytest.fixture
def ss_server(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[dict]:
    """A shadowsocks server fronted by the server-mode plugin, via the plugin-e2e fixture."""
    plugin_binary: str = request.param
    target_dir = Path(os.environ.get("CARGO_TARGET_DIR", REPO_ROOT / "target"))
    exe = target_dir / "debug" / "examples" / "ss_plugin_server"
    assert exe.is_file(), f"{exe} missing - run `cargo build -p plugin-e2e --example ss_plugin_server`"

    stderr = (tmp_path / "ss_plugin_server.stderr").open("w+")
    proc = subprocess.Popen(
        [str(exe), plugin_binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, text=True
    )
    assert proc.stdin is not None and proc.stdout is not None
    try:
        # One JSON line once the server is serving; EOF if the fixture died first.
        line = proc.stdout.readline()
        if not line:
            proc.wait()
            stderr.seek(0)
            pytest.fail(f"ss_plugin_server {plugin_binary} exited before serving:\n{stderr.read()}", pytrace=False)
        yield json.loads(line)
    finally:
        proc.stdin.close()
        proc.wait()
        # pytest shows captured output only for a failed test.
        stderr.seek(0)
        print(f"=== ss_plugin_server {plugin_binary} stderr ===\n{stderr.read()}")
        stderr.close()


# Tests ================================================================================================================


@pytest.mark.parametrize(("plugin", "ss_server"), PLUGINS, indirect=["ss_server"], ids=[p for p, _ in PLUGINS])
def test_installed_bridge_connects_through_bundled_plugin(
    bridge: Bridge, ss_server: dict, target: tuple[int, str], plugin: str, tmp_path: Path
) -> None:
    target_port, expected_body = target
    entry = {
        "id": "install-e2e",
        "name": "install-e2e",
        "server": ss_server["server"],
        "server_port": ss_server["server_port"],
        "method": ss_server["method"],
        "password": ss_server["password"],
        "plugin": plugin,
        "plugin_opts": ss_server["plugin_opts"],
    }
    config = tmp_path / "server.json"
    config.write_text(json.dumps(entry))

    started = bridge.hole_as_root(
        "proxy",
        "start",
        "--config-file",
        str(config),
        "--tunnel-mode",
        "socks-only",
        "--local-port",
        str(SOCKS_PORT),
    )
    if started.returncode != 0:
        bridge.fail(f"the installed bridge could not start {plugin}", started)
    fetched_ok = False
    try:
        fetched = subprocess.run(
            [
                "curl",
                "--silent",
                "--show-error",
                "--fail",
                "--max-time",
                str(CURL_MAX_SECONDS),
                "--socks5-hostname",
                f"127.0.0.1:{SOCKS_PORT}",
                f"http://127.0.0.1:{target_port}/",
            ],
            capture_output=True,
            text=True,
        )
        if fetched.returncode != 0 or fetched.stdout != expected_body:
            bridge.fail(f"a request through {plugin} did not reach the target (expected {expected_body!r})", fetched)
        fetched_ok = True
    finally:
        stopped = bridge.hole_as_root("proxy", "stop")
        if stopped.returncode != 0:
            report_teardown_failure(f"hole proxy stop failed: {describe(stopped)}", primary_ok=fetched_ok)
