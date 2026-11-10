"""Install the built Hole.app's bridge as root and connect through each bundled plugin.

Every other test that starts a plugin runs the bridge from the build's staging
directory, where the plugins sit beside `hole`. This one runs the bridge the way
a user's machine does: `hole bridge install` copies the `hole` binary to
/Library/PrivilegedHelperTools and launchd runs that copy as root. A start that
names a bundled plugin must still find it.

The test mutates the host (root daemon, launchd job, /var/log/hole), so it is
opt-in: marked `install_e2e`, excluded by default (pyproject.toml `addopts`),
and run by `cargo xtask run hole-dmg-install-e2e` on a CI runner with
passwordless sudo. It refuses to start over an existing install.

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

REPO_ROOT = dmg_installer._find_repo_root()

pytestmark = pytest.mark.install_e2e

# Installed layout. Mirrors `crates/bridge/src/platform/macos.rs` and
# `hole_common::protocol::default_bridge_socket_path`.
LAUNCHD_LABEL = "com.hole.bridge"
HELPER_PATH = Path("/Library/PrivilegedHelperTools/com.hole.bridge")
PLIST_PATH = Path("/Library/LaunchDaemons/com.hole.bridge.plist")
SOCKET_PATH = Path("/var/run/hole-bridge.sock")
SERVICE_DIRS = [Path("/var/log/hole"), Path("/var/db/hole")]

# The `hole proxy start` default; a fresh runner has nothing else on it.
SOCKS_PORT = 4073

# `hole bridge ipc-send` request for `BridgeRequest::Status` (a unit variant).
STATUS_REQUEST = '"Status"'

# Bound on a curl through the tunnel: the end of an external exchange, surfaced
# as a failure to a human, never used to decide that the tunnel is up.
CURL_MAX_SECONDS = 60

# (plugin name in the server entry, fixture binary that serves it)
PLUGINS = [("v2ray-plugin", "ex-ray"), ("galoshes", "galoshes")]

# Helpers ==============================================================================================================


def sudo(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["sudo", "-n", *args], capture_output=True, text=True)


def describe(r: subprocess.CompletedProcess[str]) -> str:
    return f"exit {r.returncode}\n--- stdout ---\n{r.stdout}\n--- stderr ---\n{r.stderr}"


def bridge_log() -> str:
    """Everything the installed bridge wrote under /var/log/hole."""
    r = sudo("sh", "-c", 'for f in /var/log/hole/*; do echo "=== $f"; cat "$f"; done')
    return r.stdout + r.stderr


def read_job() -> str:
    """The bridge's launchd job as `launchctl print` shows it."""
    r = sudo("launchctl", "print", f"system/{LAUNCHD_LABEL}")
    if r.returncode != 0:
        pytest.fail(
            f"cannot read the bridge's launchd job: {describe(r)}\n=== bridge log ===\n{bridge_log()}", pytrace=False
        )
    return r.stdout


def job_exit(job: str) -> str | None:
    """How launchd records the job's last end, `None` while it has never ended."""
    # A job killed by a signal has no exit code to read.
    if (killed := re.search(r"last terminating signal = (.*)", job)) is not None:
        return f"terminated by signal: {killed.group(1).strip()}"
    if (code := re.search(r"last exit code = (.*)", job)) is None:
        pytest.fail(
            f"no exit record in the bridge's launchd job:\n{job}\n=== bridge log ===\n{bridge_log()}", pytrace=False
        )
    return None if "never exited" in code.group(1) else f"exit code {code.group(1).strip()}"


def job_state(job: str) -> str:
    state = re.search(r"^\s*state = (.*)$", job, re.MULTILINE)
    return state.group(1).strip() if state is not None else "unknown"


def emit(request: pytest.FixtureRequest, text: str) -> None:
    """Write to stderr past pytest's capture, which drops it on an interrupt and a SIGKILL never flushes."""
    capture = request.config.pluginmanager.getplugin("capturemanager")
    with capture.global_and_fixture_disabled():
        print(text, file=sys.stderr, flush=True)


def tear_down(b: "Bridge", preexisting_dirs: set[Path]) -> list[str]:
    """Uninstall the bridge and remove what it left. Returns what went wrong, with the bridge's log."""
    log = bridge_log()  # before the removal
    problems = []
    r = b.hole_as_root("bridge", "uninstall")
    if r.returncode != 0:
        problems.append(f"hole bridge uninstall failed: {describe(r)}")
    for d in SERVICE_DIRS:
        if d not in preexisting_dirs:
            sudo("rm", "-rf", str(d))
    status = b.hole_as_root("bridge", "status")
    if status.returncode != 2:
        problems.append(f"bridge still installed after uninstall: {describe(status)}")
    remaining = [p for p in (HELPER_PATH, PLIST_PATH, SOCKET_PATH) if p.exists()]
    if remaining:
        problems.append(f"uninstall left files behind: {remaining}")
    if problems:
        problems.append(f"=== bridge log ===\n{log}")
    return problems


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
    preexisting_dirs = {d for d in SERVICE_DIRS if d.exists()}

    # The fixture quarantines its copy; strip it so a Gatekeeper verdict on the
    # copied helper cannot stand in for what this test measures.
    subprocess.run(["xattr", "-dr", "com.apple.quarantine", str(installed_app)], check=True)
    b = Bridge(hole=installed_app / "Contents" / "MacOS" / "hole")

    log_dir = tmp_path_factory.mktemp("install-log")
    user_data_dir = Path.home() / "Library" / "Application Support" / "hole"
    ready = False
    try:
        # The arguments `setup::run_elevated_install` passes.
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
            # The step may end by a timeout that kills this process before any teardown runs, so the evidence is
            # printed as it changes rather than at the end.
            report = f"=== bridge not ready; launchd state: {job_state(job)}; last ipc-send: {describe(r)}"
            if report != last_report:
                emit(request, report)
                last_report = report
            # Paced re-check (CONTRIBUTING "No sleeps for synchronization", class 3): readiness is a Status round
            # trip that no event announces. `--ready-notify` cannot serve it: `bridge run --service`, the launchd
            # job, rejects it. Every pass re-reads the state; nothing is concluded from the interval, and the wait
            # has no cap of its own: a bridge that stays up but never answers ends at the CI step's timeout, and
            # the step after it prints the log.
            time.sleep(0.5)

        ready = True
        yield b
    finally:
        problems = tear_down(b, preexisting_dirs)
        if problems:
            report_teardown_failure("\n".join(problems), primary_ok=ready)


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
