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
import subprocess
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


@dataclass
class Bridge:
    hole: Path

    def hole_as_root(self, *args: str) -> subprocess.CompletedProcess[str]:
        return sudo(str(self.hole), *args)

    def fail(self, what: str, r: subprocess.CompletedProcess[str]) -> None:
        pytest.fail(f"{what}: {describe(r)}\n=== bridge log ===\n{bridge_log()}", pytrace=False)


# Fixtures =============================================================================================================


@pytest.fixture(scope="module")
def bridge(installed_app: Path, tmp_path_factory: pytest.TempPathFactory) -> Iterator[Bridge]:
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
    try:
        # The arguments `setup::run_elevated_install` passes.
        r = b.hole_as_root("bridge", "install", "--log-dir", str(log_dir), "--repair-user-data-dir", str(user_data_dir))
        if r.returncode != 0:
            b.fail("hole bridge install failed", r)

        request = tmp_path_factory.mktemp("status") / "status.json"
        while True:
            # `ipc-send` deletes its request file, so write it for every attempt.
            # Ready means a Status round trip succeeds; the wait ends on that and
            # on nothing else, bounded by the CI step's timeout.
            request.write_text(STATUS_REQUEST)
            if b.hole_as_root("bridge", "ipc-send", "--request-file", str(request)).returncode == 0:
                break
            time.sleep(0.5)

        yield b
    finally:
        r = b.hole_as_root("bridge", "uninstall")
        for d in SERVICE_DIRS:
            if d not in preexisting_dirs:
                sudo("rm", "-rf", str(d))
        if r.returncode != 0:
            b.fail("hole bridge uninstall failed", r)
        status = b.hole_as_root("bridge", "status")
        assert status.returncode == 2, f"bridge still installed after uninstall: {describe(status)}"
        remaining = [p for p in (HELPER_PATH, PLIST_PATH, SOCKET_PATH) if p.exists()]
        assert not remaining, f"uninstall left files behind: {remaining}"


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
    exe = target_dir / "release" / "examples" / "ss_plugin_server"
    assert exe.is_file(), f"{exe} missing - run `cargo build --release -p plugin-e2e --example ss_plugin_server`"

    stderr = (tmp_path / "ss_plugin_server.stderr").open("w+")
    proc = subprocess.Popen([str(exe), plugin_binary],
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=stderr,
                            text=True)
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
    finally:
        stopped = bridge.hole_as_root("proxy", "stop")
        assert stopped.returncode == 0, f"hole proxy stop failed: {describe(stopped)}"
