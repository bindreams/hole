"""Connect through an installed Hole and fetch a page: the part of the journey that does not depend on the platform.

The Windows and macOS installer suites install the product their own way (`msi-installer/tests/installed/`,
`dmg-installer/tests/test_install_connect.py`), then hand this module an `InstalledHole`. The proxy is started in
SOCKS-only mode, so no TUN device, route or DNS setting is involved, and the server and the target are on this host.
"""

import http.server
import json
import os
import subprocess
import sys
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import NoReturn, Protocol

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

# The `hole proxy start` default.
SOCKS_PORT = 4073

# Failure bound on one curl through the tunnel.
CURL_MAX_SECONDS = 60

# (plugin named in the server entry, or None for plain Shadowsocks; the `ss_plugin_server` argument that serves it)
SERVERS: list[tuple[str | None, str]] = [("v2ray-plugin", "ex-ray"), ("galoshes", "galoshes"), (None, "none")]
SERVER_IDS = [plugin or "no-plugin" for plugin, _ in SERVERS]


class InstalledHole(Protocol):
    """The installed product, as one platform's suite reaches it."""

    def run(self, *args: str) -> subprocess.CompletedProcess[str]:
        """Run the installed `hole` with `args`, with the rights to reach the bridge."""
        ...

    def fail(self, what: str, result: subprocess.CompletedProcess[str]) -> NoReturn:
        """Fail the test with `what`, `result` and what the installed bridge logged."""
        ...


def report_teardown_failure(report: str, primary_ok: bool) -> None:
    """Fail on a teardown problem only when nothing failed before it; otherwise that failure stays the reported one."""
    if primary_ok:
        pytest.fail(report, pytrace=False)
    print(f"teardown after an earlier failure:\n{report}", file=sys.stderr)


# Fixtures =============================================================================================================


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
    """A shadowsocks server, plain or fronted by a server-mode plugin, via the plugin-e2e fixture.

    Parametrized indirectly with the `ss_plugin_server` argument. Yields the server's description: the fields of a
    server entry, `plugin_opts` among them only for a plugin.
    """
    kind: str = request.param
    target_dir = Path(os.environ.get("CARGO_TARGET_DIR", REPO_ROOT / "target"))
    exe = (
        target_dir / "debug" / "examples" / ("ss_plugin_server.exe" if sys.platform == "win32" else "ss_plugin_server")
    )
    assert exe.is_file(), f"{exe} missing - run `cargo build -p plugin-e2e --example ss_plugin_server`"

    # The fixture and its plugins write UTF-8; a Windows runner's default is its ANSI code page.
    stderr = (tmp_path / "ss_plugin_server.stderr").open("w+", encoding="utf-8", errors="replace")
    proc = subprocess.Popen(
        [str(exe), kind],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=stderr,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert proc.stdin is not None and proc.stdout is not None
    try:
        # One JSON line once the server is serving; EOF if the fixture died first.
        line = proc.stdout.readline()
        if not line:
            proc.wait()
            stderr.seek(0)
            pytest.fail(f"ss_plugin_server {kind} exited before serving:\n{stderr.read()}", pytrace=False)
        yield json.loads(line)
    finally:
        proc.stdin.close()
        proc.wait()
        # pytest shows captured output only for a failed test.
        stderr.seek(0)
        print(f"=== ss_plugin_server {kind} stderr ===\n{stderr.read()}")
        stderr.close()


# The journey ==========================================================================================================


def connect_and_fetch(
    hole: InstalledHole, server: dict, plugin: str | None, target: tuple[int, str], tmp_path: Path
) -> None:
    """Start the proxy for `server` through the installed bridge, fetch `target` through it, and stop the proxy.

    `server` is what `ss_server` yields; `plugin` is the plugin the entry names, `None` for plain Shadowsocks.
    """
    target_port, expected_body = target
    case = plugin or "a server with no plugin"
    entry = {
        "id": "install-e2e",
        "name": "install-e2e",
        "server": server["server"],
        "server_port": server["server_port"],
        "method": server["method"],
        "password": server["password"],
    }
    if plugin is not None:
        entry |= {"plugin": plugin, "plugin_opts": server["plugin_opts"]}
    config = tmp_path / "server.json"
    config.write_text(json.dumps(entry), encoding="utf-8")

    started = hole.run(
        "proxy", "start", "--config-file", str(config), "--tunnel-mode", "socks-only", "--local-port", str(SOCKS_PORT)
    )
    if started.returncode != 0:
        hole.fail(f"the installed bridge could not start {case}", started)
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
            encoding="utf-8",
            errors="replace",
        )
        if fetched.returncode != 0 or fetched.stdout != expected_body:
            hole.fail(f"a request through {case} did not reach the target (expected {expected_body!r})", fetched)
        fetched_ok = True
    finally:
        stopped = hole.run("proxy", "stop")
        if stopped.returncode != 0:
            report_teardown_failure(
                f"hole proxy stop failed: exit {stopped.returncode}\n--- stdout ---\n{stopped.stdout}\n"
                f"--- stderr ---\n{stopped.stderr}",
                primary_ok=fetched_ok,
            )
