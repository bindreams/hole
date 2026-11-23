"""Connect through an installed Hole and fetch a page: the part of the journey that does not depend on the platform.

The Windows and macOS installer suites install the product their own way (`msi-installer/tests/installed/`,
`dmg-installer/tests/test_install_connect.py`), then hand this module an `InstalledHole`. Two journeys:

- `connect_and_fetch` starts the proxy in SOCKS-only mode, so no TUN device, route or DNS setting is involved, and the
  server and the target are on this host.
- `full_tunnel_journey` starts it as `hole proxy start` does by default, a full tunnel, and fetches pages from outside
  the machine by address and by name. The platform suite hands it a `MachineView`: what the operating system says of
  its routes, adapters and DNS, and a `curl` run as the person.
"""

import difflib
import http.server
import json
import os
import subprocess
import sys
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

# The `hole proxy start` default.
SOCKS_PORT = 4073

# Failure bound on one curl through the tunnel.
CURL_MAX_SECONDS = 60

# What a full tunnel is asked for, from outside the machine. Cloudflare answers its resolver's own address, and the name
# `one.one.one.one` that points at it, over plain HTTP with a redirect to HTTPS: one outside party, a stable status, and
# a `Location` that echoes the host the request named. `one.one.one.one` has AAAA records and the machine of this
# test may have no IPv6 route out, so the request by name asks for IPv4.
ADDRESS_URL = "http://1.1.1.1/"
ADDRESS_REDIRECT = "https://1.1.1.1/"
NAME_URL = "http://one.one.one.one/"
NAME_REDIRECT = "https://one.one.one.one/"

# (plugin named in the server entry, or None for plain Shadowsocks; the `ss_plugin_server` argument that serves it)
SERVERS: list[tuple[str | None, str]] = [("v2ray-plugin", "ex-ray"), ("galoshes", "galoshes"), (None, "none")]
SERVER_IDS = [plugin or "no-plugin" for plugin, _ in SERVERS]


class InstalledHole(Protocol):
    """The installed product, as one platform's suite reaches it."""

    def run(self, *args: str) -> subprocess.CompletedProcess[str]:
        """Run the installed `hole` with `args`, with the rights to reach the bridge.

        A command that never exits is the platform's to bound: Windows kills it and returns it as a failed command,
        macOS leaves it to the CI step's time limit.
        """
        ...

    def report(self, what: str, result: subprocess.CompletedProcess[str]) -> str:
        """The text of a failure: `what`, how `result` ended, and what the installed bridge logged."""
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


@contextmanager
def run_ss_server(kind: str, tmp_path: Path, outbound_interface: str | None = None) -> Iterator[dict]:
    """A shadowsocks server, plain or fronted by a server-mode plugin, via the plugin-e2e fixture.

    `kind` is the `ss_plugin_server` argument. With `outbound_interface`, the server's own dials leave through that
    interface, not the routing table: a server on the machine of a full tunnel needs it, or its dials loop back into
    the tunnel. Yields the server's description: the fields of a server entry, `plugin_opts` among them only for a
    plugin.
    """
    # Cargo reads a relative `CARGO_TARGET_DIR` from where it ran, the repo root; pytest runs in the suite's folder.
    target_dir = REPO_ROOT / os.environ.get("CARGO_TARGET_DIR", "target")
    exe = (
        target_dir / "debug" / "examples" / ("ss_plugin_server.exe" if sys.platform == "win32" else "ss_plugin_server")
    )
    assert exe.is_file(), f"{exe} missing - run `cargo build -p plugin-e2e --example ss_plugin_server`"

    # The fixture and its plugins write UTF-8; a Windows runner's default is its ANSI code page.
    stderr = (tmp_path / "ss_plugin_server.stderr").open("w+", encoding="utf-8", errors="replace")
    proc = subprocess.Popen(
        [str(exe), kind, *([outbound_interface] if outbound_interface else [])],
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


@pytest.fixture
def ss_server(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[dict]:
    """`run_ss_server`, parametrized indirectly with the `ss_plugin_server` argument."""
    with run_ss_server(request.param, tmp_path) as server:
        yield server


# The journey ==========================================================================================================


def server_entry(server: dict, plugin: str | None) -> dict:
    """The server entry a `hole proxy start --config-file` reads, for `server` as `run_ss_server` describes it.

    `plugin` is the plugin the entry names, `None` for plain Shadowsocks.
    """
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
    return entry


def fail_unless_started(hole: InstalledHole, started: subprocess.CompletedProcess[str], what: str) -> None:
    """Fail the case unless `started`, a `hole proxy start` of `what`, exited 0 and said that it started the proxy.

    `hole proxy start` exits 0 for a proxy that is already running, and says so. Without the output check an earlier
    case's surviving proxy would carry this case's requests, and the case would pass without its own start having
    brought a proxy up.
    """
    if started.returncode != 0:
        pytest.fail(hole.report(f"the installed bridge did not start {what}", started), pytrace=False)
    if started.stdout.strip() != f"proxy started on local_port {SOCKS_PORT}":
        pytest.fail(hole.report(f"the installed bridge did not report that it started {what}", started), pytrace=False)


def connect_and_fetch(
    hole: InstalledHole, server: dict, plugin: str | None, target: tuple[int, str], tmp_path: Path
) -> None:
    """Start the proxy for `server` through the installed bridge, fetch `target` through it, and stop the proxy.

    `server` is what `ss_server` yields; `plugin` is the plugin the entry names, `None` for plain Shadowsocks.
    """
    target_port, expected_body = target
    case = plugin or "a server with no plugin"
    config = tmp_path / "server.json"
    config.write_text(json.dumps(server_entry(server, plugin)), encoding="utf-8")

    fetched_ok = False
    # The stop runs whatever the start did, so no case leaves a proxy for the next one to find.
    try:
        started = hole.run(
            "proxy",
            "start",
            "--config-file",
            str(config),
            "--tunnel-mode",
            "socks-only",
            "--local-port",
            str(SOCKS_PORT),
        )
        fail_unless_started(hole, started, case)
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
            pytest.fail(
                hole.report(f"a request through {case} did not reach the target (expected {expected_body!r})", fetched),
                pytrace=False,
            )
        fetched_ok = True
    finally:
        stopped = hole.run("proxy", "stop")
        if stopped.returncode != 0:
            report_teardown_failure(hole.report("hole proxy stop failed", stopped), primary_ok=fetched_ok)


# Full tunnel ==========================================================================================================


@dataclass(frozen=True)
class Page:
    """What one `curl` of a URL came back with."""

    # curl's own exit code and stderr.
    result: subprocess.CompletedProcess[str]
    # `None` when curl got no response.
    status: int | None
    redirect: str
    body: str


class MachineView(Protocol):
    """What one platform tells a full-tunnel journey about the machine, and the `curl` of the person using it."""

    def default_interface(self) -> str:
        """The interface the machine's default route leaves by: where the far side's own dials must leave from."""
        ...

    def snapshot(self) -> str:
        """The machine's routes, adapters and DNS settings as text, equal before a start and after its stop."""
        ...

    def dns_servers(self) -> Mapping[str, frozenset[str]]:
        """The DNS servers the operating system itself reports, by the scope it reports them under (an adapter, a
        resolver): a name that stays the same for the same scope from one call to the next."""
        ...

    def run_curl(self, *args: str) -> subprocess.CompletedProcess[str]:
        """Run the system's `curl` as the person whose journey this is."""
        ...


def fetch(machine: MachineView, url: str, folder: Path, *, ipv4_only: bool) -> Page:
    """`curl` of `url` as the person: the status, the redirect it names and the body. `folder` is one the person can write."""
    body_file = folder / "page.body"
    body_file.unlink(missing_ok=True)
    result = machine.run_curl(
        "--silent",
        "--show-error",
        "--max-time",
        str(CURL_MAX_SECONDS),
        "--output",
        str(body_file),
        "--write-out",
        "%{http_code}|%{redirect_url}",
        *(["--ipv4"] if ipv4_only else []),
        url,
    )
    code, _, redirect = result.stdout.partition("|")
    status = int(code) if code.isdigit() and int(code) != 0 else None
    body = body_file.read_text(encoding="utf-8", errors="replace") if body_file.is_file() else ""
    return Page(result, status, redirect, body)


def dns_servers_gained(
    before: Mapping[str, frozenset[str]], during: Mapping[str, frozenset[str]]
) -> dict[str, frozenset[str]]:
    """The DNS servers of the scopes that exist now and did not exist before: what a tunnel adds, not what a lease
    renewal or a reconfiguration of the machine's own adapters changes. Any new scope with a server counts, the
    tunnel's own or one that comes up beside it."""
    return {scope: servers for scope, servers in during.items() if scope not in before and servers}


def full_tunnel_journey(
    hole: InstalledHole, server: dict, plugin: str | None, machine: MachineView, tmp_path: Path
) -> None:
    """Start the proxy as a person does, a full tunnel, fetch pages from outside the machine, and stop it.

    `server` must have been started with `machine.default_interface()` as its outbound interface. Fails if the start
    does not succeed, a page by address or by name does not arrive, the operating system reports no DNS server pointed
    at the tunnel, or the machine's routes, adapters and DNS settings after the stop are not those before the start.
    """
    case = plugin or "a server with no plugin"
    config = tmp_path / "server.json"
    config.write_text(json.dumps(server_entry(server, plugin)), encoding="utf-8")

    before = machine.snapshot()
    dns_before = machine.dns_servers()
    primary_ok = False
    # The stop runs whatever the start did, so no case leaves a tunnel up for the next one to find.
    try:
        # No `--tunnel-mode`: a full tunnel is the default.
        started = hole.run("proxy", "start", "--config-file", str(config))
        fail_unless_started(hole, started, f"a full tunnel through {case}")

        for how, url, redirect, ipv4_only in (
            ("by address", ADDRESS_URL, ADDRESS_REDIRECT, False),
            ("by name", NAME_URL, NAME_REDIRECT, True),
        ):
            page = fetch(machine, url, tmp_path, ipv4_only=ipv4_only)
            if page.result.returncode != 0 or page.status != 301 or page.redirect != redirect:
                pytest.fail(
                    hole.report(
                        f"a page requested {how} ({url}) through the full tunnel of {case} did not arrive: expected "
                        f"status 301 redirecting to {redirect}, got status {page.status} redirecting to {page.redirect!r}, "
                        f"body starting {page.body[:200]!r}",
                        page.result,
                    ),
                    pytrace=False,
                )

        if not dns_servers_gained(dns_before, machine.dns_servers()):
            pytest.fail(
                hole.report(
                    f"the full tunnel of {case} is up, but the operating system reports no DNS server under "
                    f"a scope it did not report before the start: nothing points the machine's lookups at the tunnel "
                    f"(before the start: {dict(dns_before)})",
                    started,
                ),
                pytrace=False,
            )
        primary_ok = True
    finally:
        stopped = hole.run("proxy", "stop")
        if stopped.returncode != 0:
            report_teardown_failure(hole.report("hole proxy stop failed", stopped), primary_ok=primary_ok)
        elif (after := machine.snapshot()) != before:
            changes = "\n".join(
                difflib.unified_diff(
                    before.splitlines(), after.splitlines(), "before the start", "after the stop", lineterm=""
                )
            )
            report_teardown_failure(
                hole.report(
                    f"the machine after the stop of {case} is not as it was before the start:\n{changes}", stopped
                ),
                primary_ok=primary_ok,
            )
