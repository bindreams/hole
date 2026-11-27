"""Connect through an installed Hole and fetch a page: the part of the journey that does not depend on the platform.

The Windows and macOS installer suites install the product their own way (`msi-installer/tests/installed/`,
`dmg-installer/tests/test_install_connect.py`), then hand this module an `InstalledHole`. Two journeys:

- `connect_and_fetch` starts the proxy in SOCKS-only mode, so no TUN device, route or DNS setting is involved, and the
  server and the target are on this host.
- `full_tunnel_journey` starts it as `hole proxy start` does by default, a full tunnel, and fetches pages from outside
  the machine by address and by name, and for a plugin that carries UDP sends one datagram that draws a QUIC Version
  Negotiation reply. The far side says what it relayed, and the platform suite hands the journey a
  `MachineView`: what the operating system says of its routes, adapters and DNS, and a `curl` run as the person.
"""

import difflib
import http.server
import ipaddress
import json
import os
import re
import subprocess
import sys
import threading
import time
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generic, Protocol, TypeVar

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

# The `hole proxy start` default.
SOCKS_PORT = 4073

# Failure bound on one curl through the tunnel.
CURL_MAX_SECONDS = 60
# Failure bound on the operating system's notice that a change it was asked for has taken effect (`settle_on_notices`).
SETTLE_SECONDS = 30

# What a full tunnel is asked for, from outside the machine. Cloudflare answers `http://1.1.1.1/` and
# `http://one.one.one.one/` with a stable redirect to HTTPS on the same host. `one.one.one.one` has AAAA records and the
# machine of this test may have no IPv6 route out, so the request by name asks for IPv4.
ADDRESS_URL = "http://1.1.1.1/"
ADDRESS_REDIRECT = "https://1.1.1.1/"
ADDRESS_TARGETS = ("1.1.1.1:80",)
NAME_URL = "http://one.one.one.one/"
NAME_REDIRECT = "https://one.one.one.one/"
# The A records of `one.one.one.one`.
NAME_TARGETS = ("1.1.1.1:80", "1.0.0.1:80")

# The DNS servers a start is given when its config names none (`DnsConfig::default()`), in their order.
DNS_SERVERS = ("1.1.1.1", "1.0.0.1")
# The two halves of IPv4 that a full tunnel routes into its device (`tun_engine::routing`).
SPLIT_ROUTES = frozenset({"0.0.0.0/1", "128.0.0.0/1"})
# The IPv4 default route, as a `Route` destination.
DEFAULT_ROUTE = "0.0.0.0/0"

# Turns on the far side's line for each relay it opens: a TCP connection at `debug` (`tcprelay`), a UDP datagram at
# `trace` (`udprelay`, which `ss_plugin_server` routes into `tracing` down to that level).
RELAY_LOG = "shadowsocks_service::server::tcprelay=debug,shadowsocks_service::server::udprelay=trace"
_RELAY = re.compile(r"established tcp tunnel \S+ <-> (\S+) with ")
_UDP_RELAY = re.compile(r"udp relay \S+ -> (\S+) with (\d+) bytes, control")

# The datagram the person sends in each case that carries UDP: a QUIC long-header packet with a reserved version, which a
# server answers with Version Negotiation (RFC 9000 sections 6.1 and 17.2.1). The sender builds the packet from
# `UDP_SIZE` and the matcher counts the far side's relay lines by `UDP_TARGET` and `UDP_SIZE`, so they cannot disagree.
#
# The count is exact because nothing on the runners sends to `8.8.4.4` or `8.8.8.8` during a case. The far-side logs of
# PR #1411's CI runs on darwin arm64, darwin amd64 and windows amd64 show no relay to either address but the journey's
# own, and a bare-runner probe got Version Negotiation from `8.8.4.4:443` on macos-26-arm64, macos-15, ubuntu-26.04 and
# windows-2025. The size is a second distinction only: it is above 1200, the smallest datagram that draws Version
# Negotiation. A QUIC connection sends packets of any size once its handshake is done, so the contract above, not the
# size, keeps the count exact.
UDP_HOST = "8.8.4.4"
UDP_PORT = 443
UDP_TARGET = f"{UDP_HOST}:{UDP_PORT}"
UDP_SIZE = 1237
UDP_SENDER = Path(__file__).with_name("quic_version_negotiation_probe.py")
# Failure bound on the server's answer to that datagram, set well beyond a slow runner's. The sender resends the same
# datagram until the answer comes, so the bound is the only timer that decides failure.
UDP_REPLY_SECONDS = 60
# The version field of a Version Negotiation packet.
VERSION_NEGOTIATION = 0
# The plugins whose connection carries UDP; `v2ray-plugin` is TCP-only, and the product drops a UDP flow for it.
UDP_PLUGINS = (None, "galoshes")

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


@dataclass(frozen=True)
class SsServer:
    """A running `ss_plugin_server`."""

    # The fields of a server entry, `plugin_opts` among them only for a plugin.
    description: dict
    # Where the server's stderr goes while it runs.
    stderr: Path

    def relayed(self) -> list[str]:
        """The target (`host:port`) of every relay the server has opened so far, in order.

        The server writes the line once its own connection to the target is up and before it carries a byte, so a
        response that came through the server has its line here by the time it arrives.
        """
        return _RELAY.findall(self.stderr.read_text(encoding="utf-8", errors="replace"))

    def udp_relayed(self) -> list[tuple[str, int]]:
        """The target (`host:port`) and size in bytes of every UDP datagram the server has relayed so far, in order.

        The server writes the line when it takes the datagram in, before it sends it on.
        """
        lines = _UDP_RELAY.findall(self.stderr.read_text(encoding="utf-8", errors="replace"))
        return [(target, int(size)) for target, size in lines]

    def udp_relayed_count(self) -> int:
        """How many datagrams of the person's own (`UDP_TARGET`, `UDP_SIZE`) the server has relayed so far."""
        return self.udp_relayed().count((UDP_TARGET, UDP_SIZE))


@dataclass(frozen=True)
class Outbound:
    """Where the far side's own dials leave from: an interface and its own IPv4 address."""

    interface: str
    address: str


@contextmanager
def run_ss_server(
    kind: str, tmp_path: Path, outbound: Outbound | None = None, listen: str | None = None
) -> Iterator[SsServer]:
    """A shadowsocks server, plain or fronted by a server-mode plugin, via the plugin-e2e fixture.

    `kind` is the `ss_plugin_server` argument. With `outbound`, the server's own dials leave through that interface, not
    the routing table, or they loop back into the tunnel of the machine it runs on; on Windows its sockets are also bound
    to the address. `listen` is the address the server, or the plugin in front of it,
    listens on: loopback when `None`. It needs an `outbound`.
    """
    assert outbound is not None or listen is None, "a listen address comes with an outbound interface"
    if outbound is not None and not outbound.interface.strip():
        pytest.fail(
            f"the outbound interface asked for for the far side is empty ({outbound.interface!r}), which would send its "
            "dials through the routing table, back into the tunnel: the machine named no default interface",
            pytrace=False,
        )
    if outbound is not None:
        try:
            ipaddress.IPv4Address(outbound.address)
        except ValueError:
            pytest.fail(
                f"the address asked for for the far side's dials ({outbound.address!r}) is not an IPv4 address of "
                f"{outbound.interface}: the machine named none",
                pytrace=False,
            )
    # Cargo reads a relative `CARGO_TARGET_DIR` from where it ran, the repo root; pytest runs in the suite's folder.
    target_dir = REPO_ROOT / os.environ.get("CARGO_TARGET_DIR", "target")
    exe = (
        target_dir / "debug" / "examples" / ("ss_plugin_server.exe" if sys.platform == "win32" else "ss_plugin_server")
    )
    assert exe.is_file(), f"{exe} missing - run `cargo build -p plugin-e2e --example ss_plugin_server`"

    # The example reads the listen address after the interface and its address.
    server_args = [outbound.interface, outbound.address, *([listen] if listen else [])] if outbound else []
    stderr_path = tmp_path / "ss_plugin_server.stderr"
    with stderr_path.open("wb") as stderr:
        proc = subprocess.Popen(
            [str(exe), kind, *server_args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr,
            # Added to a developer's own directives, which the fixture reads as a comma-separated list.
            env={**os.environ, "HOLE_TEST_LOG": ",".join(filter(None, [os.environ.get("HOLE_TEST_LOG"), RELAY_LOG]))},
            text=True,
            # The fixture and its plugins write UTF-8; a Windows runner's default is its ANSI code page.
            encoding="utf-8",
            errors="replace",
        )
    assert proc.stdin is not None and proc.stdout is not None

    def stderr_text() -> str:
        return stderr_path.read_text(encoding="utf-8", errors="replace")

    try:
        # One JSON line once the server is serving; EOF if the fixture died first.
        line = proc.stdout.readline()
        if not line:
            proc.wait()
            pytest.fail(f"ss_plugin_server {kind} exited before serving:\n{stderr_text()}", pytrace=False)
        yield SsServer(json.loads(line), stderr_path)
    finally:
        proc.stdin.close()
        proc.wait()
        # pytest shows captured output only for a failed test.
        print(f"=== ss_plugin_server {kind} stderr ===\n{stderr_text()}")


@contextmanager
def run_far_side(kind: str, tmp_path: Path, machine: "MachineView") -> Iterator[SsServer]:
    """`run_ss_server` for a full tunnel, as the machine says it is reached.

    The server's own dials leave through the machine's default interface (on Windows, bound to its address). It listens
    where the machine says it is reached (`machine.far_side_address()`), TCP and UDP both, and its description names
    that address.
    """
    outbound = Outbound(machine.default_interface(), machine.default_interface_address())
    with run_ss_server(kind, tmp_path, outbound, machine.far_side_address()) as server:
        yield server


@pytest.fixture
def ss_server(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[dict]:
    """The description of a `run_ss_server`, parametrized indirectly with the `ss_plugin_server` argument."""
    with run_ss_server(request.param, tmp_path) as server:
        yield server.description


# The journey ==========================================================================================================


def server_entry(server: dict, plugin: str | None) -> dict:
    """The server entry a `hole proxy start --config-file` reads, for `server`, an `SsServer.description`.

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


# The machine of a full tunnel =========================================================================================


T = TypeVar("T")


class MachineReadError(Exception):
    """The operating system could not be asked about the machine's network: a command failed or printed nothing usable."""


@dataclass(frozen=True, order=True)
class Route:
    # An IPv4 network as `a.b.c.d/len`; anything else as the platform prints it.
    destination: str
    gateway: str
    interface: str
    # What else the platform says of the route and a tunnel must leave as it was: its metric, its flags.
    detail: str = ""


@dataclass(frozen=True, order=True)
class Resolver:
    """One place the operating system keeps DNS servers: an adapter's list for one address family on Windows, a
    resolver of `scutil --dns` on macOS."""

    # What tells it from the others, its servers aside.
    scope: str
    # In the system's order. Empty when the system has none of its own choosing there.
    servers: tuple[str, ...]
    # Empty for a resolver the system ties to no interface.
    interface: str


@dataclass(frozen=True)
class Snapshot:
    """What the operating system says of the machine's network at one moment, each part sorted.

    It leaves out what changes with no tunnel involved: neighbour and cloned routes, temporary IPv6 addresses, the
    reachability and query flags of a resolver.
    """

    interfaces: tuple[str, ...]
    routes: tuple[Route, ...]
    # `<interface> <address>/<prefix length>`, or the platform's own words for the same.
    addresses: tuple[str, ...]
    resolvers: tuple[Resolver, ...]
    # What the commands that made this reading printed, in full, as the parsers read it. Printed by the journey; two
    # readings of the same state are equal whatever they printed.
    raw: str = field(default="", compare=False, repr=False)

    def lines(self) -> list[str]:
        return [
            *(f"interface {name}" for name in self.interfaces),
            *(f"route {r.destination} via {r.gateway} on {r.interface} {r.detail}".rstrip() for r in self.routes),
            *(f"address {address}" for address in self.addresses),
            *(f"resolver {r.scope}: {', '.join(r.servers) or 'no server'}" for r in self.resolvers),
        ]


@dataclass(frozen=True)
class Settled(Generic[T]):
    """What `ChangeWatch.settle` read."""

    reading: T
    # Empty when `reading` is one for which `settled` held; otherwise what ran out, for the report.
    unsettled: str = ""


def settle_on_notices(
    read: Callable[[], T],
    settled: Callable[[T], bool],
    *,
    arm: Callable[[], None],
    wait: Callable[[float], bool],
    source: str,
) -> Settled[T]:
    """`read()` until `settled` holds, reading again on each notice from the system that something changed.

    `arm()` is called before each reading, so a notice that arrives after it is not lost; `wait(seconds)` returns
    when a notice has arrived (`True`) or the time is up (`False`). The system is not ours, so a notice that never
    comes ends the wait after `SETTLE_SECONDS`: the last reading is then returned with the bound named in
    `unsettled`, for the caller to fail on. `source` names the notice, for that text.
    """
    deadline = time.monotonic() + SETTLE_SECONDS
    while True:
        arm()
        reading = read()
        if settled(reading):
            return Settled(reading)
        remaining = deadline - time.monotonic()
        if remaining > 0 and wait(remaining):
            continue
        # A change whose notice never came is still a change.
        reading = read()
        if settled(reading):
            return Settled(reading)
        return Settled(
            reading,
            f"no notice of a change from {source} in the {SETTLE_SECONDS} s allowed, and the reading still did not hold",
        )


class ChangeWatch(Protocol):
    """A wait for the operating system to take in a change a command made, begun before the command ran."""

    def settle(self, read: Callable[[], T], settled: Callable[[T], bool]) -> Settled[T]:
        """`read()` once the system has settled: the first reading for which `settled` holds.

        Where the system finishes a change after the call that made it returns, each further reading waits for the
        system's own notice of a change (`settle_on_notices`).
        """
        ...


class MachineView(Protocol):
    """What one platform tells a full-tunnel journey about the machine, and the `curl` of the person using it."""

    def default_interface(self) -> str:
        """The interface the machine's default route leaves by: where the far side's own dials must leave from."""
        ...

    def default_interface_address(self) -> str:
        """The IPv4 address of `default_interface()`, which the far side's sockets are bound to on Windows."""
        ...

    def far_side_address(self) -> str | None:
        """The address a far side on this machine listens on, or `None` for loopback.

        An address of the machine's own makes the product install the host route that keeps its connection to the
        server out of the tunnel (`bypass_problems` reads it). `None` where the system refuses that route.
        """
        ...

    def snapshot(self) -> Snapshot:
        """The machine's interfaces, routes, addresses and DNS servers now. Raises `MachineReadError`."""
        ...

    def watch_changes(self) -> AbstractContextManager[ChangeWatch]:
        """Entered before a start or a stop, so that no change the command makes is missed."""
        ...

    def run_curl(self, *args: str) -> subprocess.CompletedProcess[str]:
        """Run the system's `curl` as the person whose journey this is."""
        ...

    def run_python(self, script: Path, *args: str) -> subprocess.CompletedProcess[str]:
        """Run `script` with the interpreter that runs this test, as the person whose journey this is."""
        ...


@dataclass(frozen=True)
class Page:
    """What one `curl` of a URL came back with."""

    # curl's own exit code and stderr.
    result: subprocess.CompletedProcess[str]
    # `None` when curl got no response.
    status: int | None
    redirect: str
    body: str


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


# The checks of a full tunnel ==========================================================================================
# Each returns the problems it found, as text, and none stops the others: a failure names every check that is red.


def page_problems(
    machine: MachineView,
    server: SsServer,
    how: str,
    url: str,
    redirect: str,
    targets: tuple[str, ...],
    folder: Path,
    *,
    ipv4_only: bool,
) -> list[str]:
    """Fetch `url` as the person; the page must arrive, and the far side must have opened a relay to one of `targets`
    for it.

    The answer alone shows nothing: the same page arrives from a machine with no tunnel. The relay shows that the
    request went into the tunnel's device, through the proxy and its plugin, and out of the far side.
    """

    def relays() -> int:
        return sum(1 for target in server.relayed() if target in targets)

    relays_before = relays()
    page = fetch(machine, url, folder, ipv4_only=ipv4_only)
    opened = relays() - relays_before
    if page.result.returncode != 0 or page.status != 301 or page.redirect != redirect:
        return [
            f"the page requested {how} ({url}) did not arrive: expected status 301 redirecting to {redirect}, got "
            f"status {page.status} redirecting to {page.redirect!r}, body starting {page.body[:200]!r}; curl exited "
            f"{page.result.returncode}: {page.result.stderr.strip()} (the far side opened {opened} relay(s) to "
            f"{' or '.join(targets)} meanwhile)"
        ]
    if opened < 1:
        return [
            f"the page requested {how} ({url}) arrived, but not through the tunnel: the far side opened no relay to "
            f"{' or '.join(targets)} while it was fetched (every relay it has opened so far: {server.relayed()})"
        ]
    return []


def udp_problems(machine: MachineView, server: SsServer) -> list[str]:
    """The person's datagram draws Version Negotiation from `UDP_TARGET`; the reply must reach the person's socket and
    answer it, and the far side must have relayed the datagram at least once and no more often than it was sent.

    The sender sends the same datagram until a reply comes, so the answer is a Version Negotiation packet whose
    connection IDs are the datagram's own, swapped (RFC 9000 section 17.2.1), whichever send it answers. The reply alone
    shows nothing: it needs the far side's relay to have carried the datagram. The count is read once, after the sender
    exits, and the healthy range is `1 <= relays <= sends`: sends made after the one that was answered can still be in
    the tunnel, and the far side writes its relay line before it forwards. More relays than sends is a datagram that came
    back to the far side: its own relay re-entering the tunnel.
    """
    relays_before = server.udp_relayed_count()
    sent = machine.run_python(UDP_SENDER, UDP_HOST, str(UDP_PORT), str(UDP_SIZE), str(UDP_REPLY_SECONDS))
    relays = server.udp_relayed_count() - relays_before
    what = f"{UDP_SIZE} bytes to {UDP_TARGET}"
    try:
        answer = json.loads(sent.stdout)
    except json.JSONDecodeError:
        return [
            f"the person's datagram of {what} did not run: exit {sent.returncode}, stdout {sent.stdout!r}, "
            f"stderr {sent.stderr.strip()!r} (the far side relayed {relays} such datagram(s) meanwhile)"
        ]
    sends = answer["sends"]
    counts = f"the person sent {sends} such datagram(s) and the far side relayed {relays}"
    if answer.get("error"):
        return [
            f"the person's datagram of {what} drew {answer['error']}: the target was unreachable from their socket; "
            f"{counts}"
        ]
    problems = []
    if answer["reply"] is None:
        problems.append(
            f"no reply to the person's datagram of {what} reached their socket in {UDP_REPLY_SECONDS} s; {counts}"
            + (" (the datagram never reached the far side)" if relays == 0 else "")
        )
    elif (answer["version"], answer["dcid"], answer["scid"]) != (
        VERSION_NEGOTIATION,
        answer["sent_scid"],
        answer["sent_dcid"],
    ):
        problems.append(
            f"the datagram that reached the person's socket is not Version Negotiation for the one they sent "
            f"(version {VERSION_NEGOTIATION}, connection IDs swapped): {answer}"
        )
    elif relays == 0:
        problems.append(
            f"the reply arrived, but the far side logged no relay for it; {counts} (the matcher does not see the far "
            f"side's lines)"
        )
    if relays > sends:
        problems.append(
            f"the far side relayed more such datagrams than the person sent; {counts} (the far side's own relay "
            f"re-entering the tunnel)"
        )
    return problems


def interfaces_gained(before: Snapshot, during: Snapshot) -> list[str]:
    return sorted(set(during.interfaces) - set(before.interfaces))


def resolvers_gained(before: Snapshot, during: Snapshot) -> list[Resolver]:
    """The resolvers with a server that `during` has and `before` had not. One whose servers changed counts: it is
    not the resolver it was."""
    return sorted(r for r in (Counter(during.resolvers) - Counter(before.resolvers)).elements() if r.servers)


def dns_problems(before: Snapshot, during: Snapshot) -> list[str]:
    """While the tunnel is up the operating system holds exactly one resolver it had not before, with the servers the
    start was given, on the tunnel's interface where the system ties resolvers to one.

    This reads what the system was told. Whether its lookups then go to that resolver is not seen here.
    """
    gained = resolvers_gained(before, during)
    tunnel = interfaces_gained(before, during)
    if len(gained) != 1:
        return [
            f"the operating system gained {len(gained)} resolver(s) with a server while the tunnel is up, expected "
            f"exactly one, holding {list(DNS_SERVERS)}: {gained}"
        ]
    (resolver,) = gained
    problems = []
    if resolver.servers != DNS_SERVERS:
        problems.append(
            f"the resolver the tunnel added ({resolver.scope}) holds {list(resolver.servers)}, not the servers the "
            f"start was given, {list(DNS_SERVERS)}"
        )
    if resolver.interface and [resolver.interface] != tunnel:
        problems.append(
            f"the resolver the tunnel added is on {resolver.interface}, not on the one interface the tunnel added "
            f"({tunnel})"
        )
    return problems


def device_problems(before: Snapshot, during: Snapshot) -> list[str]:
    """While the tunnel is up the machine has exactly one interface it had not before, and both halves of IPv4 are
    routed into it.

    It also shows that a snapshot can see a tunnel at all, without which a snapshot after the stop that equals the
    one before the start says nothing.
    """
    tunnel = interfaces_gained(before, during)
    if len(tunnel) != 1:
        return [f"the machine gained {len(tunnel)} interface(s) while the tunnel is up, expected exactly one: {tunnel}"]
    routed = {route.destination for route in during.routes if route.interface == tunnel[0]}
    if not SPLIT_ROUTES <= routed:
        return [
            f"the routes into the tunnel's interface {tunnel[0]} do not hold both halves of IPv4 "
            f"({sorted(SPLIT_ROUTES)}): {sorted(routed)}"
        ]
    return []


def bypass_problems(before: Snapshot, during: Snapshot, address: str) -> list[str]:
    """While the tunnel is up the route table holds a host route to the server at `address` through the gateway the
    default route had before the start, which the product installs to keep its own connection to the server out of the
    tunnel.

    It is read from the table. Where the server is an address of this machine the system delivers to it locally, so the
    route is installed and removed (the comparison after the stop sees it gone) but carries nothing.
    """
    host_routes = {address, f"{address}/32"}
    gateways = {route.gateway for route in before.routes if route.destination == DEFAULT_ROUTE}
    if not gateways:
        return [
            f"the machine had no default route before the start, so the route for the server {address} cannot be told"
        ]
    if any(route.destination in host_routes and route.gateway in gateways for route in before.routes):
        return [
            f"the route for the server {address} through {sorted(gateways)} was already in the table before the start"
        ]
    if any(route.destination in host_routes and route.gateway in gateways for route in during.routes):
        return []
    named = [route for route in during.routes if route.destination in host_routes]
    return [
        f"no host route for the server {address} through the gateway of the default route before the start "
        f"({sorted(gateways)}) while the tunnel is up; the routes naming the server: {named}"
    ]


def show_machine(when: str, snapshot: Snapshot) -> None:
    """Print what the commands behind `snapshot` said, in full, whether the case passes or fails."""
    if snapshot.raw:
        print(f"=== what the machine's commands printed {when} ===\n{snapshot.raw}", flush=True)


def stop_problems(hole: InstalledHole, machine: MachineView, before: Snapshot) -> list[str]:
    """Stop the proxy; the machine's interfaces, routes, addresses and DNS servers must then be those of `before`."""
    with machine.watch_changes() as watch:
        stopped = hole.run("proxy", "stop")
        if stopped.returncode != 0:
            return [f"hole proxy stop exited {stopped.returncode}: {stopped.stdout.strip()} {stopped.stderr.strip()}"]
        try:
            settled = watch.settle(machine.snapshot, lambda snapshot: snapshot == before)
        except MachineReadError as e:
            return [f"the machine could not be read after the stop: {e}"]
    after = settled.reading
    if after == before:
        return []
    changes = difflib.unified_diff(before.lines(), after.lines(), "before the start", "after the stop", lineterm="")
    problems = ["the machine after the stop is not as it was before the start:\n" + "\n".join(changes)]
    return [settled.unsettled, *problems] if settled.unsettled else problems


def full_tunnel_journey(
    hole: InstalledHole, server: SsServer, plugin: str | None, machine: MachineView, tmp_path: Path
) -> None:
    """Start the proxy as a person does, a full tunnel, fetch pages from outside the machine, and stop it.

    `server` must come from `run_far_side`, whose own dials leave by the machine's default interface; where that
    interface is `en0` of a Mac, `MacMachine.scoped_default_route` must be held too, or the far side's dials, bound to
    the interface, get `ENETUNREACH` once the tunnel's routes win the table. Fails if the start does not succeed, and
    then for each of these that does not hold: a page by address and one by name arrive through the far side
    (`page_problems`), for a plugin that carries UDP one datagram of the person's is answered through the far side
    (`udp_problems`), the system holds the tunnel's resolver (`dns_problems`) and its device and routes
    (`device_problems`), and after the stop the machine is as it was (`stop_problems`).

    For a server that is not on loopback it also checks the route that keeps the product's connection to the server out
    of the tunnel (`bypass_problems`). On loopback the product installs none, and the journey does not see that route.
    """
    case = plugin or "a server with no plugin"
    address = server.description["server"]
    config = tmp_path / "server.json"
    config.write_text(json.dumps(server_entry(server.description, plugin)), encoding="utf-8")

    before = machine.snapshot()
    show_machine("before the start", before)
    # The stop runs whatever the start did, so no case leaves a tunnel up for the next one to find.
    try:
        with machine.watch_changes() as watch:
            # No `--tunnel-mode`: a full tunnel is the default.
            started = hole.run("proxy", "start", "--config-file", str(config))
            fail_unless_started(hole, started, f"a full tunnel through {case}")
            settled = watch.settle(machine.snapshot, lambda snapshot: not dns_problems(before, snapshot))
        during = settled.reading
        show_machine("while the tunnel is up", during)
        problems = [
            *([settled.unsettled] if settled.unsettled else []),
            *page_problems(
                machine, server, "by address", ADDRESS_URL, ADDRESS_REDIRECT, ADDRESS_TARGETS, tmp_path, ipv4_only=False
            ),
            *page_problems(machine, server, "by name", NAME_URL, NAME_REDIRECT, NAME_TARGETS, tmp_path, ipv4_only=True),
            *(udp_problems(machine, server) if plugin in UDP_PLUGINS else []),
            *dns_problems(before, during),
            *device_problems(before, during),
            *([] if ipaddress.ip_address(address).is_loopback else bypass_problems(before, during, address)),
        ]
    except BaseException:
        # That failure stays the reported one.
        for problem in stop_problems(hole, machine, before):
            print(f"teardown after an earlier failure:\n{problem}", file=sys.stderr)
        raise
    problems += stop_problems(hole, machine, before)
    if problems:
        numbered = "\n".join(f"{n}. {problem}" for n, problem in enumerate(problems, 1))
        pytest.fail(hole.report(f"the full tunnel through {case} is not right:\n{numbered}", started), pytrace=False)
