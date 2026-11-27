"""Connect through an installed Hole and fetch a page: the part of the journey that does not depend on the platform.

The Windows and macOS installer suites install the product their own way (`msi-installer/tests/installed/`,
`dmg-installer/tests/test_install_connect.py`), then hand this module an `InstalledHole`. Two journeys:

- `connect_and_fetch` starts the proxy in SOCKS-only mode, so no TUN device, route or DNS setting is involved, and the
  server and the target are on this host.
- `full_tunnel_journey` starts it as `hole proxy start` does by default, a full tunnel, and fetches pages from outside
  the machine by address and by name, and for a plugin that carries UDP sends a datagram, resent until answered, that
  draws a QUIC Version Negotiation reply. After the stop it looks up a name no cache holds. The far side says what it
  relayed, and the platform suite hands the journey a `MachineView`: what the operating system says of its routes,
  adapters and DNS, and a `curl` and a Python run as the person.
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
import uuid
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, ExitStack, contextmanager
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
# The routes that capture all of IPv4 and IPv6 into a full tunnel's device (`tun_engine::routing::SPLIT_ROUTES`), as
# each platform's snapshot prints them.
SPLIT_ROUTES = frozenset({"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"})
# The IPv4 default route, as a `Route` destination.
DEFAULT_ROUTE = "0.0.0.0/0"

# Turns on the far side's line for each relay it opens: a TCP connection at `debug` (`tcprelay`), a UDP datagram at
# `trace` (`udprelay`, which `ss_plugin_server` routes into `tracing` down to that level).
RELAY_LOG = "shadowsocks_service::server::tcprelay=debug,shadowsocks_service::server::udprelay=trace"
_RELAY = re.compile(r"established tcp tunnel \S+ <-> (\S+) with ")
_UDP_RELAY = re.compile(r"udp relay (\S+) -> (\S+) with (\d+) bytes, control")

# The datagram the person sends in each case that carries UDP: a QUIC long-header packet with a reserved version, which a
# server answers with Version Negotiation (RFC 9000 sections 6.1 and 17.2.1). The sender builds the packet from
# `UDP_SIZE` and the matcher counts the far side's relay lines by `UDP_TARGET` and `UDP_SIZE`, so they cannot disagree.
#
# The check rests on two contracts, measured in CI (docs/contributing/installers.md): nothing else on the runners sends
# to `UDP_TARGET` during a case, and the product keeps one UDP association per source socket for the life of the probe,
# so the far side sees every send from one client address. The size is a second distinction only (above 1200, the
# smallest datagram that draws Version Negotiation).
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
# The lookup the person makes after the stop: a name made up for the case, under a domain whose every name resolves
# (GitHub Pages answers any name under `github.io`). No cache holds a name nobody asked before, so an answer came from
# the resolver the system holds now. A name that exists is needed: on Windows an unknown name ends in Python's
# `[Errno 11001]` (`WSAHOST_NOT_FOUND`), an error that does not say whether a resolver answered.
LOOKUP_DOMAIN = "github.io"
LOOKUP_SENDER = Path(__file__).with_name("lookup_probe.py")
# Failure bound on the answer to that lookup.
LOOKUP_SECONDS = 60
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

    def udp_relayed(self) -> list[tuple[str, str, int]]:
        """The client address (`host:port`, where the server took the datagram in from), target (`host:port`) and size in
        bytes of every UDP datagram the server has relayed so far, in order.

        The server writes the line when it takes the datagram in, before it sends it on.
        """
        lines = _UDP_RELAY.findall(self.stderr.read_text(encoding="utf-8", errors="replace"))
        return [(client, target, int(size)) for client, target, size in lines]


@dataclass(frozen=True)
class Outbound:
    """Where the far side's own dials leave from: an interface and its own IPv4 address."""

    interface: str
    address: str

    def __post_init__(self) -> None:
        # An empty interface would send the far side's dials through the routing table, back into the tunnel. Both
        # machine readers raise before they return one, so this is a contract, not an input.
        assert self.interface.strip(), "the machine named no default interface for the far side's dials"
        try:
            ipaddress.IPv4Address(self.address)
        except ValueError:
            raise AssertionError(
                f"the address for the far side's dials ({self.address!r}) is not an IPv4 address of {self.interface}"
            ) from None


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

    ok = False
    try:
        # One JSON line once the server is serving; EOF if the fixture died first.
        line = proc.stdout.readline()
        if not line:
            proc.wait()
            pytest.fail(f"ss_plugin_server {kind} exited before serving:\n{stderr_text()}", pytrace=False)
        yield SsServer(json.loads(line), stderr_path)
        ok = True
    finally:
        proc.stdin.close()
        exit_code = proc.wait()
        # pytest shows captured output only for a failed test.
        print(f"=== ss_plugin_server {kind} stderr ===\n{stderr_text()}")
        # The server serves until its stdin closes and then exits 0; another code is a crash during the case.
        if exit_code != 0:
            report_teardown_failure(
                f"ss_plugin_server {kind} exited {exit_code} after its stdin closed:\n{stderr_text()}", primary_ok=ok
            )


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
    # Empty when `reading` is one for which `settled` held; otherwise what ran out, for the report. The reading is then
    # the last one made before the bound ran out, whatever a later one would say.
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
    when a notice has arrived (`True`) or the time is up (`False`). One return may stand for many notices. The system is
    not ours, so `SETTLE_SECONDS` is the failure report on a notice it never sent: when it runs out the last reading is
    returned with `unsettled` giving the number of readings and which way the time ran out. A reading is begun only
    when the clock, read just before it, is inside the bound. `source` names the notices, for that text.
    """
    deadline = time.monotonic() + SETTLE_SECONDS
    readings = 0
    while True:
        arm()
        reading = read()
        readings += 1
        if settled(reading):
            return Settled(reading)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            ending = "the last reading ended past the bound"
        elif not wait(remaining):
            ending = f"no notice of a change came from {source} after the last reading"
        elif time.monotonic() >= deadline:
            ending = f"a notice from {source} came at the bound, too late for another reading"
        else:
            continue
        return Settled(
            reading, f"the {SETTLE_SECONDS} s bound ran out after {readings} reading(s), none of which held; {ending}"
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
    answer it, and the far side must have relayed the datagram, from one client address.

    The sender sends the same datagram until a reply comes, so the answer is a Version Negotiation packet whose
    connection IDs are the datagram's own, swapped (RFC 9000 section 17.2.1), whichever send it answers. The reply alone
    shows nothing: it needs the far side's relay to have carried the datagram.

    The relay check reads the lines this case added, once, after the sender exits. The far side writes its line before
    it forwards, so a reply that came through it has its line already: no line is a red whatever the reply was. A line
    from a second client address names the cause of a no-reply red. shadowsocks-service 1.24.0 keeps one outbound IPv4
    socket per association (`UdpAssociationContext`, `server/udprelay.rs`), so a datagram that comes back to the far side
    through the tunnel (a looping egress) arrives from a new address and draws no reply. Under the contracts at
    `UDP_TARGET`, a second address is such a datagram. The check does not see a datagram the product relays more than
    once from the one address, or a line the far side writes after the read.
    """
    seen = len(server.udp_relayed())
    sent = machine.run_python(UDP_SENDER, UDP_HOST, str(UDP_PORT), str(UDP_SIZE), str(UDP_REPLY_SECONDS))
    added = server.udp_relayed()[seen:]
    clients = Counter(client for client, target, size in added if (target, size) == (UDP_TARGET, UDP_SIZE))
    relays = clients.total()
    # In the order the far side first saw them, so the person's own comes first. The message shows four: a loop makes
    # thousands.
    addresses = list(clients.items())
    shown = ", ".join(f"{client} with {n}" for client, n in addresses[:4])
    more = f" and {len(addresses) - 4} more" if len(addresses) > 4 else ""
    relayed = f"the far side relayed {relays} from {len(addresses)} client address(es)" + (
        f": {shown}{more}" if addresses else ""
    )
    what = f"{UDP_SIZE} bytes to {UDP_TARGET}"
    try:
        answer = json.loads(sent.stdout)
    except json.JSONDecodeError:
        return [
            f"the person's datagram of {what} did not run: exit {sent.returncode}, stdout {sent.stdout!r}, "
            f"stderr {sent.stderr.strip()!r} ({relayed})"
        ]
    counts = f"the person sent {answer['sends']} such datagram(s); {relayed}"
    problems = []
    if answer["reply"] is None:
        problems.append(
            f"no reply to the person's datagram of {what} reached their socket in {UDP_REPLY_SECONDS} s"
            + (f", the last socket error was {answer['error']}" if answer.get("error") else "")
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
    if relays == 0:
        problems.append(
            "the far side logged no relay of the person's datagram"
            + (", although a reply arrived" if answer["reply"] is not None else "")
            + " (the datagram may have left the machine outside the tunnel, or never reached it; or the matcher does not "
            "see the far side's lines)"
        )
    if len(addresses) > 1:
        problems.append(
            "the far side took the person's datagram in from more than one client address (a datagram that came back to "
            "the far side, re-entering the tunnel)"
        )
    # The counts are stated once, on the first problem.
    if problems:
        problems[0] += f"; {counts}"
    return problems


def lookup_problems(machine: MachineView) -> list[str]:
    """The person looks up a name nobody has asked before, through the system resolver, and gets an answer.

    No cache holds the name, so the answer comes from the resolver the system holds now: a stop that left the
    machine's DNS confined to the tunnel (Windows confines port-53 egress to it) or pointed at it gets none.
    """
    name = f"hole-{uuid.uuid4().hex}.{LOOKUP_DOMAIN}"
    looked = machine.run_python(LOOKUP_SENDER, name, str(LOOKUP_SECONDS))
    try:
        answer = json.loads(looked.stdout)
    except json.JSONDecodeError:
        return [
            f"the person's lookup of {name} did not run: exit {looked.returncode}, stdout {looked.stdout!r}, "
            f"stderr {looked.stderr.strip()!r}"
        ]
    if answer["addresses"]:
        return []
    return [
        f"after the stop the system resolver gave the person no answer for {name}, a name no cache holds under a "
        f"domain whose every name resolves: {answer['error']}"
    ]


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
    """While the tunnel is up the machine has exactly one interface it had not before, and the `SPLIT_ROUTES` that
    capture all of IPv4 and IPv6 are routed into it.

    It also shows that a snapshot can see a tunnel at all, without which a snapshot after the stop that equals the
    one before the start says nothing.
    """
    tunnel = interfaces_gained(before, during)
    if len(tunnel) != 1:
        return [f"the machine gained {len(tunnel)} interface(s) while the tunnel is up, expected exactly one: {tunnel}"]
    routed = {route.destination for route in during.routes if route.interface == tunnel[0]}
    if not SPLIT_ROUTES <= routed:
        return [
            f"the routes into the tunnel's interface {tunnel[0]} do not hold the split routes "
            f"{sorted(SPLIT_ROUTES)}: {sorted(routed)}"
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


def tunnel_problems(before: Snapshot, during: Snapshot, address: str) -> list[str]:
    """What `during` shows wrong with the tunnel the start made: its DNS, its interface and routes, and, for a far side
    that is not on loopback, its route to the server. The start's settle waits for this to be empty."""
    problems = dns_problems(before, during) + device_problems(before, during)
    if not ipaddress.ip_address(address).is_loopback:
        problems += bypass_problems(before, during, address)
    return problems


def show_machine(when: str, snapshot: Snapshot) -> None:
    """Print what the commands behind `snapshot` said, in full, whether the case passes or fails."""
    if snapshot.raw:
        print(f"=== what the machine's commands printed {when} ===\n{snapshot.raw}", flush=True)


class _Unwatched:
    """The `ChangeWatch` of a machine whose notices could not be registered: one reading, no wait."""

    def settle(self, read: Callable[[], T], settled: Callable[[T], bool]) -> Settled[T]:
        reading = read()
        if settled(reading):
            return Settled(reading)
        return Settled(reading, "the reading did not hold, and it was not waited on: no change notice was registered")


@contextmanager
def watching(machine: MachineView, problems: list[str]) -> Iterator[ChangeWatch]:
    """`machine.watch_changes()`. When its notices cannot be registered, whatever the error, the problem is added to
    `problems` and the block runs with a watch that reads once, so the command inside it still runs. A release that
    fails is added to `problems` too, and never replaces what the block raised."""
    stack = ExitStack()
    try:
        watch = stack.enter_context(machine.watch_changes())
    except Exception as e:
        problems.append(f"the machine's change notices could not be registered: {type(e).__name__}: {e}")
        watch = _Unwatched()
    try:
        yield watch
    finally:
        try:
            stack.close()
        except Exception as e:
            problems.append(f"the machine's change notices could not be released: {type(e).__name__}: {e}")


def attempt(problems: list[str], what: str, make: Callable[[], T]) -> T | None:
    """`make()`; when it raises (the machine could not be read, a child recorded nothing), `None` and a problem naming
    `what` and the error, so that nothing found before is lost and the rest of the case runs."""
    try:
        return make()
    except Exception as e:
        problems.append(f"{what} could not be made: {type(e).__name__}: {e}")
        return None


def run_check(problems: list[str], what: str, check: Callable[[], list[str]]) -> None:
    """Add what `check` found to `problems`; a check that cannot be made is a problem of its own (`attempt`)."""
    problems.extend(attempt(problems, what, check) or [])


def stop_problems(hole: InstalledHole, machine: MachineView, before: Snapshot) -> list[str]:
    """Stop the proxy; the machine's interfaces, routes, addresses and DNS servers must then be those of `before`, and
    the person's lookups must work.

    A step that fails does not end the others: a failed stop is when the machine is most likely to be left changed.
    The lookup is made once the machine is as it was, so that what it finds is the system's resolver and not a
    resolver still being restored (`lookup_problems`).
    """
    problems: list[str] = []
    with watching(machine, problems) as watch:
        stopped = attempt(problems, "`hole proxy stop`", lambda: hole.run("proxy", "stop"))
        if stopped is not None and stopped.returncode != 0:
            problems.append(
                f"hole proxy stop exited {stopped.returncode}: {stopped.stdout.strip()} {stopped.stderr.strip()}"
            )
        settled = attempt(
            problems,
            "the reading of the machine after the stop",
            lambda: watch.settle(machine.snapshot, lambda snapshot: snapshot == before),
        )
    if settled is None:
        return problems
    after = settled.reading
    if after == before:
        run_check(problems, "the person's lookup after the stop", lambda: lookup_problems(machine))
        return problems
    changes = difflib.unified_diff(before.lines(), after.lines(), "before the start", "after the stop", lineterm="")
    # `unsettled` is empty only for a reading for which the predicate held, and here it did not.
    assert settled.unsettled
    return [
        *problems,
        settled.unsettled,
        "the machine after the stop is not as it was before the start:\n" + "\n".join(changes),
    ]


def full_tunnel_journey(
    hole: InstalledHole, server: SsServer, plugin: str | None, machine: MachineView, tmp_path: Path
) -> None:
    """Start the proxy as a person does, a full tunnel, fetch pages from outside the machine, and stop it.

    `server` must come from `run_far_side`, whose own dials leave by the machine's default interface; where that
    interface is `en0` of a Mac, `MacMachine.scoped_default_route` must be held too, or the far side's dials, bound to
    the interface, get `ENETUNREACH` once the tunnel's routes win the table. Fails if the start does not succeed, and
    then for each of these that does not hold: a page by address and one by name arrive through the far side
    (`page_problems`), for a plugin that carries UDP a datagram of the person's, resent until answered, is answered
    through the far side (`udp_problems`), the system holds the tunnel's resolver (`dns_problems`) and its device and
    routes (`device_problems`), and after the stop the machine is as it was and the person's lookups work
    (`stop_problems`).

    For a server that is not on loopback it also checks the route that keeps the product's connection to the server out
    of the tunnel (`bypass_problems`). On loopback the product installs none, and the journey does not see that route.

    The checks add to one list of problems as they are found; a check that cannot be made is a problem in it
    (`attempt`), and the stop and the report, which carries the installed bridge's log, run whatever the checks did.
    """
    case = plugin or "a server with no plugin"
    address = server.description["server"]
    config = tmp_path / "server.json"
    config.write_text(json.dumps(server_entry(server.description, plugin)), encoding="utf-8")

    before = machine.snapshot()
    show_machine("before the start", before)
    problems: list[str] = []
    started = None
    # The stop runs whatever the start did, so no case leaves a tunnel up for the next one to find.
    try:
        with watching(machine, problems) as watch:
            # No `--tunnel-mode`: a full tunnel is the default.
            started = hole.run("proxy", "start", "--config-file", str(config))
            fail_unless_started(hole, started, f"a full tunnel through {case}")
            settled = attempt(
                problems,
                "the reading of the machine after the start",
                lambda: watch.settle(machine.snapshot, lambda snapshot: not tunnel_problems(before, snapshot, address)),
            )
        if settled is not None:
            show_machine("while the tunnel is up", settled.reading)
            if settled.unsettled:
                problems.append(settled.unsettled)
        run_check(
            problems,
            "the page by address",
            lambda: page_problems(
                machine, server, "by address", ADDRESS_URL, ADDRESS_REDIRECT, ADDRESS_TARGETS, tmp_path, ipv4_only=False
            ),
        )
        run_check(
            problems,
            "the page by name",
            lambda: page_problems(
                machine, server, "by name", NAME_URL, NAME_REDIRECT, NAME_TARGETS, tmp_path, ipv4_only=True
            ),
        )
        if plugin in UDP_PLUGINS:
            run_check(problems, "the person's datagram", lambda: udp_problems(machine, server))
        if settled is not None:
            problems += tunnel_problems(before, settled.reading, address)
    except BaseException:
        # That failure stays the reported one. What the checks found prints first, so that it is out even if the stop
        # itself raises.
        for problem in problems:
            print(f"a check found, before that failure:\n{problem}", file=sys.stderr)
        for problem in stop_problems(hole, machine, before):
            report_teardown_failure(problem, primary_ok=False)
        raise
    problems += stop_problems(hole, machine, before)
    if problems:
        assert started is not None  # `fail_unless_started` raised otherwise
        numbered = "\n".join(f"{n}. {problem}" for n, problem in enumerate(problems, 1))
        pytest.fail(hole.report(f"the full tunnel through {case} is not right:\n{numbered}", started), pytrace=False)
