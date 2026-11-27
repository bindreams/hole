"""A macOS machine as the full-tunnel journey (`connect_journey.full_tunnel_journey`) sees it.

What it reads is the output of `route`, `netstat`, `ifconfig` and `scutil`, which Hole's tunnel changes; the `curl` is
this process's own, run as the user of the test, while `hole` runs as root.
"""

import ctypes
import os
import re
import select
import subprocess
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TypeVar

from connect_journey import (
    DEFAULT_ROUTE,
    ChangeWatch,
    MachineReadError,
    Resolver,
    Route,
    Settled,
    Snapshot,
    report_teardown_failure,
    settle_on_notices,
)

from dmg_installer.installed_bridge import describe, sudo

# `scutil --dns` prints the resolvers of two sections; the second, for scoped queries, is the per-interface view of the
# same configuration and is left out.
_SCOPED_SECTION = "DNS configuration (for scoped queries)"

# configd posts this each time it has rebuilt the DNS configuration `scutil --dns` prints, which it does on its own
# run loop, after the call that changed a setting has returned.
_DNS_CHANGED = b"com.apple.system.SystemConfiguration.dns_configuration"

# What a full tunnel is asked to reach from outside the machine; a route lookup for it says which way it would leave.
_PROBE_ADDRESS = "1.1.1.1"

T = TypeVar("T")

Read = Callable[..., str]


class _Transcript:
    """The commands one snapshot ran, each with what it printed in full: the text its parsers read."""

    def __init__(self) -> None:
        self._parts: list[str] = []

    def _run(self, command: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(command, capture_output=True, text=True, errors="replace")
        self._parts.append(f"$ {' '.join(command)}    (exit {result.returncode})\n{result.stdout}{result.stderr}")
        return result

    def output(self, *command: str) -> str:
        """The output of `command`; a failure raises."""
        result = self._run(command)
        if result.returncode != 0:
            raise MachineReadError(
                f"`{' '.join(command)}` exited {result.returncode}:\n{result.stdout}\n{result.stderr}"
            )
        return result.stdout

    def record(self, *command: str) -> None:
        """Run `command` for the transcript alone: what it says is not parsed, and a failure is part of what it says."""
        self._run(command)

    def note(self, text: str) -> None:
        self._parts.append(text)

    def text(self) -> str:
        return "\n".join(self._parts)


def _default_interface(read: Read) -> str:
    """`interface: en0` in `route -n get default`."""
    match = re.search(r"^\s*interface:\s*(\S+)", read("route", "-n", "get", "default"), re.MULTILINE)
    if match is None:
        raise MachineReadError("`route -n get default` names no interface: the machine has no default route")
    return match.group(1)


def _default_gateway(read: Read) -> str:
    """`gateway: 192.168.64.1` in `route -n get default`."""
    match = re.search(r"^\s*gateway:\s*(\S+)", read("route", "-n", "get", "default"), re.MULTILINE)
    if match is None:
        raise MachineReadError("`route -n get default` names no gateway: the default route is not through one")
    return match.group(1)


def _ipv4_network(destination: str) -> str:
    """`netstat` leaves the trailing zero octets of a network out (`128.0/1`) and calls the whole of IPv4 `default`;
    written in full it is the text every platform has for it."""
    if destination == "default":
        return DEFAULT_ROUTE
    address, slash, length = destination.partition("/")
    octets = address.split(".")
    if not slash or not all(octet.isdigit() for octet in octets):
        return destination
    return ".".join(octets + ["0"] * (4 - len(octets))) + "/" + length


def _routes(read: Read) -> list[Route]:
    """The rows of `netstat -rn`, without the neighbour entries (flag `L`) and the routes cloned for one destination
    (flag `W`), which the system adds and expires by itself. Static host routes stay."""
    routes = []
    for family in ("inet", "inet6"):
        for line in read("netstat", "-rn", "-f", family).splitlines():
            columns = line.split()
            # The title lines have fewer columns.
            if len(columns) < 4 or columns[0] == "Destination":
                continue
            destination, gateway, flags, interface = columns[:4]
            if {"L", "W"} & set(flags):
                continue
            routes.append(
                Route(_ipv4_network(destination) if family == "inet" else destination, gateway, interface, flags)
            )
    return routes


def _interfaces(read: Read) -> tuple[list[str], list[str]]:
    """The interfaces of `ifconfig -a` and their addresses, without the temporary IPv6 ones, which the system replaces
    on its own timer."""
    interfaces: list[str] = []
    addresses = []
    for line in read("ifconfig", "-a").splitlines():
        if (heading := re.match(r"(\S+): flags=", line)) is not None:
            interfaces.append(heading.group(1))
        elif re.match(r"\s+inet6? ", line) is not None:
            # `inet 10.0.0.1 netmask 0xff000000`, `inet 10.0.0.1 --> 10.0.0.2 netmask ...`, `inet6 fe80::1%lo0 prefixlen 64`
            address = re.match(r"\s+inet6? (\S+) (?:--> \S+ )?(?:netmask|prefixlen) (\S+)", line)
            if address is None or not interfaces:
                raise MachineReadError(f"`ifconfig -a` printed an address line this reader does not know: {line!r}")
            if " temporary" not in line:
                addresses.append(f"{interfaces[-1]} {address.group(1)}/{address.group(2)}")
    return interfaces, addresses


def _resolvers(read: Read) -> list[Resolver]:
    """The resolvers of `scutil --dns`.

    A resolver's scope is its lines other than the nameservers. Four more are left out: the `resolver #N` heading and
    the `order` line, which place it among the others and so change when a resolver is added (the en0 resolver has no
    `order` before a tunnel and `order : 200000` while it is up), and `flags` and `reach`, which say what the network
    can do now.
    """
    section = read("scutil", "--dns").split(_SCOPED_SECTION)[0]
    resolvers = []
    for block in re.split(r"^resolver #\d+\s*$", section, flags=re.MULTILINE)[1:]:
        fields = [
            (key.strip(), value.strip()) for key, _, value in (line.partition(":") for line in block.splitlines())
        ]
        scope = [
            f"{key}: {value}"
            for key, value in fields
            if key and not re.match(r"nameserver\[|flags$|reach$|order$", key)
        ]
        interface = next((re.search(r"\((\S+)\)", value) for key, value in fields if key == "if_index"), None)
        resolvers.append(
            Resolver(
                scope="; ".join(scope),
                servers=tuple(value for key, value in fields if key.startswith("nameserver[")),
                interface=interface.group(1) if interface is not None else "",
            )
        )
    return resolvers


class _ConfigdWatch:
    """A registration for configd's DNS-changed post (`notify(3)`), as the bridge's own macOS tests wait on it
    (`tun_engine::test_utils::DnsConfigNotify`)."""

    def __init__(self) -> None:
        self._notify = ctypes.CDLL(None)
        descriptor, token = ctypes.c_int(-1), ctypes.c_int(0)
        status = self._notify.notify_register_file_descriptor(
            ctypes.c_char_p(_DNS_CHANGED), ctypes.byref(descriptor), ctypes.c_int(0), ctypes.byref(token)
        )
        if status != 0:
            raise MachineReadError(f"notify_register_file_descriptor for configd's DNS-changed post returned {status}")
        self._descriptor, self._token = descriptor.value, token.value

    def close(self) -> None:
        self._notify.notify_cancel(ctypes.c_int(self._token))

    def _wait(self, seconds: float) -> bool:
        """Wait for one post; `False` when none came within `seconds`."""
        if not select.select([self._descriptor], [], [], seconds)[0]:
            return False
        # Each post writes the 4-byte token.
        os.read(self._descriptor, 4)
        return True

    def settle(self, read: Callable[[], T], settled: Callable[[T], bool]) -> Settled[T]:
        # A post waits in the descriptor until it is read, so none is lost between a reading and the wait.
        return settle_on_notices(read, settled, arm=lambda: None, wait=self._wait, source="configd (a DNS change)")


def _has_scoped_default(read: Read, interface: str) -> bool:
    """Whether `netstat -rn -f inet` lists a default route bound to `interface` (flag `I`)."""
    return any(
        route.destination == DEFAULT_ROUTE and route.interface == interface and "I" in route.detail
        for route in _routes(read)
    )


class MacMachine:
    def default_interface(self) -> str:
        return _default_interface(_Transcript().output)

    def far_side_address(self) -> str:
        """The default interface's own IPv4 address.

        For an address of its own the system delivers locally whatever the host route for it says, and the product
        installs and removes that route all the same.
        """
        address = _Transcript().output("ipconfig", "getifaddr", self.default_interface()).strip()
        if not address:
            raise MachineReadError("`ipconfig getifaddr` printed no address for the default interface")
        return address

    @contextmanager
    def scoped_default_route(self) -> Iterator[None]:
        """Hold a default route in the default interface's scope, for a far side whose sockets are bound to it.

        Such a socket (`IP_BOUND_IF`) looks routes up in the interface's scope only. A runner has none there, so once a
        tunnel's split routes win the unscoped table, the lookup finds nothing and `connect` returns `ENETUNREACH`.
        The route is added when the interface has no scoped default, through the gateway of the unscoped one, and
        deleted on exit only if this added it. It also changes what the product's own interface-bound sockets see
        (bindreams/hole#1414), so a journey of a Bypass rule must not hold it.
        """
        transcript = _Transcript()
        interface = _default_interface(transcript.output)
        if _has_scoped_default(transcript.output, interface):
            yield
            return
        gateway = _default_gateway(transcript.output)
        add = ("route", "-n", "add", "-ifscope", interface, "default", gateway)
        added = sudo(*add)
        print(f"=== scoped default route: $ {' '.join(add)}\n{describe(added)}", flush=True)
        if added.returncode != 0:
            raise MachineReadError(f"`{' '.join(add)}` failed:\n{describe(added)}")
        ok = False
        try:
            yield
            ok = True
        finally:
            delete = ("route", "-n", "delete", "-ifscope", interface, "default")
            deleted = sudo(*delete)
            print(f"=== scoped default route: $ {' '.join(delete)}\n{describe(deleted)}", flush=True)
            if deleted.returncode != 0:
                report_teardown_failure(f"`{' '.join(delete)}` failed:\n{describe(deleted)}", primary_ok=ok)

    def snapshot(self) -> Snapshot:
        transcript = _Transcript()
        interfaces, addresses = _interfaces(transcript.output)
        routes = _routes(transcript.output)
        resolvers = _resolvers(transcript.output)
        # Not parsed: where the system would send a packet for an address, by the default interface's own scope and by
        # the whole table, which the split routes of a tunnel answer differently.
        try:
            transcript.record("route", "-n", "get", "-ifscope", _default_interface(transcript.output), _PROBE_ADDRESS)
        except MachineReadError as e:
            transcript.note(f"no scoped route lookup: {e}")
        transcript.record("route", "-n", "get", _PROBE_ADDRESS)
        return Snapshot(
            interfaces=tuple(sorted(interfaces)),
            routes=tuple(sorted(routes)),
            addresses=tuple(sorted(addresses)),
            resolvers=tuple(sorted(resolvers)),
            raw=transcript.text(),
        )

    @contextmanager
    def watch_changes(self) -> Iterator[ChangeWatch]:
        watch = _ConfigdWatch()
        try:
            yield watch
        finally:
            watch.close()

    def run_curl(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["curl", *args], capture_output=True, text=True, encoding="utf-8", errors="replace")

    def run_python(self, script: Path, *args: str) -> subprocess.CompletedProcess[str]:
        command = [sys.executable, str(script), *args]
        return subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
