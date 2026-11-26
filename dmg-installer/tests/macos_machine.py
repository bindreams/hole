"""A macOS machine as the full-tunnel journey (`connect_journey.full_tunnel_journey`) sees it.

What it reads is the output of `route`, `netstat`, `ifconfig` and `scutil`, which Hole's tunnel changes; the `curl` is
this process's own, run as the user of the test, while `hole` runs as root.
"""

import ctypes
import os
import re
import select
import subprocess
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import TypeVar

from connect_journey import DnsWatch, MachineReadError, Resolver, Route, Snapshot

# `scutil --dns` prints the resolvers of two sections; the second, for scoped queries, is the per-interface view of the
# same configuration and is left out.
_SCOPED_SECTION = "DNS configuration (for scoped queries)"

# configd posts this each time it has rebuilt the DNS configuration `scutil --dns` prints, which it does on its own
# run loop, after the call that changed a setting has returned.
_DNS_CHANGED = b"com.apple.system.SystemConfiguration.dns_configuration"
# Failure bound on that post. configd is not ours; when it never posts, the journey's own check fails on what was read.
DNS_SETTLE_SECONDS = 30

T = TypeVar("T")


def _output(*command: str) -> str:
    result = subprocess.run(command, capture_output=True, text=True, errors="replace")
    if result.returncode != 0:
        raise MachineReadError(f"`{' '.join(command)}` exited {result.returncode}:\n{result.stdout}\n{result.stderr}")
    return result.stdout


def _ipv4_network(destination: str) -> str:
    """`netstat` leaves the trailing zero octets of a network out (`128.0/1`); written in full it is the text every
    platform has for it."""
    address, slash, length = destination.partition("/")
    octets = address.split(".")
    if not slash or not all(octet.isdigit() for octet in octets):
        return destination
    return ".".join(octets + ["0"] * (4 - len(octets))) + "/" + length


def _routes() -> list[Route]:
    """The rows of `netstat -rn`, without the neighbour entries (flag `L`) and the routes cloned for one destination
    (flag `W`), which the system adds and expires by itself. Static host routes stay."""
    routes = []
    for family in ("inet", "inet6"):
        for line in _output("netstat", "-rn", "-f", family).splitlines():
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


def _interfaces() -> tuple[list[str], list[str]]:
    """The interfaces of `ifconfig -a` and their addresses, without the temporary IPv6 ones, which the system replaces
    on its own timer."""
    interfaces: list[str] = []
    addresses = []
    for line in _output("ifconfig", "-a").splitlines():
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


def _resolvers() -> list[Resolver]:
    """The resolvers of `scutil --dns`.

    A resolver's scope is its lines other than the nameservers. Three more are left out: the `resolver #N` heading,
    which follows the order and so changes when a resolver is added, and `flags` and `reach`, which say what the
    network can do now.
    """
    section = _output("scutil", "--dns").split(_SCOPED_SECTION)[0]
    resolvers = []
    for block in re.split(r"^resolver #\d+\s*$", section, flags=re.MULTILINE)[1:]:
        fields = [
            (key.strip(), value.strip()) for key, _, value in (line.partition(":") for line in block.splitlines())
        ]
        scope = [f"{key}: {value}" for key, value in fields if key and not re.match(r"nameserver\[|flags$|reach$", key)]
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

    def _posted(self, deadline: float) -> bool:
        """Wait for one post; `False` when none came by `deadline`."""
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([self._descriptor], [], [], remaining)[0]:
            return False
        # Each post writes the 4-byte token.
        os.read(self._descriptor, 4)
        return True

    def settle(self, read: Callable[[], T], settled: Callable[[T], bool]) -> T:
        deadline = time.monotonic() + DNS_SETTLE_SECONDS
        while True:
            # Read first: a change that landed before this call needs no post.
            reading = read()
            if settled(reading):
                return reading
            if not self._posted(deadline):
                return read()


class MacMachine:
    def default_interface(self) -> str:
        """`interface: en0` in `route -n get default`."""
        match = re.search(r"^\s*interface:\s*(\S+)", _output("route", "-n", "get", "default"), re.MULTILINE)
        if match is None:
            raise MachineReadError("`route -n get default` names no interface: the machine has no default route")
        return match.group(1)

    def snapshot(self) -> Snapshot:
        interfaces, addresses = _interfaces()
        return Snapshot(
            interfaces=tuple(sorted(interfaces)),
            routes=tuple(sorted(_routes())),
            addresses=tuple(sorted(addresses)),
            resolvers=tuple(sorted(_resolvers())),
        )

    @contextmanager
    def watch_dns(self) -> Iterator[DnsWatch]:
        watch = _ConfigdWatch()
        try:
            yield watch
        finally:
            watch.close()

    def run_curl(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["curl", *args], capture_output=True, text=True, encoding="utf-8", errors="replace")
