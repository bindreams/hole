"""A Windows machine as the full-tunnel journey (`connect_journey.full_tunnel_journey`) sees it.

What the operating system says is read by `.github/scripts/network-state.ps1`, from this elevated process: the
answers do not depend on who asks. The `curl` is the person's, run by the de-elevated child of `member.py`.
"""

import ctypes
import json
import os
import subprocess
import sys
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TypeVar

from connect_journey import ChangeWatch, MachineReadError, Resolver, Route, Settled, Snapshot, settle_on_notices
from member import UnelevatedMember
from support import SCRIPTS

NETWORK_STATE = SCRIPTS / "network-state.ps1"

# The `curl` Windows ships, not whichever one a `PATH` names first.
CURL = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "curl.exe"

# What Windows lists as the IPv6 DNS servers of an interface that was given none.
_NO_IPV6_SERVER = ("fec0:0:0:ffff::1", "fec0:0:0:ffff::2", "fec0:0:0:ffff::3")

T = TypeVar("T")

_AF_UNSPEC = 0
# `PIPINTERFACE_CHANGE_CALLBACK`, `PIPFORWARD_CHANGE_CALLBACK` and `PUNICAST_IPADDRESS_CHANGE_CALLBACK` share one
# shape: (context, the changed row or NULL, the notification type).
_CHANGE_CALLBACK = ctypes.WINFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int)


class _IpChangeWatch:
    """Registrations for IP Helper's notices of a change to an IP interface, a route or a unicast address
    (`NotifyIpInterfaceChange`, `NotifyRouteChange2`, `NotifyUnicastIpAddressChange`), made before the command whose
    changes they wait for runs.

    These are the tables `network-state.ps1` reads its interfaces, routes and addresses from. Windows publishes no
    notice for a change of an interface's DNS servers; DNS needs no wait of its own (see `network-state.ps1`).
    """

    def __init__(self) -> None:
        library = ctypes.WinDLL("iphlpapi")
        library.CancelMibChangeNotify2.argtypes = [ctypes.c_void_p]
        library.CancelMibChangeNotify2.restype = ctypes.c_ulong
        self._cancel = library.CancelMibChangeNotify2
        self._changed = threading.Event()
        # Held for as long as the registrations are: IP Helper calls it from its own threads.
        self._callback = _CHANGE_CALLBACK(lambda context, row, kind: self._changed.set())
        self._handles: list[ctypes.c_void_p] = []
        try:
            for name in ("NotifyIpInterfaceChange", "NotifyRouteChange2", "NotifyUnicastIpAddressChange"):
                register = getattr(library, name)
                register.argtypes = [
                    ctypes.c_ushort,
                    _CHANGE_CALLBACK,
                    ctypes.c_void_p,
                    ctypes.c_ubyte,
                    ctypes.POINTER(ctypes.c_void_p),
                ]
                register.restype = ctypes.c_ulong
                handle = ctypes.c_void_p()
                status = register(_AF_UNSPEC, self._callback, None, 0, ctypes.byref(handle))
                if status != 0:
                    raise MachineReadError(f"{name} returned error {status}")
                self._handles.append(handle)
        except BaseException as registration:
            try:
                self.close()
            except MachineReadError as e:
                # `watching` handles this type; the registration's own text stays in what it gets.
                if isinstance(registration, MachineReadError):
                    raise MachineReadError(f"{registration}; {e}") from registration
            raise

    def close(self) -> None:
        """Cancel every registration. A cancel that fails raises `MachineReadError`, after the others were tried."""
        statuses = [self._cancel(handle) for handle in self._handles]
        self._handles.clear()
        if any(statuses):
            raise MachineReadError(f"CancelMibChangeNotify2 returned {statuses}")

    def settle(self, read: Callable[[], T], settled: Callable[[T], bool]) -> Settled[T]:
        return settle_on_notices(
            read,
            settled,
            # A notice that comes after this is seen by the wait; one before it is in the reading that follows.
            arm=self._changed.clear,
            wait=self._changed.wait,
            source="IP Helper (interface, route or address)",
        )


@dataclass(frozen=True)
class WindowsMachine:
    person: UnelevatedMember

    def _state(self, what: str) -> str:
        result = subprocess.run(
            [
                "pwsh",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(NETWORK_STATE),
                "-What",
                what,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if result.returncode != 0:
            raise MachineReadError(f"network-state.ps1 -What {what} exited {result.returncode}:\n{result.stderr}")
        return result.stdout

    def default_interface(self) -> str:
        return self._state("default-interface").strip()

    def default_interface_address(self) -> str:
        return self._state("default-address").strip()

    def far_side_address(self) -> None:
        """Loopback: Windows refuses the host route for the machine's own address.

        It holds `<address>/32 via 0.0.0.0` on the default interface for it, and the bridge's `netsh interface ip add
        route <address>/32 <interface> store=active` exits 1 (`hole proxy start` fails with `route setup failed`).
        """
        return None

    def snapshot(self) -> Snapshot:
        text = self._state("snapshot")
        try:
            state = json.loads(text)
        except json.JSONDecodeError as e:
            raise MachineReadError(f"network-state.ps1 -What snapshot printed no JSON ({e}):\n{text}") from e
        return Snapshot(
            # One entry per interface and address family.
            interfaces=tuple(sorted(set(state["interfaces"]))),
            routes=tuple(
                sorted(
                    Route(route["destination"], route["gateway"], route["interface"], f"metric {route['metric']}")
                    for route in state["routes"]
                )
            ),
            addresses=tuple(sorted(state["addresses"])),
            resolvers=tuple(
                sorted(
                    Resolver(
                        scope=f"{dns['interface']} {dns['family']}",
                        servers=() if tuple(dns["servers"]) == _NO_IPV6_SERVER else tuple(dns["servers"]),
                        interface=dns["interface"],
                    )
                    for dns in state["dns"]
                )
            ),
            raw=f"$ network-state.ps1 -What snapshot\n{text}",
        )

    @contextmanager
    def watch_changes(self) -> Iterator[ChangeWatch]:
        watch = _IpChangeWatch()
        try:
            yield watch
        finally:
            watch.close()

    def run_curl(self, *args: str) -> subprocess.CompletedProcess[str]:
        command = [str(CURL), *args]
        try:
            record = self.person.recorded_command(CURL, *args)
        except TimeoutError as e:
            # Returned as a failed command, not raised: the journey reports it, with the bridge's log.
            return subprocess.CompletedProcess(command, returncode=-1, stdout="", stderr=f"(killed: {e})")
        return subprocess.CompletedProcess(command, record["exit_code"], record["stdout"], record["stderr"])

    def run_python(self, script: Path, *args: str) -> subprocess.CompletedProcess[str]:
        python = Path(sys.executable)
        command = [str(python), str(script), *args]
        try:
            record = self.person.recorded_command(python, str(script), *args)
        except TimeoutError as e:
            return subprocess.CompletedProcess(command, returncode=-1, stdout="", stderr=f"(killed: {e})")
        return subprocess.CompletedProcess(command, record["exit_code"], record["stdout"], record["stderr"])
