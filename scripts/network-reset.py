#!/usr/bin/env python3
"""Emergency network reset script for Hole.

Removes routes, adapters, and stale processes left behind by a crashed
bridge. State-file-aware: reads `bridge-routes.json` (if present) from
candidate state directories to target the exact leaked bypass route
rather than blindly removing every /32 or /128 on the machine.

Run with admin/root privileges:
  macOS:   sudo python3 scripts/network-reset.py
  Windows: run from an elevated PowerShell
"""

# /// script
# requires-python = ">=3.9"
# ///
from __future__ import annotations

import argparse
import io
import ipaddress
import json
import os
import platform
import stat
import subprocess
import sys
import tempfile
import unicodedata
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

import _lib

# Keep in sync with `crates/tun-engine/src/routing/state.rs::STATE_FILE_NAME`.
# Flat JSON object; this script reads only `server_ip` and ignores other keys,
# so a newer release's file still works.
STATE_FILE_NAME = "bridge-routes.json"
# Keep in sync with `crates/bridge/src/dns_state.rs::STATE_FILE_NAME` /
# `SUPERSEDED_FILE_NAME`. The bridge's own upgrade sweep (bindreams/hole#846)
# evaluates `DNS_STATE_FILE_NAME` at most once: on full success it deletes
# the file, otherwise it renames it to `DNS_STATE_SUPERSEDED_FILE_NAME` and
# never reads that name again. This script reads BOTH so the escape survives
# that rename rather than being hidden by it.
DNS_STATE_FILE_NAME = "bridge-dns.json"
DNS_STATE_SUPERSEDED_FILE_NAME = "bridge-dns.superseded.json"


def load_dns_state_file() -> tuple[tuple[dict, Path] | None, list[Path]]:
    """Return the first readable DNS state file found across candidate state
    directories — checking the un-suffixed name before the superseded one —
    plus the path it came from, and the paths of those that exist but could
    not be read. Mirrors `load_state_file` but for DNS."""
    return load_first_record(
        (d / name for name in (DNS_STATE_FILE_NAME, DNS_STATE_SUPERSEDED_FILE_NAME) for d in candidate_state_dirs()),
        validate_dns_record,
    )


def _split_advertised(advertised: list[str]) -> tuple[list[str], list[str]]:
    """Split an `advertised` IP list into (v4, v6) subsets — the same split
    the bridge's own upgrade sweep does before comparing against a live
    family. A bare `":"` substring check is sufficient: the field only ever
    holds parsed `IpAddr` strings, never a bracketed/ported form."""
    v4 = [ip for ip in advertised if ":" not in ip]
    v6 = [ip for ip in advertised if ":" in ip]
    return v4, v6


def _family_is_still_hole(live: list[str] | None, advertised_family: list[str]) -> bool:
    """The same evidence gate the bridge's upgrade sweep applies: a family
    counts as "still Hole's" only if the live setting is a non-empty list
    that equals (order-independent) the matching `advertised` subset. `live
    is None` means the read itself failed or could not be attempted — never
    treated as a match. An empty `advertised_family` (no sound evidence
    either way) never matches either."""
    if live is None or not advertised_family:
        return False
    return sorted(live) == sorted(advertised_family)


def live_dns_windows(alias: str, family: str) -> list[str] | None:
    """Best-effort read of `alias`'s current DNS servers for one family via
    `Get-DnsClientServerAddress`. `None` on any failure — a read failure is
    never treated as evidence of a match."""
    fam_flag = "IPv4" if family == "ipv4" else "IPv6"
    result = powershell(
        f"(Get-DnsClientServerAddress -InterfaceAlias ([WildcardPattern]::Escape($env:{ARG_ALIAS})) "
        f"-AddressFamily {fam_flag} -ErrorAction SilentlyContinue).ServerAddresses -join ','",
        {ARG_ALIAS: alias},
    )
    if result.returncode != 0:
        return None
    text = result.stdout.strip()
    if not text:
        return []
    return [s.strip() for s in text.split(",") if s.strip()]


def live_dns_macos(svc: str) -> list[str] | None:
    """Best-effort read of `svc`'s current DNS servers via
    `networksetup -getdnsservers`. `None` on any failure."""
    result = run(["networksetup", "-getdnsservers", svc])
    if result.returncode != 0:
        return None
    text = result.stdout.strip()
    if not text or "aren't any dns servers" in text.lower():
        return []
    return [line.strip() for line in text.splitlines() if line.strip()]


@dataclass
class DnsRestore:
    """What a DNS restore pass left undone. The record may be deleted only if it
    left nothing undone."""

    skipped: bool = False  # a family was left alone: live DNS is not provably Hole's
    failed: bool = False  # a restore command could not be run or did not succeed

    @property
    def complete(self) -> bool:
        return not (self.skipped or self.failed)

    def attempt(self, cmd: list[str]) -> bool:
        """Run one restore command; record and return whether it succeeded."""
        succeeded = run(cmd).returncode == 0
        self.failed = self.failed or not succeeded
        return succeeded

    def unrestorable(self, what: str) -> None:
        """Record an entry this script cannot restore, so the record is kept."""
        print(f"  Cannot restore {what}; keeping the record.")
        self.failed = True


def _netsh_dns(family: str, verb: str, alias: str, *rest: str) -> list[str]:
    return ["netsh", "interface", family, verb, "dnsservers", f"name={alias}", *rest]


def restore_dns_windows(state: dict, *, force: bool) -> DnsRestore:
    """Restore each recorded family, or skip it (`skipped`) when live DNS is not
    provably Hole's, unless `force`. `failed` is set if a restore command fails."""
    print("Restoring prior DNS settings (Windows)...")
    outcome = DnsRestore()
    advertised_v4, advertised_v6 = _split_advertised(state.get("advertised", []))
    for adapter in state.get("adapters", []):
        id_obj = adapter.get("id", {})
        if id_obj.get("kind") != "windows_alias":
            outcome.unrestorable(f"an adapter of kind {id_obj.get('kind')!r} on Windows")
            continue
        alias = id_obj.get("value")
        if not alias:
            outcome.unrestorable("an adapter with no alias")
            continue
        for family, field, advertised_family in (
            ("ipv4", "v4", advertised_v4),
            ("ipv6", "v6", advertised_v6),
        ):
            if not force:
                live = live_dns_windows(alias, family)
                if not _family_is_still_hole(live, advertised_family):
                    print(
                        f"  Skipping {alias} ({family}): live DNS ({live}) does not match what Hole "
                        f"advertised ({advertised_family}) — this setting may belong to someone else "
                        f"now. Re-run with --force-dns-restore to override."
                    )
                    outcome.skipped = True
                    continue
            prior = adapter.get(field, {})
            kind = prior.get("kind")
            if kind == "dhcp":
                outcome.attempt(_netsh_dns(family, "set", alias, "dhcp"))
            elif kind == "none":
                outcome.attempt(_netsh_dns(family, "set", alias, "static", "none"))
            elif kind == "static":
                servers = prior.get("servers", [])
                if not servers:
                    # The bridge restores an empty static list as a blank NameServer, which is DHCP.
                    outcome.attempt(_netsh_dns(family, "set", alias, "dhcp"))
                    continue
                # The `add`s extend the list the `set` starts, so they need it to have succeeded.
                if not outcome.attempt(_netsh_dns(family, "set", alias, "static", servers[0], "primary")):
                    continue
                for idx, ip in enumerate(servers[1:], start=2):
                    outcome.attempt(_netsh_dns(family, "add", alias, ip, f"index={idx}"))
            else:
                outcome.unrestorable(f"{alias} ({family}): prior setting of kind {kind!r}")
    return outcome


def restore_dns_macos(state: dict, *, force: bool) -> DnsRestore:
    """The macOS counterpart of `restore_dns_windows`."""
    print("Restoring prior DNS settings (macOS)...")
    outcome = DnsRestore()
    advertised_v4, advertised_v6 = _split_advertised(state.get("advertised", []))
    for adapter in state.get("adapters", []):
        id_obj = adapter.get("id", {})
        if id_obj.get("kind") != "macos_service_name":
            outcome.unrestorable(f"an adapter of kind {id_obj.get('kind')!r} on macOS")
            continue
        svc = id_obj.get("value")
        if not svc:
            outcome.unrestorable("a network service with no name")
            continue

        if not force:
            live = live_dns_macos(svc)
            # macOS has no per-family read — a single evidence check against
            # the FULL advertised list (both families combined), mirroring
            # the fact that `networksetup -setdnsservers` writes/reads one
            # combined list, never a family independently.
            advertised_combined = advertised_v4 + advertised_v6
            if not _family_is_still_hole(live, advertised_combined):
                print(
                    f"  Skipping {svc}: live DNS ({live}) does not match what Hole advertised "
                    f"({advertised_combined}) — this setting may belong to someone else now. "
                    f"Re-run with --force-dns-restore to override."
                )
                outcome.skipped = True
                continue

        kinds = [adapter.get(field, {}).get("kind") for field in ("v4", "v6")]
        unknown = [k for k in kinds if k not in ("dhcp", "none", "static")]
        if unknown:
            outcome.unrestorable(f"{svc}: prior setting of kind {unknown[0]!r}")
            continue
        combined: list[str] = []
        saw_static = False
        for field in ("v4", "v6"):
            prior = adapter.get(field, {})
            if prior.get("kind") == "static":
                saw_static = True
                combined.extend(prior.get("servers", []))
        if saw_static and combined:
            outcome.attempt(["networksetup", "-setdnsservers", svc, *combined])
        else:
            outcome.attempt(["networksetup", "-setdnsservers", svc, "Empty"])
    return outcome


def clear_dns_state_file(path: Path) -> None:
    """Remove exactly the DNS state file that was read (whichever of the two
    names it was) — never a blind sweep of both, so a file this run
    deliberately preserved (an unconfirmed restore) isn't also deleted."""
    try:
        path.unlink()
        print(f"  Removed {path}")
    except OSError as e:
        print(f"  Failed to remove {path}: {e}")


def run(cmd: list[str], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    """Run `cmd` (never through a shell), with `env` added to the environment.
    Never raises: a command that could not be started or that the OS refused
    (too long, missing, ...) is reported and returned as a failed result, so the
    steps after it still run."""
    prefix = "".join(f"{k}={v} " for k, v in (env or {}).items())
    print(f"  $ {prefix}{' '.join(cmd)}")
    try:
        return subprocess.run(
            cmd, check=False, capture_output=True, text=True, errors="replace", env={**os.environ, **(env or {})}
        )
    except Exception as e:  # noqa: BLE001 - whatever stops the command from running is a failed command
        print(f"  ! {cmd[0]} could not be run ({type(e).__name__}: {e})")
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr=str(e))


# A record value reaches PowerShell as an environment variable the command reads
# as `$env:NAME`, never spliced into the command text, so it cannot become code.
ARG_ALIAS = "HOLE_RESET_ALIAS"
ARG_IP = "HOLE_RESET_IP"


def powershell(command: str, args: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    """Run `command` in PowerShell. Pass record values in `args` (name -> value)."""
    return run(["powershell", "-Command", command], env=args)


def candidate_state_dirs() -> list[Path]:
    """Candidate state directories, in the order the bridge and dev-console
    might have written to them. First valid JSON wins."""
    dirs: list[Path] = []
    if platform.system() == "Windows":
        program_data = os.environ.get("ProgramData", r"C:\ProgramData")
        dirs.append(Path(program_data) / "hole" / "state")  # service
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            dirs.append(Path(local_app_data) / "hole" / "state")  # default user
    elif platform.system() == "Darwin":
        dirs.append(Path("/var/db/hole/state"))  # service
        dirs.append(Path.home() / "Library" / "Application Support" / "hole" / "state")
    dirs.append(Path(tempfile.gettempdir()) / "hole-dev" / "state")  # dev-console
    return dirs


def load_state_file() -> tuple[tuple[dict, Path] | None, list[Path]]:
    """Return the first readable route state file found across candidate
    directories (None if there is none) plus its path, and the paths of those
    that exist but could not be read. An unreadable file is never touched: it
    may name a route this script cannot identify."""
    return load_first_record((d / STATE_FILE_NAME for d in candidate_state_dirs()), validate_route_record)


# Records ==============================================================================================================
#
# Every state record this script reads goes through `load_first_record`. The
# files live in directories a user can write, so a record is trusted for
# nothing: it is readable only if it parses AND has, in every field a reset
# step uses, the type and shape the Rust writer produces.


def _read_regular_file(path: Path) -> bytes:
    """The bytes of `path`, which must be a regular file. A FIFO would block the
    open and a device such as `/dev/zero` would never end, so the type is checked
    on the open descriptor (`O_NONBLOCK` keeps the open itself from blocking)."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("not a regular file")
        with os.fdopen(fd, "rb", closefd=False) as f:
            return f.read()
    finally:
        os.close(fd)


def load_first_record(
    paths: Iterable[Path], validate: Callable[[object], None]
) -> tuple[tuple[dict, Path] | None, list[Path]]:
    """Read, decode, parse and `validate` each path in turn. Returns the first
    readable record with its path, and the paths that exist but could not be
    read, which are reported and left in place. A missing path is skipped
    silently. Any exception while reading makes a record unreadable."""
    unreadable: list[Path] = []
    for path in paths:
        try:
            record = json.loads(_read_regular_file(path).decode("utf-8"))
            validate(record)
        except (FileNotFoundError, NotADirectoryError):
            continue
        except Exception as e:  # noqa: BLE001 - whatever the record does to us, it is unreadable
            print(f"  Skipping {path} ({type(e).__name__}: {e})")
            unreadable.append(path)
            continue
        print(f"  Found state file at {path}")
        return (record, path), unreadable
    return None, unreadable


def _text(value: object, what: str) -> str:
    """A string that can be passed as a process argument."""
    if not isinstance(value, str):
        raise TypeError(f"{what} is not a string")
    if "\0" in value:
        raise ValueError(f"{what} contains a NUL")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError(f"{what} is not valid Unicode") from None
    return value


def _ip_text(value: object, what: str) -> str:
    """An IP address in the canonical text form the Rust writer emits (so no
    scope id, whitespace or empty string)."""
    text = _text(value, what)
    if "%" in text:  # a scope id: Python parses it, Rust does not
        raise ValueError(f"{what} carries a scope id")
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        raise ValueError(f"{what} is not an IP address") from None
    canonical = {str(ip)}
    # Rust prints an IPv4-mapped address dotted; Python before 3.13 prints it as hex.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        canonical.add(f"::ffff:{ip.ipv4_mapped}")
    if text not in canonical:
        raise ValueError(f"{what} is not in canonical form")
    return text


def _object(value: object, what: str) -> dict:
    if not isinstance(value, dict):
        raise TypeError(f"{what} is not a JSON object")
    return value


def _list(value: object, what: str) -> list:
    if not isinstance(value, list):
        raise TypeError(f"{what} is not a JSON array")
    return value


def validate_route_record(record: object) -> None:
    """The reset steps use `server_ip`, as an address."""
    _ip_text(_object(record, "record").get("server_ip"), "server_ip")


def validate_dns_record(record: object) -> None:
    """The restore steps use `advertised` (optional) and, per adapter, `id`
    and the `v4`/`v6` priors."""
    record = _object(record, "record")
    for ip in _list(record.get("advertised", []), "advertised"):
        _ip_text(ip, "advertised entry")
    for adapter in _list(record.get("adapters"), "adapters"):
        adapter = _object(adapter, "adapter")
        id_obj = _object(adapter.get("id"), "adapter id")
        _text(id_obj.get("kind"), "adapter id kind")
        _text(id_obj.get("value"), "adapter id value")
        for field in ("v4", "v6"):
            prior = _object(adapter.get(field), f"adapter {field}")
            kind = _text(prior.get("kind"), f"adapter {field} kind")
            if kind == "static":
                for ip in _list(prior.get("servers"), f"adapter {field} servers"):
                    _ip_text(ip, f"adapter {field} server")


def reset_macos(state: dict | None) -> None:
    print("Removing split routes (IPv4 + IPv6)...")
    run(["route", "-n", "delete", "-net", "0.0.0.0/1"])
    run(["route", "-n", "delete", "-net", "128.0.0.0/1"])
    run(["route", "-n", "delete", "-inet6", "::/1"])
    run(["route", "-n", "delete", "-inet6", "8000::/1"])

    if state is not None:
        server_ip = state["server_ip"]
        if ":" in server_ip:
            print(f"Removing IPv6 bypass route for {server_ip}...")
            run(["route", "-n", "delete", "-inet6", "-host", server_ip])
        else:
            print(f"Removing IPv4 bypass route for {server_ip}...")
            run(["route", "-n", "delete", "-host", server_ip])
    else:
        print(
            "  No readable state file — cannot identify per-server bypass route. "
            "If you still have connectivity issues, run 'netstat -rn' and "
            "remove any host routes pointing at a stale hole-tun interface."
        )

    print("Killing bridge and ex-ray processes...")
    # Match both the installed binary (`/usr/local/bin/hole bridge run ...`)
    # and the dev-copied binary (`$TMPDIR/hole-dev-<pid>/hole bridge run ...`).
    # ERE: `hole` followed by zero-or-more non-space chars, then ` bridge run`.
    run(["pkill", "-fE", r"hole[^ ]* bridge run"])
    # The bridge spawns `ex-ray` directly; galoshes extracts + spawns the
    # embedded `ex-ray`. This script tracks the current build, so it reaps
    # `ex-ray` only (not the retired `v2ray-plugin` name).
    run(["pkill", "-f", "ex-ray"])

    print("Flushing route cache and DNS cache...")
    run(["route", "-n", "flush"])
    run(["dscacheutil", "-flushcache"])
    run(["killall", "-HUP", "mDNSResponder"])


def reset_windows(state: dict | None) -> None:
    print("Removing split routes (IPv4 + IPv6, scoped to hole-tun*)...")
    for prefix in ("0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"):
        run([
            "powershell",
            "-Command",
            f'Remove-NetRoute -DestinationPrefix "{prefix}" '
            f'-InterfaceAlias "hole-tun*" -Confirm:$false -ErrorAction SilentlyContinue',
        ])

    if state is not None:
        server_ip = state["server_ip"]
        family, prefix_len = ("IPv6", 128) if ":" in server_ip else ("IPv4", 32)
        print(f"Removing {family} bypass route for {server_ip}...")
        powershell(
            f"Remove-NetRoute -DestinationPrefix ($env:{ARG_IP} + '/{prefix_len}') "
            f"-Confirm:$false -ErrorAction SilentlyContinue",
            {ARG_IP: server_ip},
        )
    else:
        print(
            "  No readable state file — cannot identify per-server bypass route. "
            "If you still have connectivity issues, run 'Get-NetRoute' and "
            "remove any host routes pointing at a stale hole-tun interface."
        )

    print("Stopping HoleBridge service and killing bridge + ex-ray processes...")
    run([
        "powershell",
        "-Command",
        'Stop-Service -Name "HoleBridge" -Force -ErrorAction SilentlyContinue',
    ])
    # dev-console stages the dev bridge at `%TEMP%\hole-dev-<pid>\hole.exe`, so
    # `Name = 'hole.exe'` matches both installed and dev. The `LIKE 'hole%.exe'`
    # wildcard also catches any stale dev bridge left by an older dev-supervisor
    # naming scheme. Command-line filter ensures we only hit the bridge
    # subcommand and not the GUI.
    run([
        "powershell",
        "-Command",
        """
        Get-CimInstance Win32_Process -Filter "Name LIKE 'hole%.exe'" |
            Where-Object { $_.CommandLine -like '*bridge run*' } |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        """,
    ])
    run([
        "powershell",
        "-Command",
        'Get-Process -Name "ex-ray" -ErrorAction SilentlyContinue | Stop-Process -Force',
    ])

    print("Removing wintun adapters...")
    run([
        "powershell",
        "-Command",
        """
        Get-NetAdapter -Name "hole-tun*" -ErrorAction SilentlyContinue |
            ForEach-Object {
                Write-Host "  Removing: $($_.Name)"
                Remove-NetAdapter -Name $_.Name -Confirm:$false -ErrorAction SilentlyContinue
            }
        """,
    ])

    print("Flushing DNS cache...")
    run(["ipconfig", "/flushdns"])

    print()
    print("If still broken, run these as Administrator and reboot:")
    print("  netsh winsock reset")
    print("  netsh int ip reset")


class _ControlEscaping(io.TextIOBase):
    """Writes text with control characters other than newline and tab escaped, so
    a value read from a record cannot drive the terminal."""

    def __init__(self, inner: TextIO) -> None:
        self._inner = inner

    def write(self, s: str) -> int:
        self._inner.write("".join(_escape_control(c) for c in s))
        return len(s)

    def flush(self) -> None:
        self._inner.flush()


def _escape_control(c: str) -> str:
    if c in "\n\t" or unicodedata.category(c) != "Cc":
        return c
    return f"\\x{ord(c):02x}"


def main() -> None:
    # An adapter name the console code page cannot encode must not crash the reset.
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name)
        if stream is None:  # started with no such handle: `print` is a no-op, as before
            continue
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(errors="backslashreplace")
        setattr(sys, name, _ControlEscaping(stream))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--force-dns-restore",
        action="store_true",
        help=(
            "Skip the live-DNS evidence check and restore every recorded adapter/family "
            "unconditionally. Use this if you know the recorded prior DNS is still correct "
            "for your current network (the default check is conservative and will skip a "
            "family whose live setting doesn't match what Hole advertised)."
        ),
    )
    args = parser.parse_args()

    print("=== Hole Emergency Network Reset ===")
    print()

    _lib.require_elevation()

    print("Looking for route-state file...")
    found, unreadable = load_state_file()
    state = found[0] if found else None
    for path in unreadable:
        print(f"  The route record at {path} exists but could not be read; it was left in place.")
    print()

    print("Looking for DNS-state file...")
    dns_state_and_path, dns_unreadable = load_dns_state_file()
    for path in dns_unreadable:
        print(f"  The DNS record at {path} exists but could not be read; it was left in place.")
    print()

    system = platform.system()
    dns_restore = DnsRestore()
    if system == "Darwin":
        if dns_state_and_path is not None:
            dns_restore = restore_dns_macos(dns_state_and_path[0], force=args.force_dns_restore)
        reset_macos(state)
    elif system == "Windows":
        if dns_state_and_path is not None:
            dns_restore = restore_dns_windows(dns_state_and_path[0], force=args.force_dns_restore)
        reset_windows(state)
    else:
        print(f"Unsupported platform: {system}", file=sys.stderr)
        sys.exit(1)

    if dns_state_and_path is not None:
        _, dns_state_path = dns_state_and_path
        if dns_restore.complete:
            clear_dns_state_file(dns_state_path)
        else:
            print(f"  Leaving the DNS state file {dns_state_path} in place: DNS is not fully restored.")
            if dns_restore.failed:
                print(
                    "  The DNS restore did not complete (see above). Fix the cause and re-run, or restore "
                    "your DNS settings by hand and remove the file."
                )
            if dns_restore.skipped:
                print(
                    "  Not every family was confirmed as Hole's own prior DNS. Re-run with "
                    "--force-dns-restore if you're sure it's still correct, or remove the file "
                    "by hand once you've verified your DNS."
                )

    print()
    print("Done. Test connectivity: curl -I https://example.com")


if __name__ == "__main__":
    main()
