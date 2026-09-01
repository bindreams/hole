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
import json
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

import _lib

# Keep in sync with `crates/tun-engine/src/routing/state.rs::STATE_FILE_NAME`.
STATE_FILE_NAME = "bridge-routes.json"
# Keep in sync with `crates/bridge/src/dns_state.rs::STATE_FILE_NAME` /
# `SUPERSEDED_FILE_NAME`. The bridge's own upgrade sweep (bindreams/hole#846)
# evaluates `DNS_STATE_FILE_NAME` at most once: on full success it deletes
# the file, otherwise it renames it to `DNS_STATE_SUPERSEDED_FILE_NAME` and
# never reads that name again. This script reads BOTH so the escape survives
# that rename rather than being hidden by it.
DNS_STATE_FILE_NAME = "bridge-dns.json"
DNS_STATE_SUPERSEDED_FILE_NAME = "bridge-dns.superseded.json"


def load_dns_state_file() -> tuple[dict, Path] | None:
    """Return the first valid parsed DNS state file found across candidate
    state directories — checking the un-suffixed name before the superseded
    one — plus the path it came from. Mirrors `load_state_file` but for
    DNS."""
    for name in (DNS_STATE_FILE_NAME, DNS_STATE_SUPERSEDED_FILE_NAME):
        for d in candidate_state_dirs():
            path = d / name
            if not path.exists():
                continue
            try:
                with path.open() as f:
                    data = json.load(f)
                print(f"  Found DNS state file at {path}")
                return data, path
            except (json.JSONDecodeError, OSError) as e:
                print(f"  Skipping {path} (parse error: {e})")
    return None


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
    result = run([
        "powershell",
        "-Command",
        f'(Get-DnsClientServerAddress -InterfaceAlias "{alias}" -AddressFamily {fam_flag} '
        f"-ErrorAction SilentlyContinue).ServerAddresses -join ','",
    ])
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


def restore_dns_windows(state: dict, *, force: bool) -> bool:
    """Returns True iff every recorded family was either restored or
    skipped by explicit --force (i.e. nothing was left unconfirmed)."""
    print("Restoring prior DNS settings (Windows)...")
    any_skipped = False
    advertised_v4, advertised_v6 = _split_advertised(state.get("advertised", []))
    for adapter in state.get("adapters", []):
        id_obj = adapter.get("id", {})
        if id_obj.get("kind") != "windows_alias":
            continue
        alias = id_obj.get("value")
        if not alias:
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
                    any_skipped = True
                    continue
            prior = adapter.get(field, {})
            kind = prior.get("kind")
            if kind == "dhcp":
                run([
                    "netsh",
                    "interface",
                    family,
                    "set",
                    "dnsservers",
                    f"name={alias}",
                    "dhcp",
                ])
            elif kind == "none":
                run([
                    "netsh",
                    "interface",
                    family,
                    "set",
                    "dnsservers",
                    f"name={alias}",
                    "static",
                    "none",
                ])
            elif kind == "static":
                servers = prior.get("servers", [])
                if not servers:
                    continue
                run([
                    "netsh",
                    "interface",
                    family,
                    "set",
                    "dnsservers",
                    f"name={alias}",
                    "static",
                    servers[0],
                    "primary",
                ])
                for idx, ip in enumerate(servers[1:], start=2):
                    run([
                        "netsh",
                        "interface",
                        family,
                        "add",
                        "dnsservers",
                        f"name={alias}",
                        ip,
                        f"index={idx}",
                    ])
    return not any_skipped


def restore_dns_macos(state: dict, *, force: bool) -> bool:
    """Returns True iff nothing was left unconfirmed — see
    `restore_dns_windows`'s doc."""
    print("Restoring prior DNS settings (macOS)...")
    any_skipped = False
    advertised_v4, advertised_v6 = _split_advertised(state.get("advertised", []))
    for adapter in state.get("adapters", []):
        id_obj = adapter.get("id", {})
        if id_obj.get("kind") != "macos_service_name":
            continue
        svc = id_obj.get("value")
        if not svc:
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
                any_skipped = True
                continue

        combined: list[str] = []
        saw_static = False
        for field in ("v4", "v6"):
            prior = adapter.get(field, {})
            if prior.get("kind") == "static":
                saw_static = True
                combined.extend(prior.get("servers", []))
        if saw_static and combined:
            run(["networksetup", "-setdnsservers", svc, *combined])
        else:
            run(["networksetup", "-setdnsservers", svc, "Empty"])
    return not any_skipped


def clear_dns_state_file(path: Path) -> None:
    """Remove exactly the DNS state file that was read (whichever of the two
    names it was) — never a blind sweep of both, so a file this run
    deliberately preserved (an unconfirmed restore) isn't also deleted."""
    try:
        path.unlink()
        print(f"  Removed {path}")
    except OSError as e:
        print(f"  Failed to remove {path}: {e}")


def run(cmd: list[str], *, check: bool = False) -> subprocess.CompletedProcess[str]:
    print(f"  $ {' '.join(cmd)}")
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


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


def load_state_file() -> dict | None:
    """Return the first valid parsed state file found across candidate
    directories, or None if none exists / all are corrupted."""
    for d in candidate_state_dirs():
        path = d / STATE_FILE_NAME
        if not path.exists():
            continue
        try:
            with path.open() as f:
                data = json.load(f)
            print(f"  Found state file at {path}")
            return data
        except (json.JSONDecodeError, OSError) as e:
            print(f"  Skipping {path} (parse error: {e})")
    return None


def reset_macos(state: dict | None) -> None:
    print("Removing split routes (IPv4 + IPv6)...")
    run(["route", "-n", "delete", "-net", "0.0.0.0/1"])
    run(["route", "-n", "delete", "-net", "128.0.0.0/1"])
    run(["route", "-n", "delete", "-inet6", "::/1"])
    run(["route", "-n", "delete", "-inet6", "8000::/1"])

    if state is not None:
        server_ip = state.get("server_ip", "")
        if ":" in server_ip:
            print(f"Removing IPv6 bypass route for {server_ip}...")
            run(["route", "-n", "delete", "-inet6", "-host", server_ip])
        elif server_ip:
            print(f"Removing IPv4 bypass route for {server_ip}...")
            run(["route", "-n", "delete", "-host", server_ip])
    else:
        print(
            "  No state file found — cannot identify per-server bypass route. "
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
        server_ip = state.get("server_ip", "")
        if ":" in server_ip:
            print(f"Removing IPv6 bypass route for {server_ip}...")
            run([
                "powershell",
                "-Command",
                f'Remove-NetRoute -DestinationPrefix "{server_ip}/128" '
                f'-Confirm:$false -ErrorAction SilentlyContinue',
            ])
        elif server_ip:
            print(f"Removing IPv4 bypass route for {server_ip}...")
            run([
                "powershell",
                "-Command",
                f'Remove-NetRoute -DestinationPrefix "{server_ip}/32" '
                f'-Confirm:$false -ErrorAction SilentlyContinue',
            ])
    else:
        print(
            "  No state file found — cannot identify per-server bypass route. "
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


def main() -> None:
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
    state = load_state_file()
    print()

    print("Looking for DNS-state file...")
    dns_state_and_path = load_dns_state_file()
    print()

    system = platform.system()
    dns_fully_confirmed = True
    if system == "Darwin":
        if dns_state_and_path is not None:
            dns_fully_confirmed = restore_dns_macos(dns_state_and_path[0], force=args.force_dns_restore)
        reset_macos(state)
    elif system == "Windows":
        if dns_state_and_path is not None:
            dns_fully_confirmed = restore_dns_windows(dns_state_and_path[0], force=args.force_dns_restore)
        reset_windows(state)
    else:
        print(f"Unsupported platform: {system}", file=sys.stderr)
        sys.exit(1)

    if dns_state_and_path is not None:
        _, dns_state_path = dns_state_and_path
        if dns_fully_confirmed:
            clear_dns_state_file(dns_state_path)
        else:
            print(
                "  Leaving the DNS state file in place — not every family was confirmed as "
                "Hole's own prior DNS. Re-run with --force-dns-restore if you're sure it's "
                "still correct, or remove the file by hand once you've verified your DNS."
            )

    print()
    print("Done. Test connectivity: curl -I https://example.com")


if __name__ == "__main__":
    main()
