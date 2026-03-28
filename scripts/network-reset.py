#!/usr/bin/env python3
"""Emergency network reset script for Hole.

Removes all routes and interfaces created by hole-daemon.
Run with admin/root privileges:
  macOS:   sudo python3 scripts/network-reset.py
  Windows: run as Administrator
"""
# /// script
# requires-python = ">=3.9"
# ///

import platform
import subprocess
import sys


def run(cmd: list[str], *, check: bool = False) -> subprocess.CompletedProcess[str]:
    print(f"  $ {' '.join(cmd)}")
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def reset_macos() -> None:
    print("Removing split routes...")
    run(["route", "-n", "delete", "0.0.0.0/1"])
    run(["route", "-n", "delete", "128.0.0.0/1"])

    print("Cleaning routes via utun interfaces...")
    result = run(["ifconfig", "-l"])
    for iface in result.stdout.split():
        if not iface.startswith("utun"):
            continue
        print(f"  Cleaning routes via {iface}...")
        netstat = run(["netstat", "-rn"])
        for line in netstat.stdout.splitlines():
            if iface in line:
                dest = line.split()[0]
                run(["route", "-n", "delete", dest])

    print("Killing hole-daemon...")
    run(["pkill", "-f", "hole-daemon"])

    print("Resetting DNS on all network services...")
    result = run(["networksetup", "-listallnetworkservices"])
    for line in result.stdout.splitlines()[1:]:  # skip header
        service = line.strip()
        if service:
            run(["networksetup", "-setdnsservers", service, "Empty"])

    print("Flushing caches...")
    run(["route", "-n", "flush"])
    run(["dscacheutil", "-flushcache"])
    run(["killall", "-HUP", "mDNSResponder"])


def reset_windows() -> None:
    print("Removing split routes...")
    run([
        "powershell", "-Command",
        'Remove-NetRoute -DestinationPrefix "0.0.0.0/1" -Confirm:$false -ErrorAction SilentlyContinue'
    ])
    run([
        "powershell", "-Command",
        'Remove-NetRoute -DestinationPrefix "128.0.0.0/1" -Confirm:$false -ErrorAction SilentlyContinue'
    ])

    print("Removing /32 bypass routes...")
    run([
        "powershell", "-Command", """
        Get-NetRoute -DestinationPrefix "*/32" -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceAlias -notlike "Loopback*" } |
            ForEach-Object {
                Write-Host "  Removing: $($_.DestinationPrefix)"
                Remove-NetRoute -DestinationPrefix $_.DestinationPrefix -Confirm:$false -ErrorAction SilentlyContinue
            }
    """
    ])

    print("Stopping HoleDaemon service...")
    run(["powershell", "-Command", 'Stop-Service -Name "HoleDaemon" -Force -ErrorAction SilentlyContinue'])
    run([
        "powershell", "-Command", 'Get-Process -Name "hole-daemon" -ErrorAction SilentlyContinue | Stop-Process -Force'
    ])

    print("Removing wintun adapters...")
    run([
        "powershell", "-Command", """
        Get-NetAdapter -Name "hole-tun*" -ErrorAction SilentlyContinue |
            ForEach-Object {
                Write-Host "  Removing: $($_.Name)"
                Remove-NetAdapter -Name $_.Name -Confirm:$false -ErrorAction SilentlyContinue
            }
    """
    ])

    print("Flushing DNS...")
    run(["ipconfig", "/flushdns"])

    print()
    print("If still broken, run these and reboot:")
    print("  netsh winsock reset")
    print("  netsh int ip reset")


def main() -> None:
    print("=== Hole Emergency Network Reset ===")
    print()

    system = platform.system()
    if system == "Darwin":
        reset_macos()
    elif system == "Windows":
        reset_windows()
    else:
        print(f"Unsupported platform: {system}", file=sys.stderr)
        sys.exit(1)

    print()
    print("Done. Test connectivity: curl -I https://example.com")


if __name__ == "__main__":
    main()
