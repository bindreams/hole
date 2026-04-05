#!/usr/bin/env python3
"""Launch daemon and GUI in dev mode with multiplexed logs.

Builds the workspace once, then runs:
  1. The daemon in foreground/no-tun mode
  2. npx tauri dev for the GUI with Vite HMR (frontend-only hot reload)

Rust code changes (daemon or GUI) require Ctrl+C and re-run.
Frontend changes (ui/) are picked up instantly via Vite HMR.

Usage:
  uv run scripts/dev.py
"""
# /// script
# requires-python = ">=3.9"
# ///

import os
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

# ANSI colors ==========================================================================================================

CYAN = "\033[36m"
MAGENTA = "\033[35m"
YELLOW = "\033[33m"
BOLD = "\033[1m"
RESET = "\033[0m"


def prefix_stream(stream, label: str, color: str) -> None:
    """Read lines from a stream and print them with a colored prefix."""
    prefix = f"{color}{BOLD}[{label}]{RESET} "
    try:
        for line in iter(stream.readline, ""):
            print(f"{prefix}{line}", end="", flush=True)
    except ValueError:
        pass  # stream closed


def check_prerequisites() -> None:
    if not Path("node_modules/.bin/tauri").exists() and not Path("node_modules/.bin/tauri.cmd").exists():
        print(f"{YELLOW}node_modules not found. Run:{RESET}")
        print("  npm install")
        sys.exit(1)


def main() -> None:
    # Ensure we're at the project root
    if not Path("Cargo.toml").exists() or not Path("crates/gui").exists():
        print("Error: run this script from the project root")
        sys.exit(1)

    check_prerequisites()

    socket_path = Path(tempfile.gettempdir()) / "hole-dev.sock"

    # Resolve executables explicitly — on Windows, .cmd/.bat files (like npx.cmd)
    # are not found by subprocess.Popen without shell=True.
    cargo = shutil.which("cargo")
    npx = shutil.which("npx")
    if not cargo or not npx:
        missing = [name for name, path in [("cargo", cargo), ("npx", npx)] if not path]
        print(f"{YELLOW}Not found on PATH: {', '.join(missing)}{RESET}")
        sys.exit(1)

    # Build the workspace once up front. Both the daemon and tauri dev need the
    # built binary, and building first avoids races between the two.
    print(f"{BOLD}Building workspace...{RESET}")
    result = subprocess.run([cargo, "build"], stdout=sys.stdout, stderr=sys.stderr)
    if result.returncode != 0:
        sys.exit(result.returncode)

    # Find the built daemon binary
    daemon_bin = Path("target/debug/hole.exe") if sys.platform == "win32" else Path("target/debug/hole")
    if not daemon_bin.exists():
        print(f"{YELLOW}Binary not found at {daemon_bin}{RESET}")
        sys.exit(1)

    daemon_cmd = [str(daemon_bin), "daemon", "run", "--foreground", "--no-tun", "--socket-path", str(socket_path)]

    # tauri dev with --no-watch: skip Rust rebuild (we built already), only run
    # the Vite dev server for frontend HMR.
    gui_cmd = [npx, "tauri", "dev", "--no-watch"]
    gui_env = {**os.environ, "HOLE_DAEMON_SOCKET": str(socket_path)}

    print(f"{BOLD}Starting dev environment...{RESET}")
    print(f"  Socket: {socket_path}")
    print(f"  {CYAN}[daemon]{RESET} {daemon_bin} → foreground --no-tun")
    print(f"  {MAGENTA}[client]{RESET} npx tauri dev --no-watch")
    print(f"  Frontend changes (ui/) hot-reload. Rust changes need restart.")
    print()

    procs: list[subprocess.Popen] = []
    threads: list[threading.Thread] = []

    try:
        daemon_proc = subprocess.Popen(
            daemon_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        procs.append(daemon_proc)

        gui_proc = subprocess.Popen(
            gui_cmd,
            env=gui_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        procs.append(gui_proc)

        for proc, label, color in [
            (daemon_proc, "daemon", CYAN),
            (gui_proc, "client", MAGENTA),
        ]:
            t = threading.Thread(target=prefix_stream, args=(proc.stdout, label, color), daemon=True)
            t.start()
            threads.append(t)

        # Wait for either process to exit
        while all(p.poll() is None for p in procs):
            for t in threads:
                t.join(timeout=0.5)
                if not any(p.poll() is None for p in procs):
                    break

    except KeyboardInterrupt:
        pass
    finally:
        # On Ctrl+C, the OS already sends the signal to all console processes.
        # terminate() is a safety net for any stragglers.
        print(f"\n{BOLD}Shutting down...{RESET}")
        for proc in procs:
            if proc.poll() is None:
                proc.terminate()
        for proc in procs:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    main()
