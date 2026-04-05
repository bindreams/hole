#!/usr/bin/env python3
"""Launch daemon and GUI in dev mode with multiplexed logs.

Starts two processes:
  1. cargo-watch rebuilding the daemon in foreground/no-tun mode
  2. npx tauri dev for the GUI with Vite HMR

Both processes' output is prefixed and color-coded in a single terminal.
Ctrl+C shuts down both.

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
    if not shutil.which("cargo-watch"):
        print(f"{YELLOW}cargo-watch not found. Install it:{RESET}")
        print("  cargo install cargo-watch")
        sys.exit(1)

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

    daemon_cmd = [
        cargo,
        "watch",
        "-x",
        f"run -- daemon run --foreground --no-tun --socket-path {socket_path}",
        "-w",
        "crates/daemon",
        "-w",
        "crates/common",
    ]

    gui_cmd = [npx, "tauri", "dev"]
    gui_env = {**os.environ, "HOLE_DAEMON_SOCKET": str(socket_path)}

    print(f"{BOLD}Starting dev environment...{RESET}")
    print(f"  Socket: {socket_path}")
    print(f"  {CYAN}[daemon]{RESET} cargo watch → foreground --no-tun")
    print(f"  {MAGENTA}[gui]{RESET}    npx tauri dev")
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
            (gui_proc, "gui", MAGENTA),
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
