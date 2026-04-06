#!/usr/bin/env python3
"""Launch bridge and GUI in dev mode with multiplexed logs.

Builds the workspace, then runs three processes:
  1. Vite dev server (frontend HMR on port 1420)
  2. Bridge in foreground/no-tun mode
  3. GUI (Tauri webview loading from Vite)

Frontend changes (ui/) hot-reload instantly. Rust changes need Ctrl+C and re-run.

Usage:
  uv run scripts/dev.py
"""
# /// script
# requires-python = ">=3.9"
# ///

import atexit
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

# ANSI colors ==========================================================================================================

CYAN = "\033[36m"
MAGENTA = "\033[35m"
YELLOW = "\033[33m"
BOLD = "\033[1m"
RESET = "\033[0m"

VITE_PORT = 1420
VITE_READY_TIMEOUT = 30

# Prerequisites ========================================================================================================


def resolve_tool(name: str) -> str:
    """Resolve executable path via shutil.which (handles .cmd on Windows)."""
    path = shutil.which(name)
    if not path:
        print(f"{YELLOW}{name} not found on PATH{RESET}")
        sys.exit(1)
    return path


def ensure_node_modules(npm: str) -> None:
    if Path("node_modules").exists():
        return
    print(f"{BOLD}Installing npm dependencies...{RESET}")
    result = subprocess.run([npm, "install"], stdout=sys.stdout, stderr=sys.stderr)
    if result.returncode != 0:
        sys.exit(result.returncode)


def cargo_build(cargo: str) -> None:
    print(f"{BOLD}Building workspace...{RESET}")
    result = subprocess.run([cargo, "build"], stdout=sys.stdout, stderr=sys.stderr)
    if result.returncode != 0:
        sys.exit(result.returncode)


# Process management ===================================================================================================


def prefix_stream(stream, label: str, color: str) -> None:
    """Read lines from a stream and print them with a colored prefix."""
    prefix = f"{color}{BOLD}[{label}]{RESET} "
    try:
        for line in iter(stream.readline, ""):
            print(f"{prefix}{line}", end="", flush=True)
    except ValueError:
        pass  # stream closed


def wait_for_port(port: int, timeout: float) -> bool:
    """Poll until a TCP port is accepting connections."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def wait_for_exit(proc: subprocess.Popen, done: threading.Event) -> None:
    """Wait for a process to exit, then signal the done event."""
    proc.wait()
    done.set()


def shutdown(procs: list[subprocess.Popen]) -> None:
    print(f"\n{BOLD}Shutting down...{RESET}")
    for proc in procs:
        if proc.poll() is None:
            proc.terminate()
    for proc in procs:
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


# Main =================================================================================================================


def main() -> None:
    if not Path("Cargo.toml").exists() or not Path("crates/gui").exists():
        print("Error: run this script from the project root")
        sys.exit(1)

    cargo = resolve_tool("cargo")
    npm = resolve_tool("npm")

    ensure_node_modules(npm)
    cargo_build(cargo)

    # Locate built binary
    bin_name = "hole.exe" if sys.platform == "win32" else "hole"
    built_bin = Path("target/debug") / bin_name
    if not built_bin.exists():
        print(f"{YELLOW}Binary not found at {built_bin}{RESET}")
        sys.exit(1)

    # Copy bridge binary to temp dir — the running bridge holds a file lock on the
    # binary, which would block a subsequent cargo build. The GUI runs from the
    # original path (unlocked after it starts, since the OS loads it into memory).
    bridge_bin = Path(
        tempfile.gettempdir()
    ) / f"hole-dev-bridge-{os.getpid()}{'.exe' if sys.platform == 'win32' else ''}"
    shutil.copy2(built_bin, bridge_bin)
    atexit.register(lambda: bridge_bin.unlink(missing_ok=True))

    socket_path = Path(tempfile.gettempdir()) / "hole-dev.sock"

    print(f"\n{BOLD}Starting dev environment...{RESET}")
    print(f"  Socket: {socket_path}")
    print(f"  {CYAN}[bridge]{RESET} {bridge_bin.name} → --no-tun")
    print(f"  {MAGENTA}[client]{RESET} {built_bin} (GUI)")
    print(f"  {YELLOW}[  vite]{RESET} npm run dev → port 1420")
    print(f"  Frontend changes hot-reload. Rust changes need Ctrl+C and re-run.")
    print()

    procs: list[subprocess.Popen] = []
    done = threading.Event()

    try:
        # Start Vite first — GUI needs it listening before the webview opens.
        # stdin=DEVNULL prevents child processes from accessing the parent console's stdin.
        # Without this, Vite (via readline) puts the TTY into raw mode for keyboard shortcuts
        # and doesn't restore it when terminated, leaving arrow keys broken.
        vite_proc = subprocess.Popen(
            [npm, "run", "dev"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        procs.append(vite_proc)
        threading.Thread(target=prefix_stream, args=(vite_proc.stdout, "  vite", YELLOW), daemon=True).start()
        threading.Thread(target=wait_for_exit, args=(vite_proc, done), daemon=True).start()

        if not wait_for_port(VITE_PORT, timeout=VITE_READY_TIMEOUT):
            if vite_proc.poll() is not None:
                print(f"{YELLOW}Vite exited with code {vite_proc.returncode}{RESET}")
            else:
                print(f"{YELLOW}Vite did not start on port {VITE_PORT} within {VITE_READY_TIMEOUT}s{RESET}")
            shutdown(procs)
            sys.exit(1)

        # Start bridge
        bridge_proc = subprocess.Popen(
            [str(bridge_bin), "bridge", "run", "--no-tun", "--socket-path",
             str(socket_path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        procs.append(bridge_proc)
        threading.Thread(target=prefix_stream, args=(bridge_proc.stdout, "bridge", CYAN), daemon=True).start()
        threading.Thread(target=wait_for_exit, args=(bridge_proc, done), daemon=True).start()

        # Start GUI
        gui_env = {**os.environ, "HOLE_BRIDGE_SOCKET": str(socket_path)}
        gui_proc = subprocess.Popen(
            [str(built_bin)],
            env=gui_env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        procs.append(gui_proc)
        threading.Thread(target=prefix_stream, args=(gui_proc.stdout, "client", MAGENTA), daemon=True).start()
        threading.Thread(target=wait_for_exit, args=(gui_proc, done), daemon=True).start()

        # Block until any process exits or Ctrl+C
        done.wait()

    except KeyboardInterrupt:
        pass
    finally:
        shutdown(procs)


if __name__ == "__main__":
    main()
