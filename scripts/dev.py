#!/usr/bin/env python3
r"""Launch bridge + GUI in dev mode with multiplexed, colored logs.

Builds the workspace, then runs three processes:
  1. Vite dev server (frontend HMR on port 1420) — unelevated on macOS
  2. Bridge in foreground mode (REAL TUN + routing) — elevated
  3. GUI (Tauri webview loading from Vite) — unelevated on macOS

REQUIRES ELEVATION:
  Windows: run from an elevated PowerShell (`uv run scripts/dev.py`)
  macOS:   `sudo uv run scripts/dev.py`

On macOS, this script detects `SUDO_USER` and drops privileges for Vite
and the GUI so they read your real ~/Library config, while the bridge
inherits root. On Windows, UAC is token-based so all three inherit the
elevated token without an identity change.

The bridge binary and its v2ray-plugin sidecar are staged in a per-pid
subdirectory under the system temp dir (`$TMPDIR/hole-dev-<pid>/` or
`%TEMP%\hole-dev-<pid>\`) so they sit side-by-side under their canonical
names — same layout as the installed MSI in `Program Files\hole\bin\`.
This is what `resolve_plugin_path_inner` (crates/bridge/src/proxy.rs)
expects, and it isolates concurrent dev.py runs from each other.

Dev uses the production IPC permission path: `hole bridge grant-access`
is invoked to create the `hole` group, add you to it, and (Windows) write
the installer-user-sid file. The bridge itself uses `IpcServer::bind` +
`apply_socket_permissions`, the same code path as the installed service.

If this script crashes or is killed and your internet breaks, run:
  sudo scripts/network-reset.py    (macOS)
  scripts/network-reset.py         (Windows, from an elevated PowerShell)

Frontend changes (ui/) hot-reload instantly. Rust changes need Ctrl+C
and re-run.
"""
# /// script
# requires-python = ">=3.9"
# ///
from __future__ import annotations

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
from typing import Any

import _lib

# ANSI colors ==========================================================================================================

CYAN = "\033[36m"
MAGENTA = "\033[35m"
YELLOW = "\033[33m"
BOLD = "\033[1m"
RESET = "\033[0m"

VITE_PORT = 1420
VITE_READY_TIMEOUT = 30
SOCKET_READY_TIMEOUT = 15

# Chrome DevTools Protocol port for WebView2 remote debugging.
# Enabled on Windows by injecting WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS into
# the GUI process env. Lets external tools (Playwright, chrome-devtools-mcp,
# manual chrome://inspect) attach to the running dashboard.
CDP_PORT = 9222

# Prerequisites ========================================================================================================


def resolve_tool(name: str) -> str:
    """Resolve executable path via shutil.which (handles .cmd on Windows)."""
    path = shutil.which(name)
    if not path:
        print(f"{YELLOW}{name} not found on PATH{RESET}")
        sys.exit(1)
    return path


def ensure_node_modules(npm: str, target_user: tuple[int, int, str, str] | None) -> None:
    """Run `npm install` unconditionally to keep `node_modules/` in sync with
    `package-lock.json`.

    Unconditional install is deliberate: a prior version of this function
    skipped on `node_modules/` existing, which silently hid dependency
    additions pulled from a new commit (e.g. #148 adding
    `@tauri-apps/plugin-log`) and left Vite failing to resolve the import.
    `npm install` on a healthy tree costs ~1s, dominated by cargo below;
    `--no-audit --no-fund` trims the output to a single line so dev.py's
    startup stays quiet on the happy path."""
    print(f"{BOLD}Syncing npm dependencies...{RESET}")
    # Run as the invoking user so `node_modules/` is not owned by root.
    result = subprocess.run(
        [npm, "install", "--no-audit", "--no-fund"],
        stdout=sys.stdout,
        stderr=sys.stderr,
        env=drop_env({**os.environ}, target_user),
        **drop_kwargs(target_user),
    )
    if result.returncode != 0:
        sys.exit(result.returncode)


def cargo_build(cargo: str, target_user: tuple[int, int, str, str] | None) -> None:
    """Build the `hole` target via the orchestrator.

    `cargo xtask build hole` walks the build.yaml DAG: v2ray-plugin → galoshes
    + wintun → cargo build (debug) → stage. Replaces the prior `cargo xtask
    deps` + `cargo build` sequence with a single declarative invocation. The
    per-pid stage that follows in main() is dev.py-specific and stays separate.

    Runs as the invoking user so `target/` and `.cache/` are not owned by root
    on macOS-under-sudo.
    """
    print(f"{BOLD}Building hole (cargo xtask build hole)...{RESET}")
    result = subprocess.run(
        [cargo, "xtask", "build", "hole"],
        stdout=sys.stdout,
        stderr=sys.stderr,
        env=drop_env({**os.environ}, target_user),
        **drop_kwargs(target_user),
    )
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


def wait_for_port(port: int, timeout: float, proc: subprocess.Popen) -> bool:
    """Poll until `proc` is accepting connections on `port` via any address
    `localhost` resolves to (IPv4 and/or IPv6).

    Vite's default `localhost` host can bind to `::1` only (Windows 11,
    macOS) or `127.0.0.1` only depending on the system's hosts-file
    ordering. A hardcoded `127.0.0.1` probe misses the v6-only case and
    reports a false "did not start" timeout while Vite is actually up.

    Returns False immediately if `proc` exits before the port opens, so we don't
    falsely succeed on a port already in use by an unrelated process.
    """
    try:
        addrs = socket.getaddrinfo("localhost", port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        # Fall back to both loopback addresses if name resolution fails.
        addrs = [
            (socket.AF_INET, None, None, "", ("127.0.0.1", port)),
            (socket.AF_INET6, None, None, "", ("::1", port, 0, 0)),
        ]

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        for family, _sock_type, _proto, _canon, sockaddr in addrs:
            try:
                with socket.socket(family, socket.SOCK_STREAM) as sock:
                    sock.settimeout(0.5)
                    sock.connect(sockaddr)
                    return True
            except OSError:
                continue
        time.sleep(0.2)
    return False


def wait_for_socket(path: Path, proc: subprocess.Popen, timeout: float) -> bool:
    """Wait until the bridge socket file appears at `path`, or `proc` dies."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        if path.exists():
            return True
        time.sleep(0.1)
    return False


def wait_for_exit(proc: subprocess.Popen, done: threading.Event) -> None:
    """Wait for a process to exit, then signal the done event."""
    proc.wait()
    done.set()


def new_process_group_kwargs() -> dict[str, Any]:
    """Return Popen kwargs that put the child in its own process group /
    job object so `terminate_tree` can kill the whole subtree.

    Necessary because `npm run dev` spawns `node vite.js` as a
    grandchild. Without a process group, `proc.terminate()` on Windows
    only kills `npm.cmd` and leaves the node/vite child running, which
    holds port 1420 until the OS reaps it (minutes).
    """
    if sys.platform == "win32":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def terminate_tree(proc: subprocess.Popen) -> None:
    """Signal graceful shutdown of `proc` AND all its descendants.

    Windows: `taskkill /T` walks the tree and terminates every process.
    POSIX: `killpg` sends SIGTERM to the whole process group (set up by
    `start_new_session=True` at spawn time).
    """
    if proc.poll() is not None:
        return
    if sys.platform == "win32":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
            capture_output=True,
            check=False,
        )
    else:
        import signal as _signal
        try:
            os.killpg(os.getpgid(proc.pid), _signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            proc.terminate()


def shutdown(procs: list[subprocess.Popen]) -> None:
    print(f"\n{BOLD}Shutting down...{RESET}")
    for proc in procs:
        terminate_tree(proc)
    for proc in procs:
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            # Tree-kill already used SIGKILL on Windows; on POSIX fall
            # back to per-process SIGKILL for any stragglers.
            proc.kill()


# Privilege drop =======================================================================================================


def drop_kwargs(target: tuple[int, int, str, str] | None) -> dict:
    """Return Popen kwargs that drop privileges to `target` on POSIX.

    `extra_groups` is set to the TARGET user's full group list (via
    `os.getgrouplist`), NOT root's supplementary groups and NOT empty —
    we need hole-group membership in the GUI to open the production
    IPC socket on macOS.
    """
    if target is None:
        return {}
    uid, gid, user, _ = target
    groups = os.getgrouplist(user, gid)
    return {"user": uid, "group": gid, "extra_groups": groups}


def drop_env(env: dict, target: tuple[int, int, str, str] | None) -> dict:
    """Reset HOME/USER/LOGNAME in `env` to the target user."""
    if target is None:
        return env
    _, _, user, home = target
    return {**env, "HOME": home, "USER": user, "LOGNAME": user}


# Main =================================================================================================================


def main() -> None:
    if not Path("Cargo.toml").exists() or not Path("crates/hole").exists():
        print("Error: run this script from the project root")
        sys.exit(1)
    project_root = Path.cwd().resolve()

    _lib.require_elevation()
    target_user = _lib.sudo_target_user()  # (uid, gid, user, home) or None

    cargo = resolve_tool("cargo")
    npm = resolve_tool("npm")

    ensure_node_modules(npm, target_user)
    cargo_build(cargo, target_user)

    # Stage the runnable BINDIR (hole.exe + v2ray-plugin.exe + wintun.dll on
    # Windows) in a per-pid subdir under TEMP. The contents and naming are
    # owned by `cargo xtask stage` — see xtask/src/bindir.rs for the canonical
    # file list. Per-pid isolation prevents collisions between concurrent
    # dev.py runs and avoids the running bridge holding a file lock that
    # would block subsequent `cargo build`. Register the rmtree cleanup
    # *before* mkdir so a partially-created dir still gets removed on exit.
    dev_bin_dir = Path(tempfile.gettempdir()) / f"hole-dev-{os.getpid()}"
    atexit.register(lambda: shutil.rmtree(dev_bin_dir, ignore_errors=True))

    stage_result = subprocess.run(
        [cargo, "xtask", "stage", "--profile", "debug", "--out-dir",
         str(dev_bin_dir)],
        cwd=project_root,
        env=drop_env({**os.environ}, target_user),
        **drop_kwargs(target_user),
    )
    if stage_result.returncode != 0:
        print(f"{YELLOW}cargo xtask stage failed (exit {stage_result.returncode}){RESET}")
        sys.exit(stage_result.returncode)

    bin_name = "hole.exe" if sys.platform == "win32" else "hole"
    bridge_bin = dev_bin_dir / bin_name
    built_bin = project_root / "target" / "debug" / bin_name

    socket_path = Path(tempfile.gettempdir()) / "hole-dev.sock"
    bridge_state_dir = Path(tempfile.gettempdir()) / "hole-dev" / "state"
    bridge_state_dir.mkdir(parents=True, exist_ok=True)

    # Set up IPC access via the production path BEFORE starting the bridge
    # so that apply_socket_permissions picks up the hole group + user SID
    # from the very first socket bind.
    print(f"{BOLD}Granting IPC access (creates hole group, adds user)...{RESET}")
    grant_result = subprocess.run(
        [str(bridge_bin), "bridge", "grant-access"],
        stdout=sys.stdout,
        stderr=sys.stderr,
    )
    if grant_result.returncode != 0:
        print(f"{YELLOW}bridge grant-access failed (exit {grant_result.returncode}){RESET}")
        sys.exit(grant_result.returncode)

    print(f"\n{BOLD}Starting dev environment...{RESET}")
    print(f"  Socket:    {socket_path}")
    print(f"  State dir: {bridge_state_dir}")
    print(f"  {CYAN}[bridge]{RESET} {bridge_bin} → real TUN + routing (elevated)")
    if target_user is not None:
        print(f"  {MAGENTA}[client]{RESET} {built_bin} (GUI) → dropped to user '{target_user[2]}'")
        print(f"  {YELLOW}[  vite]{RESET} npm run dev → port 1420 (dropped to user '{target_user[2]}')")
    else:
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
            env=drop_env({**os.environ}, target_user),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            **drop_kwargs(target_user),
            **new_process_group_kwargs(),
        )
        procs.append(vite_proc)
        threading.Thread(target=prefix_stream, args=(vite_proc.stdout, "  vite", YELLOW), daemon=True).start()
        threading.Thread(target=wait_for_exit, args=(vite_proc, done), daemon=True).start()

        if not wait_for_port(VITE_PORT, VITE_READY_TIMEOUT, vite_proc):
            if vite_proc.poll() is not None:
                print(f"{YELLOW}Vite exited with code {vite_proc.returncode}{RESET}")
            else:
                print(f"{YELLOW}Vite did not start on port {VITE_PORT} within {VITE_READY_TIMEOUT}s{RESET}")
            sys.exit(1)  # finally block handles shutdown

        # Start bridge (inherits elevated credentials).
        bridge_proc = subprocess.Popen(
            [
                str(bridge_bin),
                "bridge",
                "run",
                "--socket-path",
                str(socket_path),
                "--state-dir",
                str(bridge_state_dir),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            **new_process_group_kwargs(),
        )
        procs.append(bridge_proc)
        threading.Thread(target=prefix_stream, args=(bridge_proc.stdout, "bridge", CYAN), daemon=True).start()
        threading.Thread(target=wait_for_exit, args=(bridge_proc, done), daemon=True).start()

        # Wait for the bridge to bind the socket before starting the GUI.
        # Without this, the GUI races the bridge's apply_socket_permissions
        # and can see a socket without the correct DACL/group yet.
        if not wait_for_socket(socket_path, bridge_proc, SOCKET_READY_TIMEOUT):
            if bridge_proc.poll() is not None:
                print(f"{YELLOW}Bridge exited with code {bridge_proc.returncode}{RESET}")
            else:
                print(f"{YELLOW}Bridge did not bind socket within {SOCKET_READY_TIMEOUT}s{RESET}")
            sys.exit(1)

        # Start GUI (dropped to target user on macOS under sudo).
        gui_env = drop_env({**os.environ, "HOLE_BRIDGE_SOCKET": str(socket_path)}, target_user)

        # Enable remote inspection of the dashboard webview. The env var only
        # affects WebView2 (Windows) — WKWebView on macOS ignores it — but
        # setting it unconditionally is harmless. Append to any existing value
        # rather than overwriting.
        existing_args = gui_env.get("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", "").strip()
        cdp_arg = f"--remote-debugging-port={CDP_PORT}"
        gui_env["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = f"{existing_args} {cdp_arg}".strip()

        if sys.platform == "win32":
            # WebView2 exposes the Chrome DevTools Protocol on this port.
            print(f"{BOLD}WebView2 remote debugging:{RESET} http://127.0.0.1:{CDP_PORT}")
        elif sys.platform == "darwin":
            # WKWebView exposes itself to Safari's Web Inspector via XPC, not
            # over a TCP port. Safari → Settings → Advanced → "Show features
            # for web developers" must be enabled once. CDP-based tools
            # (chrome-devtools-mcp, Playwright Chromium driver) cannot attach
            # to a WKWebView — use Playwright's WebKit driver instead.
            print(f"{BOLD}WKWebView remote debugging:{RESET} Safari → Develop → Hole → Hole Dashboard")

        gui_proc = subprocess.Popen(
            [str(built_bin), "--show-dashboard"],
            env=gui_env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            **drop_kwargs(target_user),
            **new_process_group_kwargs(),
        )
        procs.append(gui_proc)
        threading.Thread(target=prefix_stream, args=(gui_proc.stdout, "client", MAGENTA), daemon=True).start()
        threading.Thread(target=wait_for_exit, args=(gui_proc, done), daemon=True).start()

        # Block until any process exits or Ctrl+C.
        #
        # Poll on a short timeout instead of an unbounded wait. On Windows, an
        # unbounded threading.Event.wait() blocks in a native condition variable
        # that does not return for queued Python signals, swallowing Ctrl+C and
        # preventing the `finally: shutdown(procs)` clause from running. A timed
        # wait wakes the interpreter periodically so the pending KeyboardInterrupt
        # can actually be raised.
        #
        # This is NOT a busy-wait or a latency penalty for the normal exit path:
        # Event.wait(timeout) on both POSIX (futex) and Windows (WaitForSingleObject)
        # wakes immediately when the daemon `wait_for_exit` thread calls done.set(),
        # regardless of how much of the 0.5s remains. The 0.5s only bounds the
        # Ctrl+C delivery latency.
        while not done.wait(timeout=0.5):
            pass

    except KeyboardInterrupt:
        pass
    finally:
        shutdown(procs)


if __name__ == "__main__":
    main()
