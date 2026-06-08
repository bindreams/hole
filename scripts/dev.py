#!/usr/bin/env python3
r"""Launch bridge + GUI in dev mode with multiplexed, colored logs.

Builds the workspace, then runs three processes:
  1. Vite dev server (frontend HMR on port 1420) — unelevated on macOS
  2. Bridge in foreground mode (REAL TUN + routing) — elevated
  3. GUI (Tauri webview loading from Vite) — unelevated on macOS

USAGE:
  Windows: from an elevated PowerShell — `cargo xtask run hole`
  macOS / Linux: `cargo xtask run hole`  (NO sudo)

On POSIX dev.py runs as your user and elevates only the bridge
(`bridge grant-access` + `bridge run`) via sudo, so target/ stays owned by
you. Do NOT run it under sudo — it refuses, and a sudo'd `cargo xtask run
hole` leaves root-owned files in target/ — its outer build cascade runs as
root before dev.py can refuse (bindreams/hole#452). Closing that
sudo-invocation path structurally is tracked in #453. The dev GUI needs the
`hole` group for the IPC
socket; the first run after grant-access creates the group, so a one-time
log-out/in may be required. On Windows, UAC is token-based so all three
inherit the elevated token without an identity change.

The bridge binary and its sidecars (ex-ray, galoshes) are staged in a
per-pid subdirectory under the system temp dir (`$TMPDIR/hole-dev-<pid>/` or
`%TEMP%\hole-dev-<pid>\`) so they sit side-by-side under their canonical
names — same layout as the installed MSI in `Program Files\hole\bin\`.
This is what `resolve_plugin_path_inner` (crates/bridge/src/proxy/config.rs)
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
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Literal

# `grp` is POSIX-only. dev.py is also invoked on Windows, where the hole-group
# gate in main() is skipped (guarded by `system != "Windows"`). Gate the import
# so module load succeeds on Windows.
if sys.platform != "win32":
    import grp

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


def ensure_node_modules(npm: str) -> None:
    """Run `npm install` unconditionally to keep `node_modules/` in sync with
    `package-lock.json`. Runs as the invoking user — dev.py is unprivileged.

    Unconditional install is deliberate: a conditional skip-on-exists would
    silently miss dependency additions pulled from a new commit and leave Vite
    failing to resolve the import. `npm install` on a healthy tree costs ~1s,
    dominated by cargo below; `--no-audit --no-fund` trims the output to a
    single line so dev.py's startup stays quiet on the happy path."""
    print(f"{BOLD}Syncing npm dependencies...{RESET}")
    result = subprocess.run(
        [npm, "install", "--no-audit", "--no-fund"],
        stdout=sys.stdout,
        stderr=sys.stderr,
    )
    if result.returncode != 0:
        sys.exit(result.returncode)


def cargo_build(cargo: str) -> None:
    """Build the `hole` target via the orchestrator, as the invoking user.

    `cargo xtask build hole` walks the build.yaml DAG: ex-ray → galoshes
    + wintun → cargo build (debug) → stage. The per-pid stage that follows in
    main() is dev.py-specific and stays separate.

    The outer `cargo xtask run hole` cascade just ran this as this same user
    (dev.py refuses to run as root upstream), so this is an incremental no-op
    with consistent ownership — no root-owned artifacts.
    """
    print(f"{BOLD}Building hole (cargo xtask build hole)...{RESET}")
    result = subprocess.run(
        [cargo, "xtask", "build", "hole"],
        stdout=sys.stdout,
        stderr=sys.stderr,
        # HOLE_CRASH_DUMPS opts galoshes' xtask build into the dev-only
        # minidump feature (bindreams/hole#438), matching the hole target's
        # --features tombstone/crash-dumps. Never set in release/MSI builds.
        env={**os.environ, "HOLE_CRASH_DUMPS": "1"},
    )
    if result.returncode != 0:
        sys.exit(result.returncode)


# Process management ===================================================================================================

_ISO_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T")


def prefix_stream(
    stream,
    label: str,
    color: str,
    lock: threading.Lock,
    *,
    buffer_entries: bool,
) -> None:
    """Read lines from a stream and print them with a colored prefix.

    Two modes:

    - ``buffer_entries=True``: assume the stream emits structured
      tracing entries that start with an ISO 8601 timestamp; any
      continuation line (indented YAML body, stdlib panic frames, etc.)
      is part of the previous entry. The whole entry is buffered and
      flushed as a single atomic write under ``lock`` once the next
      entry-start arrives — or on EOF — so concurrent streams cannot
      split a multi-line entry (such as a panic backtrace) across each
      other.

    - ``buffer_entries=False``: each line is printed directly under
      ``lock``. Used for streams that have no timestamp anchor (Vite),
      where buffering would never see an entry-start and the stream's
      output would never flush.

    Tradeoff for the buffered mode: a quiet stream's last entry sits
    in the buffer until the next entry-start arrives or EOF. In dev
    the bridge has constant heartbeat traffic so latency is bounded;
    the worst case (panic-then-exit) is bounded by subprocess EOF,
    which triggers the final flush.
    """
    prefix = f"{color}{BOLD}[{label}]{RESET} "

    if not buffer_entries:
        try:
            for line in iter(stream.readline, ""):
                with lock:
                    print(f"{prefix}{line}", end="", flush=True)
        except ValueError:
            pass  # stream closed
        return

    buffer: list[str] = []

    def flush() -> None:
        if not buffer:
            return
        joined = "".join(f"{prefix}{ln}" for ln in buffer)
        with lock:
            sys.stdout.write(joined)
            sys.stdout.flush()
        buffer.clear()

    try:
        for line in iter(stream.readline, ""):
            if _ISO_TIMESTAMP_RE.match(line):
                # New entry-start. Emit any previous entry, begin a new buffer.
                flush()
                buffer.append(line)
            elif buffer:
                # Continuation of the in-progress entry.
                buffer.append(line)
            else:
                # Standalone line with no preceding entry — e.g. the
                # raw stdlib panic message `thread '...' panicked at ...`
                # printed by the default panic hook AFTER the tracing
                # entry was already flushed. Emit immediately.
                with lock:
                    print(f"{prefix}{line}", end="", flush=True)
        flush()
    except ValueError:
        flush()  # stream closed


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
        # External-event-with-graceful-failure exception (CLAUDE.md
        # §Synchronization invariant): the subprocess is out-of-process,
        # OS doesn't expose an "Nth process bound port P" event, so we
        # poll. Failure is relayed cleanly via the False return.
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
        # External-event-with-graceful-failure exception (CLAUDE.md
        # §Synchronization invariant): subprocess file creation is not
        # synchronously observable cross-process. Failure returns False.
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


def shutdown(
    procs: list[subprocess.Popen],
    prefix_threads: list[threading.Thread] | None = None,
    *,
    bridge_proc: subprocess.Popen | None = None
) -> None:
    print(f"\n{BOLD}Shutting down...{RESET}")
    # SIGTERM via killpg; sudo relays SIGTERM to the bridge, whose handler
    # runs the graceful route/DNS teardown.
    for proc in procs:
        terminate_tree(proc)
    for proc in procs:
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            if proc is bridge_proc:
                # The bridge runs as root behind sudo (pty/monitor mode on
                # sudo >= 1.9.14 puts it in its own session), so an
                # unprivileged parent cannot reliably force-kill it: SIGKILL
                # to the sudo wrapper does not reach the bridge and sudo
                # cannot relay SIGKILL. The graceful SIGTERM above is the
                # supported stop; if it didn't take, point at the recovery tool.
                print(
                    f"{YELLOW}The bridge did not exit within 10s and may still be running "
                    f"as root with routing changes in place.\nRun `sudo scripts/network-reset.py` "
                    f"to restore connectivity.{RESET}",
                    file=sys.stderr,
                )
            else:
                proc.kill()
    if prefix_threads is not None:
        for t in prefix_threads:
            t.join(timeout=5)


# Privilege model ======================================================================================================

# Env vars worth preserving across the sudo boundary into the elevated bridge:
# log filtering + backtraces. sudo scrubs the environment otherwise, silently
# changing dev logging behavior. RUST_LOG/RUST_BACKTRACE/HOLE_BRIDGE_LOG are
# not on sudo's default env blacklist, so `--preserve-env=<list>` passes them.
SUDO_PRESERVE_ENV = ["RUST_LOG", "RUST_BACKTRACE", "HOLE_BRIDGE_LOG"]


def elevation_action(system: str, euid: int | None) -> Literal["windows-require-admin", "posix-error-root", "posix-ok"]:
    """How dev mode handles privilege on this host.

    "windows-require-admin": Windows — require an already-elevated shell (UAC
    token-based; nothing is dropped). "posix-error-root": POSIX as root —
    refuse; dev mode runs unprivileged and elevates only the bridge, and
    running as root re-poisons target/ (bindreams/hole#452). "posix-ok":
    POSIX as a normal user — the supported path. `euid` is unused on Windows.
    """
    if system == "Windows":
        return "windows-require-admin"
    if euid == 0:
        return "posix-error-root"
    return "posix-ok"


def sudo_prefix(system: str) -> list[str]:
    """`["sudo"]` on POSIX, `[]` on Windows (already elevated; no sudo)."""
    return [] if system == "Windows" else ["sudo"]


def _elevated(elevate: list[str]) -> list[str]:
    """sudo prefix with env preservation, or [] when not elevating."""
    return [*elevate, f"--preserve-env={','.join(SUDO_PRESERVE_ENV)}"] if elevate else []


def grant_access_argv(elevate: list[str], bridge_bin: str | os.PathLike[str]) -> list[str]:
    """argv for `bridge grant-access`, sudo-prefixed on POSIX."""
    return [*_elevated(elevate), str(bridge_bin), "bridge", "grant-access"]


def bridge_argv(
    elevate: list[str], bridge_bin: str | os.PathLike[str], socket_path: str | os.PathLike[str],
    state_dir: str | os.PathLike[str]
) -> list[str]:
    """argv for `bridge run`, sudo-prefixed on POSIX."""
    return [
        *_elevated(elevate),
        str(bridge_bin), "bridge", "run", "--socket-path",
        str(socket_path), "--state-dir",
        str(state_dir)
    ]


def missing_hole_group(hole_gid: int | None, current_gids: set[int]) -> bool:
    """True if `hole` exists but the current process is not a member.

    Pass `set(os.getgroups()) | {os.getgid(), os.getegid()}` as `current_gids`
    — `os.getgroups()` omits the primary/effective gid on some systems, which
    would falsely report a user whose primary group is `hole` as missing.
    `hole_gid is None` means the group does not exist yet (nothing to check).
    """
    return hole_gid is not None and hole_gid not in current_gids


# Main =================================================================================================================


def main() -> None:
    if not Path("Cargo.toml").exists() or not Path("crates/hole").exists():
        print("Error: run this script from the project root")
        sys.exit(1)
    project_root = Path.cwd().resolve()

    system = platform.system()
    euid = None if system == "Windows" else os.geteuid()
    action = elevation_action(system, euid)
    if action == "windows-require-admin":
        _lib.require_elevation()  # elevated PowerShell (unchanged)
    elif action == "posix-error-root":
        print(
            "ERROR: do not run dev mode as root / under sudo.\n"
            "Run `cargo xtask run hole` (no sudo) — dev.py elevates only the\n"
            "bridge itself. Running as root leaves root-owned files in target/.",
            file=sys.stderr,
        )
        sys.exit(1)
    # else "posix-ok": proceed unprivileged.

    cargo = resolve_tool("cargo")
    npm = resolve_tool("npm")

    ensure_node_modules(npm)
    cargo_build(cargo)

    # Stage the runnable BINDIR (hole.exe + ex-ray.exe + wintun.dll on
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

    # Dev mode runs unprivileged; only the bridge needs root. Cache sudo
    # credentials up-front so the back-to-back grant-access + bridge run calls
    # don't each prompt (and so Vite's readiness wait can't straddle the cache).
    elevate = sudo_prefix(system)
    if elevate:
        print(f"{BOLD}Dev mode needs root for the bridge — caching sudo credentials...{RESET}")
        try:
            if subprocess.run([*elevate, "-v"]).returncode != 0:
                print(f"{YELLOW}sudo authentication failed{RESET}", file=sys.stderr)
                sys.exit(1)
        except FileNotFoundError:
            print(f"{YELLOW}sudo not found on PATH; cannot elevate the bridge{RESET}", file=sys.stderr)
            sys.exit(1)

    # Set up IPC access via the production path BEFORE starting the bridge
    # so that apply_socket_permissions picks up the hole group + user SID
    # from the very first socket bind.
    print(f"{BOLD}Granting IPC access (creates hole group, adds user)...{RESET}")
    grant_result = subprocess.run(
        grant_access_argv(elevate, bridge_bin),
        stdout=sys.stdout,
        stderr=sys.stderr,
    )
    if grant_result.returncode != 0:
        print(f"{YELLOW}bridge grant-access failed (exit {grant_result.returncode}){RESET}")
        sys.exit(grant_result.returncode)

    # The GUI must be in `hole` to open the IPC socket. If the group was just
    # created (or the user hasn't re-logged in since), the running session
    # lacks it. Check effective+real+supplementary gids.
    if system != "Windows":
        try:
            hole_gid = grp.getgrnam("hole").gr_gid
        except KeyError:
            hole_gid = None
        except OSError as e:  # macOS Directory Services transient failure
            print(f"{YELLOW}warning: could not look up 'hole' group: {e}{RESET}", file=sys.stderr)
            hole_gid = None
        current_gids = set(os.getgroups()) | {os.getgid(), os.getegid()}
        if missing_hole_group(hole_gid, current_gids):
            print(
                f"\n{YELLOW}Added you to the 'hole' group, but your current login session "
                f"predates it,\nso the dashboard can't reach the bridge yet. Log out and back "
                f"in (or reboot),\nthen run `cargo xtask run hole` again. One-time per machine. "
                f"(`newgrp hole` may also work.){RESET}",
                file=sys.stderr,
            )
            sys.exit(1)

    print(f"\n{BOLD}Starting dev environment...{RESET}")
    print(f"  Socket:    {socket_path}")
    print(f"  State dir: {bridge_state_dir}")
    sudo_note = "" if system == "Windows" else "sudo "
    print(f"  {CYAN}[bridge]{RESET} {sudo_note}{bridge_bin} → real TUN + routing (elevated)")
    print(f"  {MAGENTA}[client]{RESET} {built_bin} (GUI, as you)")
    print(f"  {YELLOW}[  vite]{RESET} npm run dev → port 1420 (as you)")
    print(f"  Frontend changes hot-reload. Rust changes need Ctrl+C and re-run.")
    print()

    procs: list[subprocess.Popen] = []
    prefix_threads: list[threading.Thread] = []
    print_lock = threading.Lock()
    done = threading.Event()

    # Initialized after the bridge Popen; declared here so the finally block is
    # safe even if startup fails before the bridge starts.
    bridge_proc: subprocess.Popen | None = None

    try:
        # Start the bridge first so all sudo calls are back-to-back after the
        # `sudo -v` preflight — Vite's readiness wait no longer straddles the
        # credential cache. stdin=DEVNULL means an expired sudo timestamp gets
        # EOF and exits non-zero (wait_for_socket then reports a clean failure)
        # rather than hanging on a prompt.
        bridge_proc = subprocess.Popen(
            bridge_argv(elevate, bridge_bin, socket_path, bridge_state_dir),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            **new_process_group_kwargs(),
        )
        procs.append(bridge_proc)
        # Bridge emits ISO-timestamped tracing entries; buffer multi-line
        # entries so panic backtraces don't get split by [client] lines.
        t_bridge = threading.Thread(
            target=prefix_stream,
            args=(bridge_proc.stdout, "bridge", CYAN, print_lock),
            kwargs={"buffer_entries": True},
            daemon=True,
        )
        t_bridge.start()
        prefix_threads.append(t_bridge)
        threading.Thread(target=wait_for_exit, args=(bridge_proc, done), daemon=True).start()

        # Wait for the bridge to bind the socket before starting the GUI.
        # Without this, the GUI races the bridge's apply_socket_permissions
        # and can see a socket without the correct DACL/group yet.
        if not wait_for_socket(socket_path, bridge_proc, SOCKET_READY_TIMEOUT):
            if bridge_proc.poll() is not None:
                print(
                    f"{YELLOW}Bridge exited with code {bridge_proc.returncode} "
                    f"(sudo credentials may have expired, or a restrictive sudoers "
                    f"env_check/env_delete rejected --preserve-env){RESET}"
                )
            else:
                print(f"{YELLOW}Bridge did not bind socket within {SOCKET_READY_TIMEOUT}s{RESET}")
            sys.exit(1)

        # Start Vite (after the bridge). GUI needs it listening before the
        # webview opens. stdin=DEVNULL prevents child processes from accessing
        # the parent console's stdin. Without this, Vite (via readline) puts the
        # TTY into raw mode for keyboard shortcuts and doesn't restore it when
        # terminated, leaving arrow keys broken.
        vite_proc = subprocess.Popen(
            [npm, "run", "dev"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            **new_process_group_kwargs(),
        )
        procs.append(vite_proc)
        # Vite's output has no ISO timestamps; per-line emit avoids the
        # buffer-never-flushes failure mode (see prefix_stream docstring).
        t_vite = threading.Thread(
            target=prefix_stream,
            args=(vite_proc.stdout, "  vite", YELLOW, print_lock),
            kwargs={"buffer_entries": False},
            daemon=True,
        )
        t_vite.start()
        prefix_threads.append(t_vite)
        threading.Thread(target=wait_for_exit, args=(vite_proc, done), daemon=True).start()

        if not wait_for_port(VITE_PORT, VITE_READY_TIMEOUT, vite_proc):
            if vite_proc.poll() is not None:
                print(f"{YELLOW}Vite exited with code {vite_proc.returncode}{RESET}")
            else:
                print(f"{YELLOW}Vite did not start on port {VITE_PORT} within {VITE_READY_TIMEOUT}s{RESET}")
            sys.exit(1)  # finally block handles shutdown

        # Start GUI (as the invoking user).
        gui_env = {**os.environ, "HOLE_BRIDGE_SOCKET": str(socket_path)}

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
            **new_process_group_kwargs(),
        )
        procs.append(gui_proc)
        # GUI also emits ISO-timestamped tracing entries.
        t_client = threading.Thread(
            target=prefix_stream,
            args=(gui_proc.stdout, "client", MAGENTA, print_lock),
            kwargs={"buffer_entries": True},
            daemon=True,
        )
        t_client.start()
        prefix_threads.append(t_client)
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
        shutdown(procs, prefix_threads, bridge_proc=bridge_proc)


if __name__ == "__main__":
    main()
