# Development

This page runs Hole from your checkout. Dev mode creates a real TUN device and edits the machine's routing table, exactly
as a release does, so the {term}`bridge` needs administrator rights. You start dev mode without them: only the bridge is
elevated.

## Run dev mode

`````{tab-set}
---
sync-group: os
---
````{tab-item} Windows
:sync: windows

From an **elevated** PowerShell. Every process inherits the elevated token.

```powershell
cargo xtask run hole
```
````

````{tab-item} macOS
:sync: macos

As yourself, with no `sudo`. It asks for your password once and uses `sudo` for the bridge only.

```sh
cargo xtask run hole
```
````
`````

```{warning}
Do not run `sudo cargo xtask run hole`. The supervisor refuses to run as root, but the build that `cargo xtask` runs
first has already left root-owned files in `target/` by then.
```

`cargo xtask run hole` builds everything (the `hole` target in [Building in detail](build.md)), then starts the
`dev-console` supervisor. The supervisor builds nothing. It does this, in order:

1. Runs `npm install`, every time, so a dependency added by a pulled commit is never missed.
1. Stages the build into a per-process directory, `hole-dev-<pid>` under the temp directory. On Windows the running
   bridge locks its own executable, and this copy lets you rebuild while it runs.
1. Refuses to continue if Vite's port (`VITE_PORT` in {src}`crates/dev-console/src/banner.rs`) is already taken, which usually means an earlier run's Vite is still alive.
1. Runs `hole bridge grant-access`, the production code path that creates the `hole` group and adds your user to it, so
   dev mode exercises the same access rules as an install. The group stays after you exit, as it does in production.
1. Starts the bridge elevated, then Vite, then the app, with their logs multiplexed and colour-coded in one terminal.
   The bridge listens on `hole-dev.sock` in the temp directory, and the app is pointed at it with `HOLE_BRIDGE_SOCKET`.

The bridge is started with `--ready-notify`: the supervisor opens a local TCP listener and the bridge connects and
echoes a token once its IPC socket is bound and its permissions are applied. Vite and the app start only after that.

Every run also writes its logs to `.tmp/dev-run/<date>_<time>/`: `bridge.log` and `gui.log` at trace level, and
`dev-console.log` with the supervisor's own output.

Front-end changes reload through Vite. A Rust change needs Ctrl+C and a new `cargo xtask run hole`. The session also ends
when any of the three processes exits.

### Stopping

Ctrl+C asks the bridge to stop gracefully, so it can put the routes and DNS back before it exits. On macOS that is a
`SIGTERM` that `sudo` relays; on Windows the supervisor signals the bridge's process tree. The supervisor waits for
`GRACE_TIMEOUT` ({src}`crates/dev-console/src/supervise.rs`) and then, on Windows, kills the tree. On macOS it does
not: killing through `sudo` would kill `sudo` and leave the root-owned bridge running with its routes in place. It prints
a pointer to {src}`scripts/network-reset.py` instead.

### The first run on macOS

The app needs membership of the `hole` group to open the bridge's socket. The first `grant-access` creates the group, and
your login session does not see it yet. The supervisor checks this on macOS, says so and exits; log out and back in (or
reboot), then run it again. This happens once per machine.

## Run the pieces yourself

Separate terminals give you more control. Terminal 1 is the bridge. On macOS, build and stage as your normal user; only
`bridge grant-access` and `bridge run` need `sudo`. On Windows, one elevated PowerShell does all of it.

`````{tab-set}
---
sync-group: os
---
````{tab-item} Windows
:sync: windows

From an elevated PowerShell, which also builds and stages.

```powershell
cargo xtask build hole
cargo xtask stage --profile debug --out-dir "$env:TEMP\hole-dev-manual"
& "$env:TEMP\hole-dev-manual\hole.exe" bridge grant-access
& "$env:TEMP\hole-dev-manual\hole.exe" bridge run `
    --socket-path "$env:TEMP\hole-dev.sock" --state-dir "$env:TEMP\hole-dev-state"
```
````

````{tab-item} macOS
:sync: macos

As yourself; `sudo` only the two bridge commands.

```sh
cargo xtask build hole
cargo xtask stage --profile debug --out-dir "$TMPDIR/hole-dev-manual"
sudo "$TMPDIR/hole-dev-manual/hole" bridge grant-access
sudo "$TMPDIR/hole-dev-manual/hole" bridge run \
    --socket-path "$TMPDIR/hole-dev.sock" --state-dir "$TMPDIR/hole-dev-state"
```
````
`````

Terminal 2 is Vite and the app, unelevated:

`````{tab-set}
---
sync-group: os
---
````{tab-item} Windows
:sync: windows

```powershell
npm run dev                                       # Vite
$env:HOLE_BRIDGE_SOCKET = "$env:TEMP\hole-dev.sock"; target\debug\hole.exe
```
````

````{tab-item} macOS
:sync: macos

```sh
npm run dev &                                     # Vite
HOLE_BRIDGE_SOCKET=$TMPDIR/hole-dev.sock target/debug/hole
```
````
`````

The bridge's options are listed under [Bridge and proxy commands](bridge-cli.md).

## Coding rules

- **Remove a hazard rather than guard it.** If a function has a precondition no test can enforce, change the code so
  the precondition cannot be broken. `CoverGuard::disarm` closes the handle it holds instead of leaking it, so it needs
  no "call only before the process exits" rule: nothing is left to police.

## Things that catch people

- **A dev run and an installed Hole share one identity.** The dev app uses the same application id, `com.hole.app`, as
  the installed one. If an installed Hole is running, the single-instance guard forwards your launch to it and the dev
  window never appears. Quit the installed Hole first.
- **Use an absolute, short path for `--socket-path`.** Windows limits the length of an AF_UNIX socket path.
- **If a crashed dev run breaks your network,** run {src}`scripts/network-reset.py` from an elevated shell: `sudo python3 scripts/network-reset.py` on macOS, `python scripts/network-reset.py` in an elevated PowerShell on Windows. [Route
  ownership](architecture/route-ownership.md#the-escape) says what it removes.
- **The first `cargo xtask deps` is slow.** It compiles ex-ray and downloads `wintun.dll`; later runs reuse Go's build
  cache and the verified download.
