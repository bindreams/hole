# The app process

The app is the `hole` binary run with no arguments: a Tauri program with a tray icon, a settings and dashboard window,
and the config file. It runs with the user's rights and does nothing to the network itself; it asks the {term}`bridge`
to. This page covers the four contracts that decide how the app behaves as a process: what runs at build time and what
at run time, how a second launch is handled, how the tray menu is rebuilt, and how the app and the bridge keep to one
version. The [architecture overview](overview.md#two-modes-one-binary) says how the two modes share a binary.

## Node is a build tool

The front end in `ui/` is HTML, CSS and TypeScript. **In a release build, Node.js runs only at build time**: Vite bundles the front end
and `tsc` checks it ({src}`package.json`). `crates/hole/tauri.conf.json` points `frontendDist` at `ui/dist`, so the bundle is
built before the Rust binary and embedded in it. A shipped app has no Node process: Tauri draws the window with the
operating system's web view (WebView2 on Windows), and the app's own code behind the window is Rust. A development run
is the exception: `beforeDevCommand` starts Vite's dev server and the window loads `devUrl` from it
([development](../development.md)).

## One instance per session

The app is single-instance through `tauri-plugin-single-instance`, keyed on the `com.hole.app` identifier. A second
launch forwards its argv and working directory to the running instance and exits. The running instance's callback
(in `launch_gui`, {src}`crates/hole/src/main.rs`) reveals the dashboard, unless the forwarded argv asks for no dashboard,
which is how a login-autostart entry that lands on a running instance stays quiet. The callback runs on a thread the
plugin owns, so UI work goes through `AppHandle::run_on_main_thread`.

The scope of the lock differs by platform, because the plugin implements it differently:

| Platform | Lock                                                          | Scope                                                            |
| -------- | ------------------------------------------------------------- | ---------------------------------------------------------------- |
| Windows  | a named mutex from `CreateMutexW`, without a `Global\` prefix | per session: each RDP or fast-user-switch user has their own app |
| macOS    | an AF_UNIX listener under `/tmp`, named from the identifier   | machine-wide                                                     |

Two things follow from where the plugin is registered.

- It is registered **inside `launch_gui`**, as the first plugin, so a duplicate launch exits before any other plugin does
  startup work. Every command-line subcommand goes to `cli::dispatch` instead and never reaches it: `hole bridge status`
  runs beside a running app.
- A process that must take over from a running app cannot just start: it would lose the lock to the old one and
  forward-and-exit. [The version handoff](#the-bridge-and-the-app-agree-on-a-version) below does the take-over with an
  explicit exit-wait.

On macOS a click on the dock icon of a running app launches no new process, so single-instance never fires; the app
handles the `Reopen` run event instead and reveals the dashboard.

## The tray menu has one commit point

Every tray menu update goes through `tray::rebuild_tray_menu` ({src}`crates/hole/src/tray.rs`), which dispatches the whole
rebuild to the main thread, **reading the state it renders there too**. `run_on_main_thread` runs inline when the caller
is already on the main thread. The reason is ordering: a worker thread that read the state early and committed the menu
later through the event-loop queue could overwrite a newer menu with a stale one. The tray *icon* is committed inside the
same closure for the same reason.

{src}`clippy.toml` enforces it. `TrayIcon::set_menu` is disallowed, and the one commit inside `rebuild_tray_menu` carries
a per-site `#[allow]`. The icon is set through `set_icon_with_as_template(icon, true)`, because on macOS plain `set_icon`
resets the template flag and the alpha-only icon renders solid black; `set_icon` and `set_icon_as_template` are
disallowed for that reason.

A corollary: `sync_autostart_state` must run on the main thread. The menu-item setters dispatch to the main thread and
block when called from any other, so calling it from a worker thread while holding a lock deadlocks the app.

### What the menu renders from

The menu renders the runtime truth, never persisted config:

- **Running state** comes from `ProxyStateCell`, the app's single view of whether the proxy is running
  ({src}`crates/hole/src/state.rs`). `BridgeLink::send` commits what an exchange with the bridge reveals into it while it
  still holds the client lock, so the cell cannot lag the exchange that produced it.
- **Direction**, Connecting or Disconnecting, comes from the in-flight `TransitionSlot`. It admits one transition at a
  time, so a Cancel is never overtaken by a second Start queued behind the bridge lock.
- Status and connect text are baked into the menu when it is built.

Persisted `config.enabled` records the last intent the bridge honoured, and `tray::persist_intended_enabled` is its only
writer. The tray never renders from it, so a relaunch cannot show "Connected" over no tunnel. The decision to connect at
launch is not the app's: the bridge makes it at its own boot, when `target::resolve_startup_target`
({src}`crates/bridge/src/target.rs`), called from the reconciler, turns the startup preference the app pushed into the
target the bridge reconciles toward.

## The bridge and the app agree on a version

The app and the bridge must never *operate* as a pair of different versions. The two modes are one binary, and the IPC
contract has no version negotiation.

1. **The bridge stamps its build version on every response**, in the `X-Hole-Bridge-Version` header (`build_router` in
   {src}`crates/bridge/src/ipc.rs`), and serves it at `GET /v1/version`. The value is `hole::version::VERSION`, which the `hole` crate
   reads from the `HOLE_VERSION` build-time variable and passes into the bridge's entry point
   ({src}`crates/hole/src/cli.rs`), down to `IpcServer::bind_with_log_dir`.

1. **The client compares** that header with its own version on every exchange and returns `ClientError::VersionMismatch`.
   A missing header, from a bridge that predates the stamp, counts as a mismatch. The pooled connection is kept: a
   reconnect cannot fix a version skew.

1. **`BridgeLink` calls a self-heal hook** ({src}`crates/hole/src/selfheal.rs`). The pure policy `decide` compares the
   image the app started from with the file at the same path now, using file identity (`same_file`), not the path:

   | Observed                                          | Action                                               |
   | ------------------------------------------------- | ---------------------------------------------------- |
   | Versions match                                    | `Operate`                                            |
   | The file at the path changed since startup        | `Relaunch`: an update replaced the image             |
   | The file is the one running, bridge still differs | `Reinstall`: show a dialog that carries no path      |
   | The file is absent                                | `Transient`: the swap is mid-flight, try again later |

The relaunch ({src}`crates/hole/src/relaunch.rs`) is an exit-wait handoff: the old app spawns the new image with
`HOLE_AWAIT_EXIT_PID` set and blocks on a `READY` line. The successor reads the old process's identity while that process
is provably alive, prints `READY`, and waits for it to exit. Only then does it launch normally, which wins the
single-instance lock. Reading the identity before `READY`, plus the start token inside it, is what closes the window in
which a process id could be reused. `relaunch.rs` carries no `#[cfg]`, and the policy and wiring are table-tested.

Self-heal is **inert** until an update produces a mismatch, and off for development and snapshot builds, which are built
in lockstep. The swap that produces the mismatch is [the update cutover](update-cutover.md).

## Where to read next

- [The seams](test-isolation.md) and [cancellation](cancellation.md): the contracts the bridge half keeps.
- [Logging and diagnostics](logging.md): where the app writes `gui.log`.
