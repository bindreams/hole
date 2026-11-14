# Logging and diagnostics

Hole's logs are what a developer or a user's bug report has to work with, and they are written by a process that is
sometimes privileged and by dependencies nobody on the team controls. The server address and the password have their
own rules: see [server-address redaction](redaction.md).

## Where the logs go

The app and the {term}`bridge` each write to stderr **and** to a size-rotated file. The setup is
`init_dual` in {src}`crates/common/src/logging.rs`; the app calls it from {src}`crates/hole/src/logging.rs` (`gui.log`)
and the bridge from {src}`crates/bridge/src/logging.rs` (`bridge.log`). A command-line subcommand that logs writes
`gui-cli.log` in the same place.

| Who                              | Directory                                                                                                                                               |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The app, or a bridge run by hand | `dirs::state_dir()/hole/logs`, else the local data directory: `%LOCALAPPDATA%\hole\logs` on Windows, `~/Library/Application Support/hole/logs` on macOS |
| The installed service            | `service_log_dir` in {src}`crates/common/src/update_marker.rs`: `%ProgramData%\hole\logs` on Windows, `/var/log/hole` on macOS                          |

`HOLE_LOG_DIR` overrides the directory for the app and for a bridge run by hand, with one exception: a bridge run by hand
and **elevated on macOS** logs to the invoking user's directory, which beats `HOLE_LOG_DIR`, and only `--log-dir` beats
that. `hole bridge log` reads the installed service's directory by
default; point it at a foreground or development bridge with `--log-dir` or `HOLE_LOG_DIR` (see [the bridge
commands](../bridge-cli.md)).

**Rotation.** The active file holds up to `MAX_LOG_BYTES`, then is renamed over `<name>.1`, the one backup. If
`<name>.1` cannot take the rename (a directory at that name, or a handle without delete sharing on it), the full file
goes to `<name>.1.fallback`, replacing the one before it, and the fallback is removed the next time `<name>.1` can take
a rotation. When neither name can, no line is lost: the active file keeps being appended past the limit until a rotation
succeeds. Only a file that cannot be opened loses lines, and it says so once, on the real stderr.

**The directory is the user's.** When the bridge runs elevated on a user's behalf, its log directory sits in the user's
profile, so `init_dual` opens it once as a `util::dir::Dir` (a link is followed only under [the ownership-transition
rule](privileged-folders.md#the-ownership-transition-rule), the final name never; created if missing, handed to the
user). `DirRotate` ({src}`crates/common/src/logging/dir_rotate.rs`) does the open, the rotation rename and the `chown` of
each fresh file, and `init_dual` removes the files of the old daily-rotation scheme, each by a single name inside that
handle. A path-based rotator would follow
whatever the user swapped in for a component of the path, as root. A directory the walk refuses disables the file sink,
with one line on the real stderr that carries no path; the bridge keeps running.

**Blocking behaviour.** The file writer is non-blocking and **not lossy**: the burst of lines at the end of a teardown
must reach the disk, at the price that a stalled disk blocks the threads that log. The writer's buffer
(`buffered_lines_limit`, tracing-appender's default) only delays when that starts: once it is full, every thread that
emits an event, the panic hook's included, waits with no limit until the disk drains. The stderr writer and the two stdio tees are lossy, so a wedged terminal can never block the
bridge or the panic hook.

## Turning the volume up

Each sink builds its own filter: a global default of `info`, then `RUST_LOG`, then the sink's directives, then a pin of
`hole::logging=debug` so the logging subsystem reports its own lifecycle. A directive later in the list overrides an
earlier one of the same specificity. The global `info` is deliberate: a dependency's start-up and warning lines are often
the diagnosis.

| Variable          | What it sets                                                                                                |
| ----------------- | ----------------------------------------------------------------------------------------------------------- |
| `HOLE_BRIDGE_LOG` | The bridge's **file** directives, a comma-separated list. Beats `HOLE_LOG`. Default `hole_bridge=info`.     |
| `HOLE_LOG`        | The file directives for the app (default `hole=info`) and, when `HOLE_BRIDGE_LOG` is unset, for the bridge. |
| `HOLE_LOG_STDERR` | The stderr directives. Unset, stderr mirrors the file sink.                                                 |
| `HOLE_LOG_DIR`    | The log directory (not honoured by an elevated macOS bridge run by hand, above).                            |
| `RUST_LOG`        | Layered under every sink's directives, so it composes with the variables above.                             |

`HOLE_BRIDGE_LOG=hole_bridge=debug,shadowsocks_service=trace` adds the Shadowsocks server's per-relay byte counts
(`L2R N bytes, R2L M bytes`), which is how a connection that moved no bytes is diagnosed. It writes at least one trace
line per TCP connection, so use it for debugging only, and read the warning on it in [server-address
redaction](redaction.md#limits). `cargo xtask run hole` sets the file sink to `trace` for first-party crates, not
`shadowsocks_service`, and writes the logs of each run to a directory of its own ([Development](../development.md)).

## The stdio safety net

At startup `init_dual` redirects file descriptors 1 and 2 (Windows: the standard handles) to pipes. A reader thread per
pipe tees every line to the original handle, so a terminal still sees it, and emits it as a tracing event, with target
`hole::stdout_relay` or `hole::stderr_relay`, so the file sees it too. The stderr layer drops those two targets, or it
would write each line twice. The net catches whatever bypasses `tracing`: the Go runtime of a plugin, a native library, the
default panic printer. A panic hook emits an error event with a backtrace under `hole::panic` and then calls the previous
hook.

The most visible case is WebView2 on Windows, which writes Chromium-format lines (`[MMDD/HHMMSS.mmm:LEVEL:file:line]`)
straight to the inherited stderr. They land in `gui.log` through the relay. **A Chromium line is a real log record:
investigate its cause rather than filtering it.**

The redirect cannot be switched off in a release build. `HOLE_LOGGING_DISABLE_REDIRECT` is honoured only when
`debug_assertions` is on.

## Logging an error

An error reaches a log as a value, in one form:

```rust
tracing::warn!(error = &e as &dyn std::error::Error, "what failed");
```

- **Boxed and borrowed.** A boxed error (`Box<dyn Error>`, with or without `+ Send + Sync`) and an `anyhow::Error` pass as
  `error = &*b`, and a reference to one as `error = &**b`. When `e` is a reference to a concrete error, cast it without
  the extra `&` (`error = e as &dyn std::error::Error`): `&&T` is not `'static`.
- **The message never interpolates the error** (`{e}`, `%e`, `?e`). The field carries it, and the message would print its
  first link a second time. The message says what failed.
- **The renderer.** `YamlFormat` renders an error field as a YAML list of the error's `Display` and each `source()`
  after it, outermost first, one item per link (a multi-line `Display` stays one item). The stock formatter that
  `galoshes` and `garter-bin` install prints the same field as `error=<Display> error.sources=[..]`, so the call site is
  the same there.
- **The type rule.** A variant's `Display` names what this layer failed to do and never formats its `source()`; a cause
  is `#[source]` or `#[from]`. A `Display` that includes its cause prints it twice. A wrapper variant exposes its inner
  error as its `source()` and is not `#[error(transparent)]`, which forwards `source()` past the inner value so `find`
  and `raw_os_error` cannot reach it. A new wrapper is `#[error("<what failed>")] V(#[source] Inner)` (or `#[from]`). The
  existing `#[error("{0}")]` wrappers are a transitional exception: a logged chain shows their inner text twice until
  they get text of their own. `ProxyError::PluginResolve` is `transparent` too.
- **Reading a chain in code.** Use `util::error` ({src}`crates/util/src/error.rs`: `chain`, `links`, `find`,
  `raw_os_error`) and do not write a `source()` loop by hand. The module doc says what the walks reach.
- **A value that is not an error stays as it is.** A third-party type with no `std::error::Error` impl, and a `String` made
  from an error, are logged as they are. Text a user reads (a dialog, a toast) is written from `user_message()` or the
  type's `Display`, never from the log field.

## What reaches a toast

The front end's `console.error` and `console.warn` are intercepted by `installConsoleRelay()` in {src}`ui/main.ts` and
forwarded through `@tauri-apps/plugin-log` into `gui.log`. The relay only logs; it never shows a toast, so a tight loop
cannot flood the window. A user-visible failure is shown with `showToast(message, kind)` from {src}`ui/toast.ts`, which
caps how many toasts are visible.

**An error that carries a filesystem path or other PII must be redacted before it reaches a toast.** The detail still
goes to `gui.log`. Three mechanisms are sanctioned:

1. **A content-free error type, plus a `warn!` that names the path.** `ConfigError`
   ({src}`crates/common/src/config.rs`) carries the failing operation and the OS error, never the path, and its `Parse`
   variant carries only a category and a line and column. `save_config` ({src}`crates/hole/src/commands.rs`) logs the
   path with `warn!` and puts the path-free message in the toast.
1. **A detail-free wire variant, plus a `warn!`**, when the detail itself could carry content: `import_file`
   ({src}`crates/hole/src/commands.rs`) returns `ImportFailure::SaveFailed` or `CorruptedJson` (no fields) and logs the
   full error.
1. **The redaction registry**, for the configured server address, which no per-site rule can cover.

## Plugin diagnostics

The plugin process ({term}`ex-ray`, {term}`galoshes`) is otherwise invisible. Its stdout and stderr lines are relayed
into the bridge's log as tracing events from `garter::binary`, so the usual directives apply to them. Two more tools:

- **The plugin tap.** `garter::TapPlugin` ({src}`crates/garter/src/tap.rs`) puts an instrumented loopback hop in front of
  the plugin and logs, per connection, `bytes_to_plugin`, `bytes_from_plugin`, `ttfb_ms` (`None` means the connection closed
  without an upstream byte), `close_kind` and `tap_conn_id`. It is switched on by the `diagnostic_plugin_tap` field of
  `AppConfig`, which reaches a bridge running as a service, or by `HOLE_BRIDGE_PLUGIN_TAP` in a development shell, where
  environment variables do not survive into the service manager. It costs a loopback round trip per byte and a line per
  connection, so it is not for default use under load. A failed DNS self-test logs a hint that points at the tap lines
  when the tap is on, and says how to turn it on when it is off.
- **Directive injection.** For a plugin whose `PluginDescriptor::takes_hole_directives` is set (all three shipped names
  today), `inject_plugin_directives` appends `loglevel=debug` and, when a resolver is configured, `ech-doh=<DoH URL>` to
  `SS_PLUGIN_OPTIONS`. Any other plugin has its options validated and passed through untouched. An operator's own
  `loglevel` is always replaced. Their `ech-doh` is replaced only when Hole's value outranks it
  (`hole_ech_doh_outranks`: Hole's resolver answered the bootstrap, or the operator's value names its server by name
  rather than by IP address); otherwise it stands, and Hole's appended copy loses to it, because ex-ray reads the first
  value of a repeated key. `derive_ech_doh` derives the URL, and the [kill-switch cover](kill-switch.md)'s resolver permit reads the same
  field. Hole never injects `ech=<mode>`: ex-ray owns the mode.

## Where to read next

- [Server-address redaction](redaction.md): why a log line never holds the server's address.
- [The galoshes transport](galoshes-transport.md): the plugin side of the diagnostics.
