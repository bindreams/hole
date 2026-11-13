# Bridge and proxy commands

The `hole` binary has subcommands beyond the ones a user needs, for running the {term}`bridge` by hand, installing it,
and driving a running one from a shell. The commands a user needs (`upgrade`, `path`, `bridge unlock`) are on the
[command line reference](../reference/cli.md). `hole --help` and `hole <command> --help` list the options of every
command below; the definitions are in {src}`crates/hole/src/cli.rs`.

## `hole bridge`

| Command                                                      | What it does                                                                                             |
| ------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------- |
| `hole bridge run`                                            | Runs the bridge in the foreground. It creates the TUN device and the routes, so run it elevated.         |
| `hole bridge run --service`                                  | Runs the bridge as a service. The service installer passes this; the SCM or launchd starts it.           |
| `hole bridge install`                                        | Installs and starts the bridge service.                                                                  |
| `hole bridge enable`                                         | Sets the service to start automatically and starts it. Needs elevation.                                  |
| `hole bridge uninstall`                                      | Stops and removes the service.                                                                           |
| `hole bridge status`                                         | Prints whether the bridge is installed and running.                                                      |
| `hole bridge log [path \| watch [--tail N]]`                 | With no argument, prints the bridge log; `path` prints where it is; `watch` streams it, after `N` lines. |
| `hole bridge grant-access`                                   | Creates the `hole` group and adds the current user to it. Needs elevation.                               |
| `hole bridge ipc-send (--base64 B64 \| --request-file PATH)` | Sends one IPC request to the bridge. Needs elevation.                                                    |

Options of `bridge run`:

- `--socket-path`, `--log-dir`, `--state-dir` override the default locations. The folder of a `--socket-path` gets the
  same link walk as the default folder, and nothing more: Hole does not require the bridge to own it, and whoever passes
  it vouches for it. The safety work is on the default path of a production install.
- `--plugin-dir DIR` runs the plugins found in `DIR` instead of the ones beside the executable. The bridge reads the
  folder and never writes it. It cannot be combined with `--service`. On macOS the folder must carry a current
  `layout.json` stamp, which says it is a Hole plugin folder but not who can write it, so name only a folder that only
  root can write, such as `/Library/Application Support/Hole`.
- `--ready-notify HOST:PORT/TOKEN` connects to that address and echoes the token once the IPC socket is bound and its
  permissions are applied. The dev supervisor uses it; it is not for the service.

`bridge install`, `enable`, `uninstall` and `grant-access` take `--log-dir`, and so does `bridge log`. `bridge grant-access` can send an IPC request afterwards (`--then-send`, `--then-send-file`).
The GUI's elevated paths run these commands, and pass `--result-file` to `grant-access` and `ipc-send` to read the outcome
back across stripped stdio.

The GUI reads the bridge's socket from the `HOLE_BRIDGE_SOCKET` environment variable when it is set, which is how a dev
app finds a dev bridge ([Development](development.md)).

```{dropdown} Internal subcommands
`hole bridge cutover --payload DIR --target-version V` swaps the staged binaries during an update and restarts the
service. On Windows the bridge starts it, detached, as LocalSystem, because a service cannot restart itself through the
SCM.

`hole bridge release-covers` is hidden. The MSI's uninstall runs it: it releases every fail-closed cover and records the
kill switch as off. It is wider than `unlock`, since it also clears a transient cover that no later bridge start is left
to sweep, and like `unlock` it refuses while a bridge is alive. `hole bridge uninstall --keep-covers` is hidden for the
MSI's major-upgrade path: it removes the service but leaves every cover engaged. `hole bridge unlock` is the command for
recovery.
```

## `hole proxy`

These wrap the IPC requests the app sends, and read a `ServerEntry` (`server`, `server_port`, `method`, `password`, and
optionally `plugin` and `plugin_opts`) from a JSON file. They are for reproducing a bug: write a config by hand and drive
the running bridge from a shell without the GUI.

| Command                                     | What it does                                               |
| ------------------------------------------- | ---------------------------------------------------------- |
| `hole proxy start --config-file PATH`       | Starts the proxy with the server in the file.              |
| `hole proxy stop`                           | Stops the proxy.                                           |
| `hole proxy test-server --config-file PATH` | Runs one connectivity test against the server in the file. |

Options of `proxy start`:

- `--tunnel-mode full` (the default) installs the TUN device and the split routes, and needs elevation.
  `--tunnel-mode socks-only` binds only the SOCKS5 listener and does no routing work, so it needs no elevation, and
  clients must be configured to use it.
- `--local-port` and `--local-port-http` set the listener ports. They must differ when both listeners are enabled.
- `--http` enables the HTTP CONNECT listener, which is off by default and TCP-only.
- `--no-socks5` disables the SOCKS5 listener. With `--tunnel-mode full` it requires `--http` to be off too: that is a
  pure-VPN start, where the TUN data path uses an internal SOCKS5 listener on a port the OS picks, and nothing listens on
  `--local-port`.
