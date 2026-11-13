# System tools and absolute paths

The {term}`bridge` runs as root or SYSTEM and starts operating-system tools: `route`, `netsh`, `pfctl` and others. It never
names one by a bare program name. This page covers how a spawn is built, what the compiler refuses, and how the same rule
reaches plugins. It is for a developer who needs the bridge to run a new tool.

## Why a bare name is not allowed

A program named without a directory is looked up by something an unprivileged user can influence. On macOS that is `PATH`.
On Windows, `CreateProcess` searches the application's directory and the *current directory* before System32 (see the
`lpApplicationName` section of [`CreateProcessW`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw)).
A bare name run as root would run whatever a lower-privileged user put at the front of that search.

## `SystemTool`

Every OS tool is a variant of `util::system_tool::SystemTool` ({src}`crates/util/src/system_tool.rs`), with one enum per
platform: the macOS tools (`route`, `ifconfig`, `pfctl`, `networksetup` and the rest of that enum) at fixed absolute paths in
SIP-protected locations, and the Windows tools (`route`, `netsh`, `net`, `pnputil`) under the directory `GetSystemDirectoryW`
reports, never an assumed `C:\Windows`. `SystemTool::command()` is the only way to build a `Command` for one, and its program
is always an absolute path.

If the system directory cannot be read, `path()` and `command()` return the error rather than falling back to a bare name,
and the caller carries it as its spawn error (`CommandFailure::Spawn`, or the `io::Error` it already returns). A best-effort
teardown logs it and goes on. `RouteCommand` and `SetupCommand` hold a `SystemTool` plus arguments, not an argv whose first
element is a program name.

On Windows `command()` also sets `CREATE_NO_WINDOW`. The release app and its elevated children have no console, so a console
tool started without the flag would open a visible console window.

### PowerShell

A root PowerShell is deliberately not a `SystemTool` variant. Its module autoload reads `PSModulePath`, whose default begins
with the invoking user's writable `Documents\WindowsPowerShell\Modules`, so a cmdlet resolved from there would run a planted
module as SYSTEM or an administrator. `SystemPowershell::command(script)` is the only constructor, so a PowerShell without
the module pin cannot be written. It sets `PSModulePath` to the system module directory in the child's environment, and
prepends an assignment of the same value to every script. Both are needed: PowerShell rebuilds an inherited value that equals
the machine's, with the user's directory in front, and autoload reads `$env:PSModulePath` as the script left it.

## What the compiler refuses

{src}`clippy.toml` bans the ways to start a process by a bare name: `std::process::Command::new`,
`tokio::process::Command::new`, and every `cosca` command constructor (`Command::new`, `run`, `run_line`, sync and `tokio`).
It also bans the `cosca::Command` methods that name its program (`executable`, `raw_executable`, `arg`, `args`,
`commandline`), because `Command` implements `Default` and a constructor reached that way is one no path can ban.

A spawn that is not an OS tool (Hole's own executable, the unprivileged app's `osascript`, a developer's `sudo`, `xtask`
and `dev-console`, test harnesses) takes an `#[allow(clippy::disallowed_methods)]` with its reason. Test files and tooling
files take a module-level one. Bridge production code never does: an inner `#![allow(clippy::disallowed_methods)]` switches the
process ban off for the whole module, so a spawn there takes an item-level allow. A library the privileged binary must not
call is a `[dev-dependencies]` entry of the bridge and not a `[dependencies]` one; `handle-holders` is one, because it runs
`lsof` by `PATH` on macOS ({src}`crates/bridge/Cargo.toml`). Test and tooling code that runs under `sudo` or an admin shell in
CI is attended and keeps bare names.

## Plugins

The privileged bridge runs only the plugins Hole ships (`hole_common::plugin::KNOWN_PLUGINS`), found in the one folder its
`PluginSource` names, with the same aim by a different mechanism. `PluginSource::resolve`
({src}`crates/bridge/src/proxy/plugin_source.rs`) is the only production producer of a `BundledPlugin`, a shipped plugin's
descriptor bound to the absolute path of its binary, and `start_plugin_chain` accepts only that. A bare name for
`garter::BinaryPlugin` to look up on `PATH` cannot be written on the bridge's path. A test stages an install with
`PluginSource::build_dir`.

`resolve` is the one gate for "may this plugin run". It is asked first in `start_cancellable` and `run_server_test`, before any
DoH bootstrap, cover or dial: an unbundled name or a missing binary is refused with nothing touched, and reaches the user as
the usual start error. Import already rejects such plugins, so only a hand-edited or old config, or a direct IPC call, gets
here. Third-party SIP003 plugins are not supported.
