# The installers

Hole ships as a Windows MSI and a macOS DMG. The end-to-end runs that install them change the machine they run on, so
read the warnings before you run one.

## Windows installer

The installer is a WiX project in {src}`msi-installer/`, driven from Python. It installs Hole system-wide, registers the
`HoleBridge` service to run as LocalSystem, and adds `hole` to the system `PATH`.

```sh
cargo xtask build hole-msi                          # release build, slow; writes target\release\hole.msi
cd msi-installer && uv run --group dev pytest -v    # checks of the WiX source and of the built MSI
msiexec /i target\release\hole.msi /quiet           # install (drop /quiet for the wizard)
```

`hole-msi` builds the front end first, because a release build embeds `ui/dist/` (see [Building in
detail](build.md#the-front-end-toggle)).

### Who stops the running service

With Hole running, Windows Installer's uninstall dialog lists the app and the `HoleBridge` service, and its default
closes both. If the person declines, the `BridgeUninstall` action (`hole bridge uninstall`, before `RemoveFiles`) stops
the service anyway and the uninstall completes with the app left running.

### The install, E2E and uninstall run

CI's installer lane installs the MSI, drives the installed app through WebDriver, uninstalls it and checks nothing is
left. It also upgrades over a second MSI linked from the same staged files. Both uninstall paths meet a running
`HoleBridge` service, so the harness passes `MSIRESTARTMANAGERCONTROL=Disable` (under `/quiet`, Restart Manager would
otherwise stop the service first); for the upgrade's nested removal it writes the property into the second MSI itself,
because the removal ignores the outer command line. The proof is a `stop wait: sending Stop` record with a `Running`
look in `C:\ProgramData\hole\logs\gui-cli.log`, gained during the `msiexec` call and, for the upgrade, written by
the old product's uninstall, not the new product's install. The upgrade then uninstalls on the shipped default and
expects Restart Manager to stop the service. The lifecycle runs against any MSI (`MSI_UNDER_TEST`); the upgrade case
also needs the working tree's staged files (`target\release\installer-stage`, from `cargo xtask build hole-msi`) and an MSI
under test whose version is not lower than the tree's.

Between the two, the lane installs once more and connects ({src}`msi-installer/tests/installed/test_connect.py`): the
installed `hole.exe` asks the `HoleBridge` service the MSI registered to start a SOCKS-only proxy for a server behind
`galoshes`, one behind `v2ray-plugin` and one with no plugin, and `curl` fetches a page through each. This is the
only test in which the service the service manager started runs a plugin; the bridge's own end-to-end tests start it
as a child of the test. A failure prints what `C:\ProgramData\hole\logs\bridge.log` gained during the case. It runs
against any MSI too, a published release included. The server is the `ss_plugin_server` example of
{src}`crates/plugin-e2e/`, with the working tree's `galoshes` and `ex-ray` builds on its side, so the plugins of the
MSI under test must still speak to the tree's.

A third install connects as the user the installer granted
({src}`msi-installer/tests/installed/test_member_access.py`). Every other case reaches the bridge from the elevated
test process, which the socket's Administrators entry admits whatever the bridge granted anyone else. This one runs the
installed `hole.exe` from a child that `gsudo` de-elevated, whose token was made before the install and so carries no
`hole` group. It connects to the server with no plugin, restarts the `HoleBridge` service, connects again, and does
both once more. A second test takes the user out of the group, restarts the service, checks that the user is now
refused, runs an elevated `hole bridge grant-access` and connects with no further restart. Each fails before its first
connect when the child still holds Administrators, already carries the group,
or is not the user the installer added. The child cannot read pytest's own temporary folder, so its files are in
`member-access\` under the log folder. A failure also says how the child's own connect to the bridge's socket went:
`hole` can exit before its own error text reaches a pipe.

A fourth install starts a full tunnel, the default of `hole proxy start`, as that same user
({src}`msi-installer/tests/installed/test_full_tunnel.py`), once for a server behind each bundled plugin and once for a
server with no plugin. The server runs on the test machine, so it dials out of the machine's default interface instead of
the routing table, which the tunnel now owns; that is the one thing the example is told. `curl`, run by the de-elevated
child, requests `http://1.1.1.1/` and, over IPv4, `http://one.one.one.one/`, and each must answer `301` with a
`Location` for the host the request named. The case then asks the operating system for the IPv4 DNS servers of each adapter (`Get-DnsClientServerAddress`)
and fails when none is new while the tunnel is up. After `hole proxy stop` the machine's routes, adapters, addresses and
DNS settings must equal those taken before the start. The case needs the internet, and the machine's routes and DNS
belong to the tunnel for a few seconds.

```{warning}
This installs Hole system-wide on the machine you run it on. Use a throwaway machine or virtual machine, not the one you
work on.
```

```sh
# from an ELEVATED terminal
cargo xtask run hole-msi-install-tests    # MSI_UNDER_TEST=<path\to\hole.msi> tests a different MSI
cargo xtask run hole-msi-cleanup          # after an interrupted run
```

It needs the MSI built beforehand (`cargo xtask build hole-msi`, or the one `MSI_UNDER_TEST` names), the repo's
`node_modules`, and for the connect, member-access and full-tunnel cases `cargo build -p plugin-e2e --example ss_plugin_server` plus
the `galoshes` and `ex-ray` builds `hole-msi` leaves (`cargo xtask build galoshes` alone builds both). The target builds none of these, so
run `cargo xtask build frontend-build` once if `hole-msi` has not left `node_modules`. The run refuses to start, before
it changes anything, when:

- the shell is not elevated, or there is no MSI at `target\release\hole.msi` (or at the path `MSI_UNDER_TEST` names);
- a Hole MSI product is registered, the `HoleBridge` service exists, `C:\Program Files\hole` exists (even empty), its
  `bin` folder is in the machine `PATH`, or any `hole.exe` is running. It names what it found and kills nothing: a
  development build shares the single-instance id and the bridge socket with the installed one, so the E2E would drive
  the wrong process.

Before installing, it records the MSI's ProductCode in `target\.hole-installed-by-the-msi-test-harness`. The cleanup
uninstalls, by that ProductCode, only a Hole this harness installed, and reports any other it finds. The upgrade case
records both of its ProductCodes, so the cleanup removes whichever of the two an interrupted run left.

The tools the E2E needs (`tauri-driver`, `msedgedriver`, `gsudo`) download into `.cache/installer-e2e/`; nothing is added
to `PATH` outside the test's child processes. Each phase that starts child processes has a failure bound
(`GSUDO_SELFTEST_TIMEOUT_SECONDS`, `DASHBOARD_E2E_TIMEOUT_SECONDS` and, for each `hole` command of the connect,
member-access and full-tunnel cases, `HOLE_CLI_TIMEOUT_SECONDS` in {src}`msi-installer/tests/installed/support.py`), so a wedged phase
fails by name and the uninstall still runs. The server of those cases has none: it is the tree's code, and one that never reports
ready ends at the CI step's limit. Install
and uninstall logs go to `target\msi-test-logs\`, or to `MSI_TEST_LOG_DIR`. Nothing asserts what remains in
`C:\ProgramData\hole` after the uninstall.

In CI the `installer-tests` step runs this target, and `installer-cleanup` (which always runs) runs the cleanup. The
connect case's server is built by its own step, `installer-test-server`, right after the MSI build and before
`hole-build`: `installer-tests` runs after `hole-build`, and no step after that one may compile ([CI](ci.md)). The TUN
test lane runs only once the cleanup passed or no MSI was built.

## macOS installer

The app is built and bundled by Tauri, from the config in {src}`crates/hole/tauri.conf.json`. {src}`dmg-installer/` is the
Python project that wraps the app in the DMG (`dmgbuild`) and holds the tests of the result.

```sh
cargo xtask build hole-dmg       # writes the .dmg
cargo xtask run hole-dmg-tests   # mounts it and checks the payload and the code signature
```

`hole-dmg` runs the steps listed under its target in {src}`build.yaml`: `npx tauri build --no-bundle`, a copy of the
debug symbols, the installer background (`cargo xtask dmg-background`), `npx tauri bundle` to assemble the `.app`, and
`dmgbuild` (through `uv run --directory dmg-installer build`) to wrap it in the styled DMG.

`hole-dmg-tests` attaches the DMG with `hdiutil` and checks the one it finds in the release build, or the one
`DMG_UNDER_TEST` names.

Three things about the payload are checked by `hole-dmg-tests` ({src}`dmg-installer/tests/`):

- **The plugins are not in the app.** `hole` embeds ex-ray and galoshes in itself, and the bridge service copies them
  into a root-owned folder when it starts. The expected file list comes from
  `cargo xtask bindir-names --os darwin --bundle`, not from a copy in the tests.
- **The debug symbols sit next to the binary.** `hole.dSYM` is in `Contents/MacOS`, because the standard library's
  backtrace code finds a `*.dSYM` by scanning the running binary's folder and matching its Mach-O UUID. That UUID is
  fresh on every link, so the symbols and the shipped binary must come from the same one; this is why `hole-dmg`
  builds once and takes the symbols from that build. Cargo's packed debug info leaves `target/release/hole.dSYM` as a
  symlink, which the bundler would ship dangling, so the build copies it dereferenced into `.cache/` first.
- **The build leaves the tree clean.** The Tauri CLI can rewrite tracked files, `crates/hole/Cargo.toml` among them,
  before compiling, which would add `.dirty` to the version baked into the binary. The committed file already has the
  form the CLI writes. The tests fail if a build modifies a tracked file or the binary reports `.dirty`. They need a
  checkout with no uncommitted changes to tracked files, so with local edits `hole-dmg-tests` fails on these two
  checks alone.

### Installing the built app for real

```sh
cargo xtask run hole-dmg-install-e2e
```

installs the built app's bridge as root, connects with `hole proxy start` to a server behind each bundled plugin and to
one with no plugin, fetches a page through each, and uninstalls. It then starts a full tunnel for each of the three and
fetches pages from outside the machine by address and by name, as the Windows lane does; that case runs as root, not as the
installing user. The connections are the same code the Windows lane runs ({src}`tests/installed/connect_journey.py`).
It is meant for CI: it needs passwordless `sudo`, refuses to run over an existing install, and expects `hole-dmg` to
have built the app and `cargo build -p plugin-e2e --example ss_plugin_server` to have built the test's server.
