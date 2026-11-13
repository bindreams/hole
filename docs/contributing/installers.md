# The installers

Hole ships as a Windows MSI and a macOS DMG. This page covers building each, checking what they contain, and the
end-to-end runs that install them for real. The runs change the machine they run on, so read the warnings before you run
one.

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

### The install, E2E and uninstall run

CI's installer lane installs the MSI, drives the installed app through WebDriver, uninstalls it and checks nothing is
left. The same run works locally, against any MSI:

```{warning}
This installs Hole system-wide on the machine you run it on. Use a throwaway machine or virtual machine, not the one you
work on.
```

```sh
# from an ELEVATED terminal
cargo xtask run hole-msi-install-tests    # MSI_UNDER_TEST=<path\to\hole.msi> tests a different MSI
cargo xtask run hole-msi-cleanup          # after an interrupted run
```

It needs the MSI built beforehand (`cargo xtask build hole-msi`, or the one `MSI_UNDER_TEST` names) and the repo's
`node_modules`; the target builds neither, so run `cargo xtask build frontend-build` once if `hole-msi` has not left
them. The run refuses to start, before it changes anything, when:

- the shell is not elevated, or there is no MSI at `target\release\hole.msi` (or at the path `MSI_UNDER_TEST` names);
- a Hole MSI product is registered, the `HoleBridge` service exists, `C:\Program Files\hole` exists (even empty), its
  `bin` folder is in the machine `PATH`, or any `hole.exe` is running. It names what it found and kills nothing: a
  development build shares the single-instance id and the bridge socket with the installed one, so the E2E would drive
  the wrong process.

Before installing, it records the MSI's ProductCode in `target\.hole-installed-by-the-msi-test-harness`. The cleanup
uninstalls, by that ProductCode, only a Hole this harness installed, and reports any other it finds.

The tools the E2E needs (`tauri-driver`, `msedgedriver`, `gsudo`) download into `.cache/installer-e2e/`; nothing is added
to `PATH` outside the test's child processes. Each phase that starts child processes has a failure bound
(`GSUDO_SELFTEST_TIMEOUT_SECONDS` and `DASHBOARD_E2E_TIMEOUT_SECONDS` in
{src}`msi-installer/tests/installed/support.py`), so a wedged phase fails by name and the uninstall still runs. Install
and uninstall logs go to `target\msi-test-logs\`, or to `MSI_TEST_LOG_DIR`. Nothing asserts what remains in
`C:\ProgramData\hole` after the uninstall.

In CI the `installer-tests` step runs this target, and `installer-cleanup` (which always runs) runs the cleanup. The TUN
test lane runs only once the cleanup passed or no MSI was built.

## macOS installer

The DMG is built from a Tauri app bundle in {src}`dmg-installer/`.

```sh
cargo xtask build hole-dmg       # writes the .dmg
cargo xtask run hole-dmg-tests   # mounts it and checks the payload and the code signature
```

`hole-dmg` runs the steps listed under its target in {src}`build.yaml`: a Tauri build without bundling, a copy of the
debug symbols, the installer background (`cargo xtask dmg-background`), `tauri bundle` to assemble the `.app`, and
`dmgbuild` to wrap it in the styled DMG.

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

installs the built app's bridge as root, connects through each bundled plugin with `hole proxy start`, and uninstalls.
It is meant for CI: it needs passwordless `sudo`, refuses to run over an existing install, and expects `hole-dmg` to
have built the app and `cargo build -p plugin-e2e --example ss_plugin_server` to have built the test's server.
