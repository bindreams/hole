# Plugin binaries: where each platform gets them

The {term}`bridge` runs with administrator rights, and a {term}`SIP003 plugin` it starts runs with the same rights. So the
bridge runs only the plugins Hole ships, from one folder it can vouch for, and never one found on the `PATH`, which is
writable by the user on a bridge elevated from the app. For what the plugins are, read [Shadowsocks and its plugins](../../how-it-works/plugins.md).

## One owner of "where are the plugins"

`PluginSource` ({src}`crates/bridge/src/proxy/plugin_source.rs`) is the only owner of the answer, for every platform and
mode. A caller asks `PluginSource::resolve(name)` and gets a `BundledPlugin`, a descriptor from `KNOWN_PLUGINS`
({src}`crates/common/src/plugin.rs`) bound to the absolute path of its binary, or a typed `PluginResolveError`. The plugin
spawner accepts nothing else, and only `resolve` builds one, so "may this run" has one gate. The configured name may be a
friendly one: `v2ray-plugin` resolves to the binary `ex-ray`. A name outside `KNOWN_PLUGINS` is `NotBundled`, and its error
lists the plugins Hole ships. The server test resolves through the same source as a connect
(`ProxyManager::plugin_source_handle`).

Per-variant behaviour is a method of `PluginSource`, one exhaustive match each, and no file outside the per-platform
constructors names a variant; `plugin_source_policy_lives_on_the_type_not_at_call_sites` enforces it.

| Platform and mode                      | `PluginSource`    | Where the plugins are                                  | Who writes them                       | How they are vouched for                                                 |
| -------------------------------------- | ----------------- | ------------------------------------------------------ | ------------------------------------- | ------------------------------------------------------------------------ |
| macOS service                          | `Managed`         | `/Library/Application Support/Hole`, root-owned        | the service, from bytes inside `hole` | the repair of this start, [below](#macos-the-folder-the-service-keeps)   |
| Windows service                        | `InstallDir`      | beside the installed bridge executable                 | the installer                         | Program Files is not user-writable by default; the bridge does not check |
| foreground, either platform            | `BuildDir`        | beside the bridge executable, a staged build directory | `cargo xtask stage`                   | nothing                                                                  |
| foreground `--plugin-dir DIR`, Windows | `Explicit`        | `DIR`, read and never written                          | the administrator                     | nothing                                                                  |
| foreground `--plugin-dir DIR`, macOS   | `ExplicitStamped` | `DIR`, read and never written                          | the administrator                     | a current layout stamp                                                   |

`BuildDir` and `InstallDir` look in the directory of the real executable: `beside` canonicalizes a symlinked
registration, and requires an absolute executable path so the lookup never depends on the working directory. A missing
binary is `BinaryMissing`, whose remedy differs per variant (`PluginSource::remedy`): reinstall, or run
`cargo xtask stage`, or check `--plugin-dir`.

## macOS: the folder the service keeps

On macOS the plugins are inside `hole`, and the app bundle carries none. The build script
{src}`crates/hole/build/embed_plugins.rs` reads each from `.cache/<name>/<name>-<triple>`, hashes it, copies the *same
read* into `$OUT_DIR`, and generates `embedded_plugins.rs`, which {src}`crates/hole/src/embedded_plugins.rs` includes. The
platform difference is stated once, in {src}`xtask-lib/src/bindir.rs`: `embedded_plugin_names` is the plugin names on
macOS and none elsewhere, and `bundle_payload_names` is what the bundle holds without them
({src}`crates/hole/tauri.macos.conf.json` clears `externalBin`). A dev or test build with stub sidecars embeds empty
payloads, which repair never converges toward and never removes anything for. A release build with an empty payload fails
in `embed_plugins.rs`. The DMG test `test_hole_carries_the_plugin_bytes` compares the embedded bytes with `.cache`.

At every service start the bridge makes `PLUGIN_DIR` ({src}`crates/bridge/src/platform/macos.rs`) hold exactly those files
plus a layout stamp. The step, `prepare_plugins`, runs in `platform::macos::run` after the IPC socket is bound and the
liveness lock held, and before DNS and route recovery: repairs come first, so a bridge stuck in any later step never
misses one, and the one bridge holding the liveness lock is the only repairer. It never stops the start. Its duration is
logged at `info`.

### Repair

Repair is a pure decision and a thin applier ({src}`crates/bridge/src/plugin_repair.rs`,
{src}`crates/bridge/src/plugin_repair/apply.rs`). `decide_repair(Survey, carried) -> RepairPlan` is one match on what the
folder is:

| Survey                                                                                                 | Plan                                                                                                                                                                                                                                                |
| ------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `NoDir`                                                                                                | create the folder, write every carried plugin, store the stamp                                                                                                                                                                                      |
| `UnsoundDir` (a link or file at its name, another owner or group, or a mode group or others can write) | rebuild the folder, write, store the stamp. No stamp was read, since nothing in an unsound folder is trusted. If a plugin has no payload in this build the folder is left alone, because rebuilding would remove a plugin this build cannot replace |
| `SoundDir`, stamp unreadable                                                                           | nothing: the folder is left exactly as it is                                                                                                                                                                                                        |
| `SoundDir`                                                                                             | set the mode to 0755 if it differs; write what is missing or differs; clear a name that holds something other than a file, then write it; remove unexpected names; store the stamp if there is none                                                 |

`apply` runs the steps in order, each file as a staged temporary renamed over its name, through `util::dir::Dir` handles,
so no name is acted on by path. A failing step does not stop the next, so one stubborn entry does not keep the other plugin
from landing. The step that stores the stamp claims convergence (`Step::claims_convergence`), so it runs only when every
step before it succeeded, and a crash at any step leaves a folder the next start finishes. Unexpected names are removed,
folders with everything below them (`Dir::remove_tree`). A name that differs from a carried name or the stamp only in
case is the same entry when the volume says it is the same file (a case-insensitive volume), and a stray otherwise.

A repair whose steps all succeeded is judged by surveying the folder again (`left_to_do`): a step's success says it ran,
not what the volume made of it, so a step the volume did not carry out leaves the repair `Degraded`.

### What the start may run

How the start prepared is recorded as a `Prepared`: the repair's `RepairOutcome`, and whether the runtime folder was made.
The `Managed` source holds it in a `RepairVerdict`, and `Prepared::standing` is one match over every cell:

| `Standing`          | Because                                                                           | `resolve` gives                        |
| ------------------- | --------------------------------------------------------------------------------- | -------------------------------------- |
| `Vouched`           | repair `Converged` or `Repaired`, runtime folder made                             | the path                               |
| `NotPrepared`       | no preparation has run yet                                                        | `FolderNotPrepared`                    |
| `FolderNotRepaired` | repair `Degraded` (a failed write, an unreadable folder, a build with no payload) | `FolderNotRepaired`                    |
| `RuntimeDirNotMade` | repair `Converged` or `Repaired`, but the runtime folder could not be made        | `RuntimeDirNotMade`, naming the folder |
| `StampUnreadable`   | repair `Refused`                                                                  | `LayoutUnreadable`, naming the stamp   |

When the repair `Degraded` or `Refused` and the runtime folder also failed, the error names the folder and the runtime
failure is only logged.

A start asks `resolve` for the configured plugin before anything else: before the DoH bootstrap, before any cover is
engaged or released, before any dial. A refusal therefore touches nothing and reaches the user as the usual start
error. Import already rejects plugins Hole does not ship, so only a hand-edited or old config, or a direct IPC call,
gets here.

### The layout stamp

The stamp is `layout.json`, a `util::versioned_file` record of the `OsRecord` role
({src}`crates/bridge/src/plugin_repair/layout_stamp.rs`). A stamp this release cannot read, whether newer, corrupt or
unreadable, is never replaced or removed: repair changes nothing, and every plugin start and server test refuses with an
error that names the stamp. There is no in-app escape; the remedy in the error is to stop Hole and move the file aside,
and the next start rebuilds the folder.

## `--plugin-dir`

`hole bridge run --plugin-dir DIR` runs a foreground bridge from `DIR`, which must be a directory (`absolute_plugin_dir`
makes it absolute and does not canonicalize). It conflicts with `--service`. The bridge runs the binaries in `DIR` with its
own privileges and never writes the folder.

- On Windows nothing is checked.
- On macOS the only check is that `DIR` is a Hole plugin folder, meaning its stamp is current. That tells a wrong folder
  from a right one; it does not say who can write the folder, so name only a folder that only root can write, such as
  `PLUGIN_DIR`. The stamp is read under the bridge's vouched-read rules (`util::dir::ReadDir`), so name the real folder and
  not a user's link to a folder somebody else owns; a stamp another user owns is refused too, and the error says it was
  refused and why. A folder that is gone after the bridge started is `PluginDirNotFound`.

The foreground default, `BuildDir`, runs whatever sits beside the executable.

## Plugins that extract themselves

{term}`galoshes` unpacks its embedded `ex-ray` at run time, and it needs a folder only root can write. `PluginSource::runtime_dir`
is `SERVICE_RUNTIME_DIR` for `Managed` and none for every other source. It is outside `PLUGIN_DIR` on purpose, because
repair removes what it does not recognise there. `prepare_plugins` makes it root-owned with mode 0700, and the plugin spawn
sets `XDG_RUNTIME_DIR` to it whether or not launchd supplies a `HOME`. For a foreground bridge the plugin uses the
environment the bridge was started with.

## Uninstall

`uninstall` ({src}`crates/bridge/src/platform/macos.rs`) removes the plugin folder, the runtime folder, the launchd
property list and the helper, attempting every removal and naming each that failed, so one that cannot be removed never
keeps the registration from going. `has_anything_to_uninstall` gates the removals, and it is true while any of the
four is still present, so a retry reaches the leftovers of an uninstall whose folder removal failed after the property list
went. `is_installed` is only the property list, and a leftover folder must not make it read as installed. The rest of
the uninstall is in [uninstall and the service](kill-switch-uninstall.md).
