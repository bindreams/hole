# Licensing

Hole is licensed under the [GNU GPL version 3 or later](https://www.gnu.org/licenses/gpl-3.0.html), unless a component's
own `LICENSE` file says otherwise. The full text is in {src}`LICENSE.md`.

Some libraries and plugins are Apache-2.0 so that others can reuse them. Each carries its own license file:

| Component    | What it is                                                  | License file                     |
| ------------ | ----------------------------------------------------------- | -------------------------------- |
| `file-lock`  | Cross-process exclusive file lock                           | {src}`crates/file-lock/LICENSE`  |
| `galoshes`   | A SIP003 plugin that adds UDP                               | {src}`crates/galoshes/LICENSE`   |
| `garter`     | Runs a chain of SIP003 plugins                              | {src}`crates/garter/LICENSE`     |
| `garter-bin` | The `garter` command-line binaries                          | {src}`crates/garter-bin/LICENSE` |
| `stepstool`  | Elevation primitives for running one child as administrator | {src}`crates/stepstool/LICENSE`  |
| `tombstone`  | Records native crashes for the next start                   | {src}`crates/tombstone/LICENSE`  |
| `util`       | Small cross-platform utilities                              | {src}`crates/util/LICENSE`       |
| `ex-ray`     | The first-party SIP003 plugin (a Go module)                 | {src}`crates/ex-ray/LICENSE`     |

Code Hole builds on keeps its own license. The Go code vendored into ex-ray carries its license files under
`crates/ex-ray/third_party/`.

The diagrams in this documentation use icons from [Lucide](https://lucide.dev), under the ISC and MIT licenses. Their
text is published with the documentation: {src}`docs/_static/licenses/lucide.txt`. The marks of other apps in a diagram
come from [Simple Icons](https://simpleicons.org) (CC0). They are trademarks of their owners and stand for the apps
themselves.

## What each artifact carries

Every `hole` artifact carries one generated file, `NOTICES.md`: Hole's own license statement with the URL of the source
of that release, the GPL-3.0 text, then the license and notices of every third-party component in that artifact.

| Artifact                                   | Carries                                                         | Where                                                                                                                                                                                                                                |
| ------------------------------------------ | --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Windows installer (`.msi`)                 | `NOTICES.md`                                                    | `<install folder>\bin\NOTICES.md`, beside `hole.exe`                                                                                                                                                                                 |
| Windows update archive (zip)               | `NOTICES.md`                                                    | the root of the zip; the updater installs it into `bin\`                                                                                                                                                                             |
| macOS disk image (`.dmg`)                  | `NOTICES.md`                                                    | `Hole.app/Contents/Resources/NOTICES.md`                                                                                                                                                                                             |
| macOS update archive (tar.gz)              | the built `Hole.app`                                            | the same path inside it                                                                                                                                                                                                              |
| `galoshes`, `ex-ray`, `garter` executables | not covered: each is one bare file with nowhere to put a notice | tracked in [#1350](https://github.com/bindreams/hole/issues/1350), [#1351](https://github.com/bindreams/hole/issues/1351) and [#1352](https://github.com/bindreams/hole/issues/1352), each a blocker for that product's next release |
| `garter` on crates.io                      | its `LICENSE`, which `cargo package` includes                   | the package root; it holds no third-party code                                                                                                                                                                                       |

The Windows name is fixed: every Windows updater from 0.3.0 on requires a file named exactly `NOTICES.md` in the payload
([Ship blockers](../contributing/maintainers/ship-blockers.md)).

Judgments, which no license text decides:

- The GPL-3.0 text and the source URL in the file are there for GPL-3.0 section 6 (object code is accompanied by the
  source or an offer of it). The URL names the release tag. Whether a URL meets "accompanied" is a judgment.
- An in-app view of the file is not required by any license text below. Hole has none.

## What each license family asks

What a binary copy owes, by license. The clauses are quoted from the standard texts. "Meets it" says how `NOTICES.md`
does, and each judgment is marked.

- **MIT**: "The above copyright notice and this permission notice shall be included in all copies or substantial portions
  of the Software." The file prints each component's own license file whole, so its holder line is kept.
- **BSD-2-Clause, BSD-3-Clause**: "Redistributions in binary form must reproduce the above copyright notice, this list of
  conditions and the following disclaimer in the documentation and/or other materials provided with the distribution." Met
  the same way. A link alone would not meet it.
- **ISC**: the permission is granted "provided that the above copyright notice and this permission notice appear in all
  copies." Met the same way.
- **Apache-2.0**: section 4(a) "You must give any other recipients of the Work or Derivative Works a copy of this License"
  and 4(d) "If the Work includes a "NOTICE" text file as part of its distribution, then any Derivative Works that You
  distribute must include a readable copy of the attribution notices contained within such NOTICE file". The text is
  printed once, followed by the components under it, with every `NOTICE` file a component ships.
- **MPL-2.0**: section 3.2 "(a) such Covered Software must also be made available in Source Code Form ... and You must
  inform recipients of the Executable Form how they can obtain a copy of such Source Code Form". The file prints the
  text and the source URL of each such component. Judgment: a crates.io URL pinned to the version is a sufficient way to
  say how to obtain it.
- **Unicode-3.0**: "this copyright and permission notice appear with all copies of the Data Files or Software, or ... in
  associated Documentation". Met the same way as MIT.
- **CDLA-Permissive-2.0** (`webpki-roots`, data): "A Data Recipient may share Data, with or without modifications, so
  long as the Data Recipient makes available the text of this agreement with the shared Data." The text is printed.
  Judgment: this applies to data embedded in a binary.
- **OFL-1.1** (the two fonts): "Original or Modified Versions of the Font Software may be bundled, redistributed and/or
  sold with any software, provided that each copy contains the above copyright notice and this license." The file prints
  the license with the holder line from each font's upstream `LICENSE`. Judgment: a subset of a font in `woff2` form is
  still the Font Software for this clause.
- **BSL-1.0**: "unless such copies or derivative works are solely in the form of machine-executable object code", so a
  binary owes nothing. **Zlib, Unlicense, CC0-1.0, 0BSD, MIT-0, WTFPL** ask nothing of object code. The file lists them
  because it is customary.

A license on the list in `.config/notices.yaml` is compatible with GPL-3.0-or-later and has a duty for a binary copy that
the file meets. Judgment: none of the licenses found is incompatible with a GPL-3.0-or-later whole.

### Components that are not packages

- **Rust standard library**: `MIT OR Apache-2.0`, linked into every Rust binary, with third-party crates and the Unicode
  tables of its own. Its section is the pinned toolchain's own copyright file for it
  (`<sysroot>/share/doc/rust/COPYRIGHT-library.html`, which `rustc --print sysroot` finds from the repository root), converted
  to text and printed whole, followed by the text of each license the file names for its own source files by identifier
  alone (from the toolchain's `licenses/`). The file also lists the standard library's build and test tools, so the section
  names more than is linked; a sentence at its head says so. A toolchain without the file fails the build.
- **Go standard library**: BSD-3-Clause, linked into `ex-ray`. It is a `declared:` entry, not a Go module, and it has no
  pinned version: the version and the `LICENSE` printed are those of the Go toolchain that builds `ex-ray` (`go env GOVERSION` and `go env GOROOT`, run in `crates/ex-ray`, so `go.mod` selects the toolchain as the build does). The
  `toolchain` line of `go.mod` is a minimum, so a newer local Go prints its own version and the build still passes.
- **Microsoft Edge WebView2 SDK** (Windows only): `hole.exe` links `WebView2LoaderStatic.lib`, because `webview2-com-sys`
  selects the static loader on `msvc`; `hole.exe` carries the loader's code and imports no `WebView2Loader.dll`. The
  crate bundles the library without the SDK's license. Its x64 library is byte for byte the one in the NuGet package
  `Microsoft.Web.WebView2` 1.0.3800.47, whose `LICENSE.txt` (BSD-3-Clause, "Copyright (C) Microsoft Corporation") the file
  prints; the package's `NOTICE.txt` covers `tools/wv2winrt`, which is not linked. On a `webview2-com-sys` bump the SDK
  version is read again.
- **Wintun** (`wintun.dll`): a separate binary under WireGuard LLC's "Prebuilt Binaries License", read from the `LICENSE.txt`
  of the pinned zip. Section 3(c) forbids you to "remove any proprietary notices, labels, or copyrights from the
  Software". Section 3(d) forbids you to "resell, redistribute ... or otherwise transfer rights of the Software without
  the prior written consent of WireGuard LLC, except insofar as the Software is distributed alongside other software that
  uses the Software only via the Permitted API". Nothing in it requires the text to accompany a copy; the file prints it
  anyway. Judgment: Hole uses Wintun only through the `wintun.h` API, so 3(d) allows shipping it beside `hole.exe`.
- **The static MSVC runtime**: every Windows executable carries the Visual C++ runtime linked in. Under Microsoft's Visual
  Studio license terms (Community 2022, the `.docx` linked from
  <https://visualstudio.microsoft.com/license-terms/vs2022-ga-community/>), which allow distributing "the object code form
  of code listed on the Distributable List located at https://aka.ms/vs/17/redistribution", no notice is owed: they ask
  for none, so `NOTICES.md` says nothing about the runtime. Open in
  [#1355](https://github.com/bindreams/hole/issues/1355): whether the statically linked runtime libraries may be
  redistributed (the list names the `.msm` merge modules and the files under `VC\redist`, not the static `.lib` files),
  and which Visual Studio edition builds the releases.

## How the file is made

`cargo xtask notices [--os OS] [--arch ARCH] [--out PATH]` writes the file for one platform's `hole` artifact: the
host's file, however the host was named (bare, or `--os` and `--arch` that resolve to it), goes to
`.cache/notices/NOTICES.md`, which is where the staging and the macOS bundler read it; any other platform's goes to
`.cache/notices/<os>-<arch>/NOTICES.md`. The `hole`, `hole-msi` and `hole-dmg` targets depend on the `notices` target, which runs it, so every installer build and the CI build of it generate the file; nothing is committed.

It collects what the artifact links:

- Rust crates from `cargo metadata --filter-platform <triple>`: normal edges only, proc-macro crates left out, starting at
  `hole` and `galoshes`. The list is a superset: `cargo metadata` merges the features of build scripts and of the
  program, so some crates that no binary links are listed. Naming a crate that is not linked does no harm; an exact
  walk could leave out a crate that the installers' workspace build links.
- Go packages from `go list -deps` for `crates/ex-ray` with the platform's `GOOS` and `GOARCH`, mapped to modules, with
  `replace`d modules read from `crates/ex-ray/third_party/` and nested licenses of linked packages included.
- The npm packages in `node_modules/` that are not dev-only, as npm's own record of what it installed there
  (`node_modules/.package-lock.json`) lists them; `package-lock.json` must agree with it, and the build fails naming the
  `npm-install` target when it does not: every package of the record is in the lock with the same
  version and `dev` flag, every package the lock lists is installed unless it is `dev`, `optional` or `devOptional` (npm
  may leave out any of the three: a production-only install, or a platform the package does not fit), and each
  production package's folder holds a `package.json` of the recorded version. On a given host that is the set the UI is
  built from. For another `--os` or `--arch` generation proceeds when the lock has no production package that npm
  installs only on some platforms (`optional` or `devOptional`, and not `dev`), and fails otherwise: that set can only
  be read on the platform it is for.
- What no package manager declares, from `.config/notices.yaml`: the fonts in `ui/fonts/`, `wintun.dll`, the WebView2 SDK, the Rust
  and Go standard libraries and the code in `ex-ray` derived from `shadowsocks/v2ray-plugin`.

It picks each component's license from the ordered `licenses:` list in `.config/notices.yaml`: the list allows, and the
position prefers. Where an expression offers a choice (`MIT OR Apache-2.0`), the first listed license it allows is
followed. A license that names a holder is printed whole as the component distributes it, and two texts are merged only
when byte-identical. A standard text that names no holder (Apache-2.0, MPL-2.0) is printed once. No license text is
committed: standard texts come from the `spdx` crate, Go's from `GOROOT`, Wintun's from the pinned zip, a component's own
from its source folder.

A listed license whose text is its standard text (`text: shared`) must have one in the `spdx` crate, which the config load
checks; a license without one (`LicenseRef-...`) is `text: own`. An entry may name a license with an exception
(`Apache-2.0 WITH LLVM-exception`); it covers only that requirement, and prints the component's own files, so it is `text: own`.

### When the build fails

The build fails instead of guessing, and the message names the component and the entry that settles it. Read the
component's own license file first, then add to `.config/notices.yaml`:

| Failure                                                       | Entry to add                                                                                                                             |
| ------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| No license in its expression is on the list                   | the license under `licenses:`, if it is compatible with GPL-3.0-or-later and the file meets its duty                                     |
| It declares no license (every Go module does)                 | `overrides:` with `ecosystem:`, `license:` read from its `LICENSE`, pinned to a version                                                  |
| It declares a license that does not parse (`BSD`)             | the same `overrides:` entry: its `license:` replaces a declared license that does not parse, and never one that does                     |
| A license needs a notice and the component ships none         | `overrides:` with `texts:` and `text:` (the text) or `notice:` (the holder line), with the upstream `source:` URL it was read from       |
| Upstream ships no license text at all                         | `overrides:` with `texts:` and `upstream_words:` (what upstream does state, verbatim); the standard text follows it, with no holder line |
| A font or shipped binary has no entry                         | `declared:` with its name, license, `files:` (the repository path the message names) and a holder line read from upstream                |
| An override matches no component of an artifact it applies to | remove it, fix its `name` or `version`, or limit its `platforms:` to the artifacts that carry the component                              |

A `license:` in the config is checked when the file is loaded, the way a component's is chosen: it must parse, and the
generator must follow a license under it (`MIT OR GPL-2.0-only` is followed as `MIT` when only `MIT` is listed; a
license that is not listed, or one with an exception, is not followed). The message names which. An `overrides:` entry that sets one must also set `version:`, because a license read from a component's files
is true of the version it was read from; a bump leaves the entry unused, which fails the build and asks for the license to
be read again. The entry to add for a component's own bad or missing license therefore always names the version.

An entry in `declared:` or `overrides:` applies to the artifacts its `platforms:` names: `windows` is every Windows
artifact, `windows/amd64` one architecture of it. With no `platforms:` it applies to every artifact. Each artifact is
generated alone, so an override must match a component in every artifact it applies to; one that matches nothing in an
artifact fails that artifact's build. Two entries that apply to one component may not both set `license:` (or, for a
declared component, `text_from:`).

An entry never holds a text that a source can provide. Quote upstream exactly, and never invent a holder line.
