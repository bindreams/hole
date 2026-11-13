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
`crates/ex-ray/third_party/`. Attributions for other third-party code and bundled assets are not yet collected or
shipped inside release artifacts; that is tracked in [bindreams/hole#1261](https://github.com/bindreams/hole/issues/1261).
