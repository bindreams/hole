# cargo-wix

A `cargo` subcommand for building Windows MSI installers using the [WiX Toolset](https://wixtoolset.org/).

WiX v6 is bundled into the `cargo-wix` binary at compile time — no external WiX installation needed. The bundled WiX uses .NET Framework 4.7.2, which is built into Windows 10+ and requires no additional runtime.

## Quick start

1. Install cargo-wix:
   ```sh
   cargo install --path crates/wix
   ```

2. Add config to your crate's `Cargo.toml`:
   ```toml
   [workspace.metadata.wix]
   wxs = "installer.wxs"
   before = ["bash", "scripts/prepare-installer.sh"]

   [package.metadata.wix.bindpaths]
   BinDir = "target/release/installer-stage"
   ```

3. Run:
   ```sh
   cargo wix
   ```

## Configuration reference

All configuration goes under `[workspace.metadata.wix]` in the workspace root `Cargo.toml`.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `wxs` | string | yes | Path to `.wxs` source file, relative to workspace root |
| `package` | string | no | Workspace member whose name/version are used for the MSI. Auto-injects `ProductVersion` define. |
| `output` | string | no | Output MSI path, relative to workspace root. Default: `<target_dir>/release/<package_name>.msi` |
| `before` | array of strings | no | Command (argv-style) to run before `wix build` |
| `after` | array of strings | no | Command (argv-style) to run after `wix build` |

### Subtables

**`[package.metadata.wix.defines]`** — WiX preprocessor defines passed as `-d KEY=VALUE`.

`ProductVersion` is automatically injected from the crate's `[package] version`. Explicit defines take precedence.

**`[package.metadata.wix.bindpaths]`** — WiX bindpaths passed as `-bindpath NAME=PATH`. Paths are resolved relative to the workspace root.

## Hooks

The `before` and `after` fields each specify a single command as an argv-style array. The first element is the program, the rest are arguments. Commands inherit stdout/stderr and run with CWD set to the workspace root.

If the `before` hook fails (non-zero exit), the build aborts. If the `after` hook fails, a warning is printed but the MSI path is still returned.

### Environment variables

Hooks receive these environment variables (in addition to the inherited environment):

| Variable | Description |
|----------|-------------|
| `WIX_OUTPUT` | Absolute path to the output MSI |
| `WIX_WXS` | Absolute path to the `.wxs` source file |
| `WIX_PACKAGE_NAME` | Package name from Cargo.toml |
| `WIX_PACKAGE_VERSION` | Package version from Cargo.toml |
| `WIX_WORKSPACE_ROOT` | Workspace root directory |
| `WIX_TARGET_DIR` | Cargo target directory |

## CLI reference

```
cargo wix [OPTIONS]

Options:
    --wxs <PATH>              Override .wxs file path
    --output <PATH>           Override output MSI path
    --skip-before             Skip the before hook
    --skip-after              Skip the after hook
    --bindpath <NAME=PATH>    Additional bindpath (repeatable)
    -d, --define <KEY=VALUE>  Additional WiX define (repeatable)
```

## Library usage

```rust
use cargo_wix::Builder;

let output = Builder::new("/path/to/installer.wxs")
    .workspace_root("/project")
    .target_dir("/project/target")
    .package_name("my-app")
    .package_version("1.0.0")
    .bindpath("BinDir", "/project/target/release/stage")
    .define("ProductName", "My App")
    .build()?;
```

## How WiX is bundled

At compile time, `build.rs` downloads the WiX v6 MSI from GitHub releases, extracts it using the `msi` and `cab` crates, filters to the target architecture, and packs the files into a zip embedded in the binary via `include_bytes!`. At runtime, the zip is extracted to a cache directory (`~/.cache/cargo-wix/`) on first use.

The pinned WiX version and SHA256 hash are in `wix-toolchain.toml`. A GitHub Actions workflow (`update-wix.yaml`) checks for new WiX releases weekly.
