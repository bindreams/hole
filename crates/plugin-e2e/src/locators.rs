//! Locators for the plugin binaries the suites drive. Each path is derived
//! from `xtask` so the test and the build orchestrator stay in lock-step
//! (a triple-map / commit drift breaks compilation, not a silent wrong-path).

use std::path::PathBuf;

/// Workspace root, derived from this crate's `CARGO_MANIFEST_DIR`
/// (`<root>/crates/plugin-e2e`).
fn workspace_root() -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Locate the ex-ray binary built by `cargo xtask ex-ray`
/// (`<repo>/.cache/ex-ray/ex-ray-<host-triple>[.exe]`).
///
/// The path is derived from [`xtask::ex_ray::output_name`] so the test and the
/// build orchestrator stay in lock-step. The friendly wire name `v2ray-plugin`
/// resolves to this binary; a config may also name `ex-ray` directly.
pub fn locate_ex_ray() -> PathBuf {
    workspace_root()
        .join(".cache")
        .join("ex-ray")
        .join(xtask::ex_ray::output_name())
}

/// Locate the pinned upstream shadowsocks/v2ray-plugin built by
/// `cargo xtask provision-upstream-v2ray`.
///
/// Lives at `<repo>/.cache/upstream-v2ray-plugin/<PINNED_COMMIT>/`; the path
/// comes from [`xtask::upstream_v2ray::cached_binary_path`], so the single
/// source of truth for the pinned commit is the xtask module. Used by the
/// cross-impl interop suite to prove ex-ray is wire-compatible with genuine
/// upstream v2ray-plugin in both directions.
pub fn locate_upstream_v2ray() -> PathBuf {
    xtask::upstream_v2ray::cached_binary_path(&workspace_root())
}

/// Locate the galoshes binary built by `cargo xtask galoshes`
/// (`<repo>/target/release/galoshes[.exe]` — always release, since galoshes
/// embeds ex-ray at compile time).
pub fn locate_built_galoshes() -> PathBuf {
    let bin = if cfg!(windows) { "galoshes.exe" } else { "galoshes" };
    workspace_root().join("target").join("release").join(bin)
}
