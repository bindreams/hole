//! The single source of the per-platform update-archive asset suffix, shared by
//! the updater (which matches release assets by it) and xtask (which names the
//! archive it builds + emits it to the release workflow) so the two cannot drift.

use crate::bindir::Os;

/// `<os>-<arch>.<ext>` — `ext` is `zip` on Windows, `tar.gz` elsewhere.
pub fn update_asset_suffix(os: Os, arch: &str) -> String {
    let ext = if os == Os::Windows { "zip" } else { "tar.gz" };
    format!("{os}-{arch}.{ext}") // Os's Display renders windows/darwin/linux
}

/// This host's suffix (compile-time selected — the updater and xtask each run on
/// the platform they target).
pub fn host_update_asset_suffix() -> String {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return update_asset_suffix(Os::Windows, "amd64");
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    return update_asset_suffix(Os::Darwin, "arm64");
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    return update_asset_suffix(Os::Darwin, "amd64");
    // Any other host (notably linux CI, which compiles xtask-lib but never calls
    // this) has no hole update archive. Panic at runtime rather than
    // `compile_error!` so the linux build stays green — this crate, unlike the
    // win/mac-only GUI, is compiled on linux.
    #[cfg(not(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "macos", target_arch = "x86_64"),
    )))]
    panic!("update-archive asset suffix is only defined for windows-amd64 and darwin-arm64/amd64")
}
