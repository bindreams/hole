//! Download + verify wintun.dll on Windows.
//!
//! wintun.dll is a runtime dependency, not a compile-time input. Keeping the
//! download out of `build.rs` lets `cargo check` succeed offline — a download
//! in `build.rs` would run (and fail without network) on every check.
//!
//! Output: `<repo>/.cache/wintun/wintun.dll` (Windows only). On non-Windows
//! this module compiles to a no-op stub so `cargo xtask deps` works on macOS
//! without panicking.

use std::path::{Path, PathBuf};

#[cfg(target_os = "windows")]
use anyhow::Context;
use anyhow::Result;

#[cfg(target_os = "windows")]
const WINTUN_URL: &str = "https://www.wintun.net/builds/wintun-0.14.1.zip";
#[cfg(target_os = "windows")]
const WINTUN_ZIP_SHA256: &str = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51";

/// Download wintun.dll if not already cached. Returns the path to the
/// extracted DLL on Windows; returns `Ok(None)` on non-Windows.
pub fn ensure(repo_root: &Path) -> Result<Option<PathBuf>> {
    #[cfg(target_os = "windows")]
    {
        ensure_windows(repo_root).map(Some)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = repo_root;
        Ok(None)
    }
}

#[cfg(target_os = "windows")]
fn ensure_windows(repo_root: &Path) -> Result<PathBuf> {
    let wintun_dir = repo_root.join(".cache").join("wintun");
    let dll_path = wintun_dir.join("wintun.dll");
    let hash_sentinel = wintun_dir.join("wintun.dll.verified");

    std::fs::create_dir_all(&wintun_dir).with_context(|| format!("failed to create {}", wintun_dir.display()))?;

    // Cache check: if the sentinel matches our pinned hash, the DLL on disk
    // is the verified one we want and we can skip the network round-trip.
    if dll_path.exists() && hash_sentinel.exists() {
        let stored = std::fs::read_to_string(&hash_sentinel).unwrap_or_default();
        if stored.trim() == WINTUN_ZIP_SHA256 {
            return Ok(dll_path);
        }
        // Hash mismatch — stale cache from a different version, fall through
        // to re-download.
    }

    // The wintun zip is ~0.4 MiB; the ceiling only guards against a runaway server.
    let zip_data = crate::download::fetch_verified("wintun.dll", WINTUN_URL, 16 * 1024 * 1024, WINTUN_ZIP_SHA256)?;

    // Extract wintun.dll from zip — the layout inside the zip is
    // `wintun/bin/<arch>/wintun.dll`. We pin amd64.
    let cursor = std::io::Cursor::new(&zip_data);
    let mut archive = zip::ZipArchive::new(cursor).context("failed to open wintun zip")?;
    let mut dll_file = archive
        .by_name("wintun/bin/amd64/wintun.dll")
        .context("wintun/bin/amd64/wintun.dll not found in zip archive")?;

    let mut dll_data = Vec::new();
    std::io::Read::read_to_end(&mut dll_file, &mut dll_data).context("failed to read wintun.dll bytes from zip")?;

    std::fs::write(&dll_path, &dll_data).with_context(|| format!("failed to write {}", dll_path.display()))?;
    std::fs::write(&hash_sentinel, WINTUN_ZIP_SHA256)
        .with_context(|| format!("failed to write {}", hash_sentinel.display()))?;

    eprintln!("xtask: wintun.dll downloaded and verified ({} bytes)", dll_data.len());
    Ok(dll_path)
}
