//! Download + verify wintun.dll on Windows.
//!
//! wintun.dll is a runtime dependency, not a compile-time input. Keeping the
//! download out of `build.rs` lets `cargo check` succeed offline — a download
//! in `build.rs` would run (and fail without network) on every check.
//!
//! Output: `<repo>/.cache/wintun/wintun.dll` and the zip's `LICENSE.txt` beside
//! it, which the notices file prints for the DLL (Windows only). On non-Windows this module compiles to a no-op stub so
//! `cargo xtask deps` works on macOS without panicking.

use std::path::{Path, PathBuf};

#[cfg(target_os = "windows")]
use anyhow::Context;
use anyhow::Result;

#[cfg(target_os = "windows")]
const WINTUN_URL: &str = "https://www.wintun.net/builds/wintun-0.14.1.zip";
#[cfg(target_os = "windows")]
const LICENSE_NAME: &str = "LICENSE.txt";
#[cfg(target_os = "windows")]
const SENTINEL_NAME: &str = "wintun.dll.verified";
#[cfg(target_os = "windows")]
pub(crate) const WINTUN_ZIP_SHA256: &str = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51";

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

    std::fs::create_dir_all(&wintun_dir).with_context(|| format!("failed to create {}", wintun_dir.display()))?;

    // A cache the sentinel certifies skips the network round-trip.
    // Size ceiling against a runaway server.
    let fetch = || crate::download::fetch_verified("wintun.dll", WINTUN_URL, 16 * 1024 * 1024, WINTUN_ZIP_SHA256);
    match cache_state(&wintun_dir) {
        CacheState::Complete => Ok(dll_path),
        // The DLL may be loaded by a running bridge: write the licence beside it and leave the DLL alone.
        CacheState::LacksOnlyTheLicence => {
            extract_license(&fetch()?, &wintun_dir)?;
            eprintln!("xtask: wintun licence downloaded and verified");
            Ok(dll_path)
        }
        CacheState::Refill => {
            let dll_path = extract(&fetch()?, &wintun_dir)?;
            eprintln!("xtask: wintun.dll downloaded and verified");
            Ok(dll_path)
        }
    }
}

/// What a cache folder holds.
#[cfg(target_os = "windows")]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum CacheState {
    /// The DLL and the licence, both certified by the sentinel.
    Complete,
    /// The verified DLL, and no licence the sentinel certifies: the DLL may be in use, so it must not be written again.
    LacksOnlyTheLicence,
    /// No verified DLL: everything is written.
    Refill,
}

/// What `dir` holds. The sentinel `wintun.dll.verified` is written after the files and certifies them: its first line
/// names the pinned zip the DLL came out of, its second the SHA-256 of the licence written beside it. A DLL is the
/// verified one only when the first line is the pinned zip's, and the licence is whole only when its bytes are the second's.
#[cfg(target_os = "windows")]
pub(crate) fn cache_state(dir: &Path) -> CacheState {
    let sentinel = std::fs::read_to_string(dir.join(SENTINEL_NAME)).unwrap_or_default();
    let mut lines = sentinel.lines().map(str::trim);
    let (zip_line, licence_line) = (lines.next(), lines.next());
    let verified = dir.join("wintun.dll").exists() && zip_line == Some(WINTUN_ZIP_SHA256);
    let licence_certified = licence_line.is_some_and(|certified| {
        std::fs::read(dir.join(LICENSE_NAME)).is_ok_and(|licence| crate::download::sha256_hex(&licence) == certified)
    });
    match (verified, licence_certified) {
        (true, true) => CacheState::Complete,
        (true, false) => CacheState::LacksOnlyTheLicence,
        (false, _) => CacheState::Refill,
    }
}

/// Write `wintun.dll` (the amd64 build), the zip's `LICENSE.txt` and then the sentinel into `dir`, and return the DLL's
/// path.
///
/// The layout inside the zip is `wintun/bin/<arch>/wintun.dll` and `wintun/LICENSE.txt`.
#[cfg(target_os = "windows")]
pub(crate) fn extract(zip_data: &[u8], dir: &Path) -> Result<PathBuf> {
    let dll = read_entry(zip_data, "wintun/bin/amd64/wintun.dll")?;
    let license = read_entry(zip_data, "wintun/LICENSE.txt")?;

    let dll_path = dir.join("wintun.dll");
    // `stage` hard-links the cached files into the folders it stages: replace a file, never write through it.
    crate::stage::write_replacing(&dll_path, &dll)?;
    write_license_and_sentinel(&license, dir)?;
    Ok(dll_path)
}

/// Write the zip's `LICENSE.txt` and the sentinel into `dir`: for a folder whose DLL is already there and verified.
#[cfg(target_os = "windows")]
pub(crate) fn extract_license(zip_data: &[u8], dir: &Path) -> Result<()> {
    write_license_and_sentinel(&read_entry(zip_data, "wintun/LICENSE.txt")?, dir)
}

/// The licence first, then the sentinel that certifies it: a cache is complete only once the last write has landed.
#[cfg(target_os = "windows")]
fn write_license_and_sentinel(license: &[u8], dir: &Path) -> Result<()> {
    crate::stage::write_replacing(&dir.join(LICENSE_NAME), license)?;
    let sentinel = format!("{WINTUN_ZIP_SHA256}\n{}\n", crate::download::sha256_hex(license));
    crate::stage::write_replacing(&dir.join(SENTINEL_NAME), sentinel.as_bytes())
}

#[cfg(target_os = "windows")]
fn read_entry(zip_data: &[u8], name: &str) -> Result<Vec<u8>> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(zip_data)).context("failed to open wintun zip")?;
    let mut file = archive
        .by_name(name)
        .with_context(|| format!("{name} not found in zip archive"))?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut bytes).with_context(|| format!("failed to read {name} from zip"))?;
    Ok(bytes)
}
