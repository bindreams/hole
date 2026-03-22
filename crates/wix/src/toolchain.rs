use std::io::Read;
use std::path::PathBuf;

use serde::Deserialize;

use crate::error::{Error, Result};

/// The bundled WiX zip archive, created by build.rs from the MSI.
const WIX_BUNDLE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/wix-bundle.zip"));

#[derive(Debug, Deserialize)]
struct WixToolchain {
    version: String,
    #[allow(dead_code)]
    url: String,
    #[allow(dead_code)]
    sha256: String,
}

fn toolchain() -> &'static WixToolchain {
    static TOOLCHAIN: std::sync::OnceLock<WixToolchain> = std::sync::OnceLock::new();
    TOOLCHAIN.get_or_init(|| {
        toml::from_str(include_str!("../wix-toolchain.toml")).expect("failed to parse wix-toolchain.toml")
    })
}

/// Returns the pinned WiX version string.
pub fn wix_version() -> &'static str {
    &toolchain().version
}

/// Returns the cache directory for the pinned WiX version.
///
/// Platform-independent (returns a path even on non-Windows, for testability).
pub fn wix_cache_dir() -> PathBuf {
    let base = dirs::cache_dir().expect("failed to determine cache directory");
    base.join("cargo-wix").join(format!("wix-v{}", wix_version()))
}

/// Ensures WiX is extracted and cached. Returns the path to `wix.exe`.
///
/// The WiX binaries are bundled in the cargo-wix binary at compile time.
/// On first run, they are extracted to the cache directory.
///
/// On non-Windows, returns `Err(Error::UnsupportedPlatform)`.
#[cfg(target_os = "windows")]
pub fn ensure_wix() -> Result<PathBuf> {
    let cache_dir = wix_cache_dir();
    // Find wix.exe within the extracted bundle. The MSI installs to a
    // directory named "WiX Toolset vX.Y" — we search for wix.exe rather
    // than hardcoding the directory name, so version bumps don't break this.
    let wix_exe = find_wix_exe(&cache_dir)?;

    let sentinel = cache_dir.join("wix.extracted");
    let expected_version = wix_version();

    if wix_exe.exists() && sentinel.exists() {
        let stored_version = std::fs::read_to_string(&sentinel).unwrap_or_default();
        if stored_version.trim() == expected_version {
            return Ok(wix_exe);
        }
    }

    extract_bundle(&cache_dir)?;
    Ok(wix_exe)
}

#[cfg(not(target_os = "windows"))]
pub fn ensure_wix() -> Result<PathBuf> {
    Err(Error::UnsupportedPlatform)
}

#[cfg(target_os = "windows")]
fn find_wix_exe(base: &std::path::Path) -> Result<PathBuf> {
    // Walk the extracted directory tree looking for wix.exe
    fn walk(dir: &std::path::Path) -> Option<PathBuf> {
        let entries = std::fs::read_dir(dir).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.file_name().map(|n| n == "wix.exe").unwrap_or(false) {
                return Some(path);
            }
            if path.is_dir() {
                if let Some(found) = walk(&path) {
                    return Some(found);
                }
            }
        }
        None
    }

    walk(base).ok_or_else(|| Error::ExtractionFailed("wix.exe not found in cache".into()))
}

#[cfg(target_os = "windows")]
fn extract_bundle(cache_dir: &std::path::Path) -> Result<()> {
    eprintln!(
        "Extracting bundled WiX v{} to {}...",
        wix_version(),
        cache_dir.display()
    );

    // Clean any stale cache
    if cache_dir.exists() {
        std::fs::remove_dir_all(cache_dir)?;
    }
    std::fs::create_dir_all(cache_dir)?;

    // Extract the bundled zip
    let cursor = std::io::Cursor::new(WIX_BUNDLE);
    let mut archive = zip::ZipArchive::new(cursor)
        .map_err(|e| Error::ExtractionFailed(format!("failed to open bundled zip: {e}")))?;

    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| Error::ExtractionFailed(format!("failed to read zip entry {i}: {e}")))?;

        if file.is_dir() {
            continue;
        }

        let name = file.name().to_string();
        let out_path = cache_dir.join(&name);

        // Create parent directories
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        std::fs::write(&out_path, &data)?;
    }

    // Write version sentinel
    let sentinel = cache_dir.join("wix.extracted");
    std::fs::write(&sentinel, wix_version())?;

    eprintln!("WiX v{} extracted ({} files)", wix_version(), archive.len());
    Ok(())
}

#[cfg(test)]
#[path = "toolchain_tests.rs"]
mod toolchain_tests;
