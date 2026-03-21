// Asset download with atomic rename.

use std::path::{Path, PathBuf};

use super::error::UpdateError;

/// Download an asset from a URL to `dest`, using an intermediate `.part` file.
///
/// Any existing `.part` file from a prior failed attempt is overwritten.
/// This is a blocking function — call from `spawn_blocking`.
pub fn download_asset(url: &str, dest: &Path) -> Result<(), UpdateError> {
    let part = part_file_path(dest);

    // Stream to .part file.
    let response = ureq::get(url).call()?;
    let mut body = response.into_body().into_reader();
    let mut file = std::fs::File::create(&part)?;
    std::io::copy(&mut body, &mut file)?;
    drop(file);

    // Atomic-ish rename to final destination.
    std::fs::rename(&part, dest)?;
    Ok(())
}

/// Compute the `.part` file path for a given destination.
pub(crate) fn part_file_path(dest: &Path) -> PathBuf {
    let mut name = dest.as_os_str().to_owned();
    name.push(".part");
    PathBuf::from(name)
}

#[cfg(test)]
#[path = "download_tests.rs"]
mod download_tests;
