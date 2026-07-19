//! Pack and unpack the per-platform update payload. `xtask` calls `pack_*` to
//! build the release archive; the bridge calls `unpack_*` to extract it in-process
//! during cutover. One crate owns both directions so the two can't drift; the
//! round-trip test is the guard. Extraction confines every entry to `dest` and
//! fails loud (never a silent skip) on an escaping path.

#[cfg(target_os = "macos")]
use std::path::Component;
use std::path::{Path, PathBuf};

/// Zip `(source_path, dest_name)` entries flat at the archive root, naming each
/// by `dest_name` (NOT the source basename — ex-ray's is `ex-ray-<triple>.exe`).
#[cfg(target_os = "windows")]
pub fn pack_zip(entries: &[(PathBuf, String)], out: &Path) -> std::io::Result<()> {
    use std::io::Write;
    let file = std::fs::File::create(out)?;
    let mut w = zip::ZipWriter::new(file);
    let opts = zip::write::SimpleFileOptions::default();
    for (src, name) in entries {
        w.start_file(name.clone(), opts)
            .map_err(|e| std::io::Error::other(format!("zip start {name}: {e}")))?;
        let bytes = std::fs::read(src)?;
        w.write_all(&bytes)?;
    }
    w.finish()
        .map_err(|e| std::io::Error::other(format!("zip finish: {e}")))?;
    Ok(())
}

/// Unpack a `.zip` into `dest` in-process. Confines each entry via
/// `enclosed_name` (rejects absolute / `..`), logs per-entry progress.
#[cfg(target_os = "windows")]
pub fn unpack_zip(zip_path: &Path, dest: &Path) -> std::io::Result<()> {
    let file = std::fs::File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| std::io::Error::other(format!("open zip: {e}")))?;
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| std::io::Error::other(format!("zip entry {i}: {e}")))?;
        let rel = entry
            .enclosed_name()
            .ok_or_else(|| std::io::Error::other(format!("unsafe zip entry path: {}", entry.name())))?;
        tracing::debug!(entry = %rel.display(), "unpacking update entry");
        let out = dest.join(rel);
        if entry.is_dir() {
            std::fs::create_dir_all(&out)?;
            continue;
        }
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut writer = std::fs::File::create(&out)?;
        std::io::copy(&mut entry, &mut writer)?;
    }
    Ok(())
}

/// tar.gz the `.app` bundle (macos), preserving exec bits and symlinks.
#[cfg(target_os = "macos")]
pub fn pack_targz(app_dir: &Path, out: &Path) -> std::io::Result<()> {
    let file = std::fs::File::create(out)?;
    let enc = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut builder = tar::Builder::new(enc);
    builder.follow_symlinks(false);
    let name = app_dir
        .file_name()
        .ok_or_else(|| std::io::Error::other("app dir has no name"))?;
    builder.append_dir_all(name, app_dir)?;
    builder.into_inner()?.finish()?;
    Ok(())
}

/// Unpack a `.tar.gz` into `dest` in-process, preserving exec bits + symlinks.
/// Iterates entries so it can confine each (hard-error on an escaping `..`/
/// absolute path — never `unpack`'s silent skip) and log per-entry progress.
#[cfg(target_os = "macos")]
pub fn unpack_targz(targz: &Path, dest: &Path) -> std::io::Result<()> {
    let file = std::fs::File::open(targz)?;
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(file));
    archive.set_preserve_permissions(true);
    archive.set_overwrite(true);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        if path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(std::io::Error::other(format!(
                "unsafe tar entry path: {}",
                path.display()
            )));
        }
        tracing::debug!(entry = %path.display(), "unpacking update entry");
        // `unpack_in` returns Ok(false) when it internally skips an entry it
        // deems unsafe; make that loud so an incomplete bundle never reaches the
        // irreversible swap (structurally enforces "never a silent skip", rather
        // than trusting the pre-check to mirror unpack_in's internal logic).
        if !entry.unpack_in(dest)? {
            return Err(std::io::Error::other(format!(
                "skipped unsafe tar entry: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

/// The single `*.app` bundle directly under `dir`. Propagates read errors and
/// errors on a count != 1. Shared by the bridge (post-unpack staging check) and
/// xtask (built-bundle selection) so the "exactly one .app" invariant has one
/// implementation, not two that can drift.
pub fn find_single_app(dir: &Path) -> std::io::Result<PathBuf> {
    let mut apps = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() && path.extension().is_some_and(|ext| ext == "app") {
            apps.push(path);
        }
    }
    match apps.as_slice() {
        [one] => Ok(one.clone()),
        _ => Err(std::io::Error::other(format!(
            "expected exactly one .app, found {}",
            apps.len()
        ))),
    }
}

#[cfg(test)]
fn main() {
    skuld::run_all();
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod lib_tests;
