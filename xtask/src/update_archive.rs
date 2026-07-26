//! Build the per-platform update-payload archive from `bindir_dest_names` via
//! the shared `payload-archive` crate (the same code the bridge unpacks with).
//! Windows: a flat `.zip`; macOS: a `.tar.gz` of the built `Hole.app`.

use std::path::Path;

use anyhow::Result;

use crate::Profile;

/// Build the host-platform update archive at `out`.
pub fn build_update_archive(profile: Profile, repo_root: &Path, out: &Path) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        use anyhow::{bail, Context};

        use crate::bindir::{bindir_files, BindirSource};

        let mut entries = Vec::new();
        for f in bindir_files(profile, repo_root)? {
            match f.source {
                // Name each entry by `dest_name`, NOT the source basename —
                // ex-ray's on-disk name is `ex-ray-<triple>.exe`, the entry must
                // be `ex-ray.exe` so the bridge unpacks a valid BINDIR.
                BindirSource::File(p) => entries.push((p, f.dest_name)),
                BindirSource::Directory(p) => {
                    bail!("windows update archive cannot hold a directory bundle: {}", p.display())
                }
            }
        }
        payload_archive::pack_zip(&entries, out).context("pack windows update zip")
    }
    #[cfg(target_os = "macos")]
    {
        use anyhow::Context;

        let app = find_built_app(profile, repo_root)?;
        payload_archive::pack_targz(&app, out).context("pack macos update tar.gz")
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let _ = (profile, repo_root, out);
        anyhow::bail!("update-archive is only built on windows/macos")
    }
}

/// Assert `archive` carries a usable payload: every BINDIR entry present and
/// non-empty on Windows, a non-empty app binary on macOS. Runs against the real
/// built artifact in the release workflow, where the fake-tree unit tests can't
/// reach.
pub fn verify_update_archive(archive: &Path) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        use std::collections::HashMap;

        use anyhow::{bail, Context};
        use xtask_lib::bindir::{bindir_dest_names, Os};

        let file = std::fs::File::open(archive).with_context(|| format!("open {}", archive.display()))?;
        let mut zip = zip::ZipArchive::new(file).with_context(|| format!("read zip {}", archive.display()))?;
        let mut sizes = HashMap::new();
        for i in 0..zip.len() {
            let entry = zip.by_index(i)?;
            sizes.insert(entry.name().to_string(), entry.size());
        }
        for name in bindir_dest_names(Os::Windows) {
            match sizes.get(&name) {
                None => bail!("{name} is missing from {}", archive.display()),
                Some(0) => bail!("{name} is empty in {}", archive.display()),
                Some(_) => {}
            }
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        use anyhow::{bail, Context};

        const BINARY: &str = ".app/Contents/MacOS/hole";

        let file = std::fs::File::open(archive).with_context(|| format!("open {}", archive.display()))?;
        let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(file));
        let mut size = None;
        for entry in tar
            .entries()
            .with_context(|| format!("read tar {}", archive.display()))?
        {
            let entry = entry?;
            if entry.path()?.to_string_lossy().ends_with(BINARY) {
                size = Some(entry.size());
            }
        }
        match size {
            None => bail!("Contents/MacOS/hole is missing from {}", archive.display()),
            Some(0) => bail!("Contents/MacOS/hole is empty in {}", archive.display()),
            Some(_) => Ok(()),
        }
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let _ = archive;
        anyhow::bail!("update-archive is only built on windows/macos")
    }
}

/// The single built `.app` under `target/<profile>/bundle/macos`, via the shared
/// `payload_archive::find_single_app` — bridge and xtask enforce the "exactly one
/// .app" invariant with ONE implementation.
#[cfg(target_os = "macos")]
fn find_built_app(profile: Profile, repo_root: &Path) -> Result<std::path::PathBuf> {
    let dir = repo_root.join("target").join(profile.dir_name()).join("bundle/macos");
    // Flat message (not `.context()`): anyhow's `Display`/`to_string()` shows only
    // the outermost message, so wrapping would hide `find_single_app`'s
    // "expected exactly one .app" detail. Keep the dir + the underlying reason in
    // one line so both survive into a toast/log.
    payload_archive::find_single_app(&dir)
        .map_err(|e| anyhow::anyhow!("select built .app under {}: {e}", dir.display()))
}

// update-archive only builds on windows/macos (the linux arm bails), so its
// tests live there too — no orphan, both platforms run in CI.
#[cfg(all(test, any(target_os = "windows", target_os = "macos")))]
#[path = "update_archive_tests.rs"]
mod update_archive_tests;
