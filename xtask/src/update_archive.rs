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
