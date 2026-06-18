//! Extract the bare binaries from the verified MSI/DMG onto the destination
//! volume. The privileged bridge (SYSTEM/root) cannot trust the non-admin GUI
//! that hands it the payload over the IPC socket: it re-verifies the payload
//! offline against the embedded minisign key before any irreversible step
//! (fail-closed). A deeper Authenticode/codesign observation belongs here as
//! log-only defense-in-depth (NOT a gate — gating risks a self-inflicted brick
//! on signing-cert rotation).
//!
//! Same-volume staging is required so the subsequent rename is a directory-entry
//! flip, not a cross-volume copy (Windows) / `EXDEV` (macOS).

use std::path::{Path, PathBuf};

/// Re-verify the payload offline before the irreversible steps: minisign over
/// the caller-supplied `SHA256SUMS` manifest, then the payload's SHA-256 against
/// its manifest entry. The GUI already verified on download, but it is the
/// attacker in the bridge's trust model — re-verification here is mandatory and
/// fully offline (the manifest + signature are passed in, no network).
pub fn reverify(
    payload_path: &Path,
    asset_name: &str,
    sha256sums: &str,
    sha256sums_minisig: &str,
) -> Result<(), hole_common::verify::VerifyError> {
    hole_common::verify::verify_payload_offline(payload_path, asset_name, sha256sums, sha256sums_minisig)
}

/// Staged binaries extracted onto the destination volume, ready to rename-swap.
///
/// Windows carries only the staging dir: the detached cutover child re-finds
/// every bundled binary by name under it, so individual staged paths aren't
/// threaded here.
#[derive(Debug, Clone)]
pub struct ExtractedImages {
    /// Directory on the destination volume holding the extracted binaries.
    pub staging_dir: PathBuf,
    /// The staged `Hole.app` bundle.
    #[cfg(target_os = "macos")]
    pub app: PathBuf,
    /// The staged helper Mach-O inside the bundle.
    #[cfg(target_os = "macos")]
    pub helper: PathBuf,
}

/// Build the Windows `msiexec /a` admin-install args that extract the MSI's
/// full payload (every bundled binary) to `target_dir`. Quiet (`/qn`) so no UI.
#[cfg(target_os = "windows")]
pub fn msiexec_admin_args(msi: &Path, target_dir: &Path) -> Vec<String> {
    vec![
        "/a".into(),
        msi.to_string_lossy().into_owned(),
        "/qn".into(),
        format!("TARGETDIR={}", target_dir.to_string_lossy()),
    ]
}

/// Extract the bare binaries onto the destination volume.
///
/// Windows: `msiexec /a` admin-install of the MSI into a staging dir on the same
/// volume as the install dir (the cutover re-finds each bundled binary under
/// it). macOS: `hdiutil
/// attach` the DMG, copy the `.app` onto the destination volume (the DMG mount
/// is a separate volume → `EXDEV`), then detach.
pub fn extract(payload_path: &Path, staging_parent: &Path) -> std::io::Result<ExtractedImages> {
    #[cfg(target_os = "windows")]
    {
        imp_windows::extract(payload_path, staging_parent)
    }
    #[cfg(target_os = "macos")]
    {
        imp_macos::extract(payload_path, staging_parent)
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let _ = (payload_path, staging_parent);
        Err(std::io::Error::other("update extraction unsupported on this platform"))
    }
}

#[cfg(target_os = "windows")]
pub use imp_windows::{find_staged, find_staged_exe};

#[cfg(all(test, target_os = "windows"))]
pub(crate) use imp_windows::find_file_inner;

#[cfg(target_os = "windows")]
mod imp_windows {
    use std::path::{Path, PathBuf};

    use super::{msiexec_admin_args, ExtractedImages};

    /// Subdirectory where the MSI payload lands.
    const STAGING_NAME: &str = ".update-staging";
    /// The binary used for the post-extract fail-closed presence check.
    pub const EXE_NAME: &str = "hole.exe";

    /// Locate `name` under a staging dir, erroring if absent (the detached
    /// `bridge cutover` child receives only the staging dir path, so it re-finds
    /// each bundled binary by name).
    pub fn find_staged(staging_dir: &Path, name: &str) -> std::io::Result<PathBuf> {
        find_file(staging_dir, name)?
            .ok_or_else(|| std::io::Error::other(format!("{name} not found in staged payload under {staging_dir:?}")))
    }

    /// Locate the staged `hole.exe` — the payload-present fail-closed check.
    pub fn find_staged_exe(staging_dir: &Path) -> std::io::Result<PathBuf> {
        find_staged(staging_dir, EXE_NAME)
    }

    /// Extract into a staging dir guaranteed to be on the SAME volume as the
    /// installed binary (the swap is `std::fs::rename`, which fails cross-device).
    /// `_staging_parent` (the service state dir) is ignored on Windows: it may be
    /// on a different volume than Program Files, so the install dir is the only
    /// safe same-volume parent.
    pub fn extract(payload_path: &Path, _staging_parent: &Path) -> std::io::Result<ExtractedImages> {
        let install_dir = std::env::current_exe()?
            .parent()
            .ok_or_else(|| std::io::Error::other("current_exe has no parent dir"))?
            .to_path_buf();
        let staging_dir = install_dir.join(STAGING_NAME);
        // A leftover staging dir from a crashed prior attempt would poison the
        // admin-install; start clean.
        if staging_dir.exists() {
            std::fs::remove_dir_all(&staging_dir)?;
        }
        std::fs::create_dir_all(&staging_dir)?;

        let args = msiexec_admin_args(payload_path, &staging_dir);
        let out = std::process::Command::new("msiexec").args(&args).output()?;
        if !out.status.success() {
            return Err(std::io::Error::other(format!(
                "msiexec /a failed (code {:?}): {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr)
            )));
        }

        // Fail-closed: confirm hole.exe is present before the irreversible swap.
        find_staged_exe(&staging_dir)?;
        Ok(ExtractedImages { staging_dir })
    }

    /// Find `name` anywhere under `root` (an MSI lays out files into a versioned
    /// subtree, so the exe is not at a fixed depth). Guards against directory
    /// symlink cycles: `is_dir()` follows symlinks, so a cycle would otherwise
    /// recurse forever — a `visited` set of canonical paths breaks it. This is a
    /// cycle BREAK, not a depth cap (the tree is otherwise traversed in full).
    fn find_file(root: &Path, name: &str) -> std::io::Result<Option<PathBuf>> {
        let mut visited = std::collections::HashSet::new();
        find_file_inner(root, name, &mut visited)
    }

    pub(crate) fn find_file_inner(
        dir: &Path,
        name: &str,
        visited: &mut std::collections::HashSet<PathBuf>,
    ) -> std::io::Result<Option<PathBuf>> {
        // Dedup on the resolved identity so a symlink back to an ancestor is a
        // no-op the second time. If canonicalize fails (broken reparse point,
        // path too long), fall back to the literal path as the key — traverse
        // the dir rather than hide a real target under it, while still deduping.
        let key = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
        if !visited.insert(key) {
            return Ok(None);
        }
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                if let Some(found) = find_file_inner(&path, name, visited)? {
                    return Ok(Some(found));
                }
            } else if path.file_name().is_some_and(|f| f == name) {
                return Ok(Some(path));
            }
        }
        Ok(None)
    }
}

#[cfg(target_os = "macos")]
mod imp_macos {
    use std::path::{Path, PathBuf};

    use super::ExtractedImages;

    /// Subdirectory on the destination volume where the bundle is staged.
    const STAGING_NAME: &str = ".update-staging";
    /// Helper Mach-O inside the `.app` (what the privileged helper runs).
    const HELPER_IN_APP: &str = "Contents/MacOS/hole";
    /// Staged-helper basename, a SIBLING of the staged `.app` (NOT inside it).
    /// The app swap deletes the staged `.app` tree, so the helper must live
    /// outside it or its staging path vanishes before the helper swap.
    const STAGED_HELPER_NAME: &str = "com.hole.bridge.staged";

    pub fn extract(payload_path: &Path, staging_parent: &Path) -> std::io::Result<ExtractedImages> {
        let staging_dir = staging_parent.join(STAGING_NAME);
        if staging_dir.exists() {
            std::fs::remove_dir_all(&staging_dir)?;
        }
        std::fs::create_dir_all(&staging_dir)?;

        let mount = tempfile::TempDir::with_prefix("hole-cutover-mount-")?;
        let attach = std::process::Command::new("hdiutil")
            .args([
                "attach",
                "-nobrowse",
                "-quiet",
                "-mountpoint",
                &mount.path().to_string_lossy(),
                &payload_path.to_string_lossy(),
            ])
            .output()?;
        if !attach.status.success() {
            return Err(std::io::Error::other(format!(
                "hdiutil attach failed: {}",
                String::from_utf8_lossy(&attach.stderr)
            )));
        }

        // Everything after a successful attach must go through detach.
        let result = copy_from_mount(mount.path(), &staging_dir);
        let _ = std::process::Command::new("hdiutil")
            .args(["detach", &mount.path().to_string_lossy()])
            .output();

        let app = result?;
        // Stage the helper as a sibling of the `.app`. It is copied from the
        // bundle's in-app Mach-O, then swapped independently into HELPER_PATH —
        // the app swap deletes the staged `.app`, so a helper path inside it
        // would be gone (ENOENT) by the time the helper swap runs.
        let helper = staging_dir.join(STAGED_HELPER_NAME);
        std::fs::copy(app.join(HELPER_IN_APP), &helper)?;
        Ok(ExtractedImages {
            staging_dir,
            app,
            helper,
        })
    }

    /// Copy the `.app` bundle off the (separate-volume) DMG mount onto the
    /// destination volume so the later swap is same-volume.
    fn copy_from_mount(mount: &Path, staging_dir: &Path) -> std::io::Result<PathBuf> {
        let app_entry = std::fs::read_dir(mount)?
            .filter_map(|e| e.ok())
            .find(|e| e.path().extension().is_some_and(|ext| ext == "app"))
            .ok_or_else(|| std::io::Error::other("no .app bundle found in DMG"))?;
        let app_src = app_entry.path();
        let app_name = app_src
            .file_name()
            .ok_or_else(|| std::io::Error::other("DMG .app entry has no filename"))?;
        let app_dest = staging_dir.join(app_name);

        let out = std::process::Command::new("/bin/cp")
            .args(["-R", &app_src.to_string_lossy(), &app_dest.to_string_lossy()])
            .output()?;
        if !out.status.success() {
            return Err(std::io::Error::other(format!(
                "copy .app off DMG failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Ok(app_dest)
    }
}

#[cfg(test)]
#[path = "extract_tests.rs"]
mod extract_tests;
