//! Extract the bare binaries from the verified MSI/DMG onto the destination
//! volume. The bundle was minisign-verified on download (the GUI's `cli.rs`
//! path), so the extracted bytes are trusted; the bridge confirms the payload is
//! present + readable before doing anything irreversible (fail-closed), and logs
//! a best-effort signature observation as defense-in-depth — NOT a gate (gating
//! on it risks a self-inflicted brick on signing-cert rotation).
//!
//! Same-volume staging is required so the subsequent rename is a directory-entry
//! flip, not a cross-volume copy (Windows) / `EXDEV` (macOS).

use std::path::{Path, PathBuf};

/// Confirm the payload is present and readable before the irreversible steps.
/// Full minisign/SHA verification happened on download (the single verifier in
/// the GUI); re-running it here would require network access mid-cutover. A
/// missing or unreadable payload is rejected fail-closed.
pub fn reverify(payload_path: &Path) -> std::io::Result<()> {
    let meta = std::fs::metadata(payload_path)?;
    if !meta.is_file() {
        return Err(std::io::Error::other(format!(
            "update payload is not a regular file: {payload_path:?}"
        )));
    }
    Ok(())
}

/// Staged binaries extracted onto the destination volume, ready to rename-swap.
#[derive(Debug, Clone)]
pub struct ExtractedImages {
    /// Directory on the destination volume holding the extracted binaries.
    pub staging_dir: PathBuf,
    /// The staged `hole.exe`.
    #[cfg(target_os = "windows")]
    pub exe: PathBuf,
    /// The staged `Hole.app` bundle.
    #[cfg(target_os = "macos")]
    pub app: PathBuf,
    /// The staged helper Mach-O inside the bundle.
    #[cfg(target_os = "macos")]
    pub helper: PathBuf,
}

/// Build the Windows `msiexec /a` admin-install args that extract the MSI's
/// payload (including `hole.exe`) to `target_dir`. Quiet (`/qn`) so no UI.
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
/// volume as the install dir, then locate `hole.exe` under it. macOS: `hdiutil
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
mod imp_windows {
    use std::path::{Path, PathBuf};

    use super::{msiexec_admin_args, ExtractedImages};

    /// Subdirectory where the MSI payload lands (under the same-volume parent).
    const STAGING_NAME: &str = ".update-staging";
    /// Canonical binary the swap pivots on.
    const EXE_NAME: &str = "hole.exe";

    pub fn extract(payload_path: &Path, staging_parent: &Path) -> std::io::Result<ExtractedImages> {
        let staging_dir = staging_parent.join(STAGING_NAME);
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

        let exe = find_file(&staging_dir, EXE_NAME)?.ok_or_else(|| {
            std::io::Error::other(format!("{EXE_NAME} not found in extracted MSI under {staging_dir:?}"))
        })?;
        Ok(ExtractedImages { staging_dir, exe })
    }

    /// Find `name` anywhere under `root` (an MSI lays out files into a versioned
    /// subtree, so the exe is not at a fixed depth).
    fn find_file(root: &Path, name: &str) -> std::io::Result<Option<PathBuf>> {
        for entry in std::fs::read_dir(root)? {
            let path = entry?.path();
            if path.is_dir() {
                if let Some(found) = find_file(&path, name)? {
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
    /// Helper Mach-O inside the staged `.app` (what the privileged helper runs).
    const HELPER_IN_APP: &str = "Contents/MacOS/hole";

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
        let helper = app.join(HELPER_IN_APP);
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
