//! Generic ownership primitive: `chown(2)` a path to a uid/gid. Not
//! Hole-specific — a thin, testable wrapper over `libc::chown`. macOS is the
//! only current user; elsewhere it is a no-op so callers stay cfg-free.

use std::path::Path;

#[cfg(target_os = "macos")]
pub fn chown_path(path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL"))?;
    // SAFETY: `c` is a valid NUL-terminated path for the duration of the call.
    let rc = unsafe { libc::chown(c.as_ptr(), uid, gid) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "macos"))]
pub fn chown_path(_path: &Path, _uid: u32, _gid: u32) -> std::io::Result<()> {
    Ok(())
}

/// Best-effort `chown` when an owner is set; a failure is logged and swallowed.
pub fn chown_if_some(path: &Path, owner: Option<(u32, u32)>) {
    if let Some((uid, gid)) = owner {
        if let Err(e) = chown_path(path, uid, gid) {
            tracing::warn!(error = %e, path = %path.display(), "chown failed");
        }
    }
}

#[cfg(test)]
#[path = "ownership_tests.rs"]
mod ownership_tests;
