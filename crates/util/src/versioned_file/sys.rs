//! The platform calls `versioned_file` needs and `std` does not offer: a
//! durable replace and a rename that never replaces.

use std::io;
use std::path::Path;

use tempfile::NamedTempFile;

/// Renames the temp file over `dest`. On Windows the move is written through,
/// so the rename is durable when this returns; on unix the caller syncs the
/// directory.
pub(super) fn publish(tmp: NamedTempFile, dest: &Path) -> io::Result<()> {
    #[cfg(windows)]
    return windows_impl::replace_write_through(tmp, dest);
    #[cfg(not(windows))]
    return tmp.persist(dest).map(|_| ()).map_err(|e| e.error);
}

/// Renames `from` to `to`, failing with `AlreadyExists` instead of replacing
/// `to`, in one atomic step. `Unsupported` when the platform or the
/// filesystem cannot do that: the caller must not fall back to an
/// exists-then-rename check, which is the race this call closes.
pub(super) fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(windows)]
    return windows_impl::rename_noreplace(from, to);
    #[cfg(unix)]
    return unix_impl::rename_noreplace(from, to);
}

#[cfg(test)]
#[path = "sys_tests.rs"]
mod sys_tests;

#[cfg(unix)]
mod unix_impl {
    use std::ffi::CString;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn c_path(path: &Path) -> io::Result<CString> {
        CString::new(path.as_os_str().as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
    }

    #[cfg(target_os = "linux")]
    pub(super) fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
        let (from, to) = (c_path(from)?, c_path(to)?);
        // SAFETY: both are valid NUL-terminated paths for the duration of the call.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                from.as_ptr(),
                libc::AT_FDCWD,
                to.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if rc == 0 {
            return Ok(());
        }
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            Some(errno) if renameat2_unavailable(errno) => Err(io::Error::from(io::ErrorKind::Unsupported)),
            _ => Err(e),
        }
    }

    /// The kernel or the filesystem does not offer `renameat2` with the flag.
    /// `EPERM` is not among these: it is a refusal of this rename (a sticky
    /// directory, a security module), and the hard-link fallback is allowed
    /// where it was not and leaves its backup when the delete is refused.
    #[cfg(target_os = "linux")]
    pub(super) fn renameat2_unavailable(errno: i32) -> bool {
        matches!(errno, libc::ENOSYS | libc::EINVAL | libc::EOPNOTSUPP)
    }

    #[cfg(target_os = "macos")]
    pub(super) fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
        let (from, to) = (c_path(from)?, c_path(to)?);
        // SAFETY: both are valid NUL-terminated paths for the duration of the call.
        let rc = unsafe { libc::renamex_np(from.as_ptr(), to.as_ptr(), libc::RENAME_EXCL) };
        if rc == 0 {
            return Ok(());
        }
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            // The volume does not support `RENAME_EXCL`.
            Some(libc::ENOTSUP | libc::EINVAL) => Err(io::Error::from(io::ErrorKind::Unsupported)),
            _ => Err(e),
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub(super) fn rename_noreplace(_from: &Path, _to: &Path) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

#[cfg(windows)]
mod windows_impl {
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use tempfile::NamedTempFile;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MOVE_FILE_FLAGS,
    };

    /// A `windows` error as the `io::Error` of the Win32 code inside it.
    fn io_error(e: windows::core::Error) -> io::Error {
        // An `HRESULT_FROM_WIN32` value keeps the Win32 code in its low word.
        match e.code().0 as u32 >> 16 {
            0x8007 => io::Error::from_raw_os_error((e.code().0 as u32 & 0xFFFF) as i32),
            _ => io::Error::other(e),
        }
    }

    fn move_file(from: &Path, to: &Path, flags: MOVE_FILE_FLAGS) -> io::Result<()> {
        let wide = |p: &Path| p.as_os_str().encode_wide().chain(Some(0)).collect::<Vec<u16>>();
        let (from, to) = (wide(from), wide(to));
        // SAFETY: both buffers are NUL-terminated and outlive the call.
        unsafe { MoveFileExW(PCWSTR(from.as_ptr()), PCWSTR(to.as_ptr()), flags) }.map_err(io_error)
    }

    /// `MOVEFILE_WRITE_THROUGH` is what makes the move durable before the call
    /// returns; the replace itself is what `persist` does.
    pub(super) fn replace_write_through(tmp: NamedTempFile, dest: &Path) -> io::Result<()> {
        let mut from = tmp.into_temp_path();
        move_file(&from, dest, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)?;
        // Moved: the temp name is no longer ours to delete.
        from.disable_cleanup(true);
        Ok(())
    }

    /// Without `MOVEFILE_REPLACE_EXISTING` the move fails when `to` exists.
    pub(super) fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
        move_file(from, to, MOVEFILE_WRITE_THROUGH)
    }
}
