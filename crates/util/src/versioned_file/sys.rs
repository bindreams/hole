//! The platform calls `versioned_file` needs and `std` does not offer: a
//! durable replace, a rename that never replaces, and an advisory file lock.

use std::fs::File;
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

/// Blocks until this handle holds the exclusive lock on its file. The lock is
/// per handle, not per process, and released by [`unlock`] or by closing it.
pub(super) fn lock_exclusive(file: &File) -> io::Result<()> {
    #[cfg(windows)]
    return windows_impl::lock(file, false).map(|_| ());
    #[cfg(unix)]
    return unix_impl::lock(file, false).map(|_| ());
}

/// Whether this handle took the exclusive lock without waiting.
#[cfg(test)]
pub(super) fn try_lock_exclusive(file: &File) -> io::Result<bool> {
    #[cfg(windows)]
    return windows_impl::lock(file, true);
    #[cfg(unix)]
    return unix_impl::lock(file, true);
}

pub(super) fn unlock(file: &File) {
    #[cfg(windows)]
    windows_impl::unlock(file);
    #[cfg(unix)]
    unix_impl::unlock(file);
}

#[cfg(windows)]
pub(super) use windows_impl::io_error;

#[cfg(test)]
#[path = "sys_tests.rs"]
mod sys_tests;

#[cfg(unix)]
mod unix_impl {
    use std::ffi::CString;
    use std::fs::File;
    use std::io;
    use std::os::fd::AsRawFd;
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

    /// The kernel, the filesystem or a seccomp profile does not offer
    /// `renameat2` with the flag. `EPERM` is a profile's answer; a real one
    /// makes the hard-link fallback fail the same way.
    #[cfg(target_os = "linux")]
    pub(super) fn renameat2_unavailable(errno: i32) -> bool {
        matches!(errno, libc::ENOSYS | libc::EINVAL | libc::EOPNOTSUPP | libc::EPERM)
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

    pub(super) fn lock(file: &File, nonblocking: bool) -> io::Result<bool> {
        let op = libc::LOCK_EX | if nonblocking { libc::LOCK_NB } else { 0 };
        loop {
            // SAFETY: the descriptor is open for the call.
            if unsafe { libc::flock(file.as_raw_fd(), op) } == 0 {
                return Ok(true);
            }
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock if nonblocking => return Ok(false),
                _ => return Err(e),
            }
        }
    }

    pub(super) fn unlock(file: &File) {
        // SAFETY: the descriptor is open for the call. Closing the file would
        // release the lock anyway, so a failure here has nothing to act on.
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[cfg(windows)]
mod windows_impl {
    use std::fs::File;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;

    use tempfile::NamedTempFile;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        LockFileEx, MoveFileExW, UnlockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LOCK_FILE_FLAGS,
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MOVE_FILE_FLAGS,
    };
    use windows::Win32::System::IO::OVERLAPPED;

    /// `ERROR_LOCK_VIOLATION`: a `LockFileEx` that would have waited.
    const LOCK_VIOLATION: i32 = 33;

    /// A `windows` error as the `io::Error` of the Win32 code inside it.
    pub(in crate::versioned_file) fn io_error(e: windows::core::Error) -> io::Error {
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

    fn handle(file: &File) -> HANDLE {
        HANDLE(file.as_raw_handle())
    }

    pub(super) fn lock(file: &File, nonblocking: bool) -> io::Result<bool> {
        let flags = LOCKFILE_EXCLUSIVE_LOCK
            | if nonblocking {
                LOCKFILE_FAIL_IMMEDIATELY
            } else {
                LOCK_FILE_FLAGS(0)
            };
        let mut region = OVERLAPPED::default();
        // SAFETY: the handle is open and `region` outlives the call; the lock
        // covers the first byte, which no one reads or writes.
        match unsafe { LockFileEx(handle(file), flags, None, 1, 0, &mut region) } {
            Ok(()) => Ok(true),
            Err(e) => match io_error(e) {
                e if nonblocking && e.raw_os_error() == Some(LOCK_VIOLATION) => Ok(false),
                e => Err(e),
            },
        }
    }

    pub(super) fn unlock(file: &File) {
        let mut region = OVERLAPPED::default();
        // SAFETY: as in `lock`. The system releases the lock when the handle
        // closes, but only eventually; this is the prompt release.
        let _ = unsafe { UnlockFileEx(handle(file), None, 1, 0, &mut region) };
    }
}
