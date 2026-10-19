//! The platform calls `versioned_file` needs and `std` does not offer: a
//! replace that an open reader cannot block and a rename that never replaces.

use std::io;
use std::path::Path;

use tempfile::NamedTempFile;

/// Renames the temp file over `dest`, even while another handle has `dest`
/// open: that reader keeps the old file, and the next open gets the new one.
/// On Windows, a volume without POSIX rename (FAT, exFAT, some network shares)
/// gets `MoveFileExW` instead, which fails while a reader has `dest` open.
/// The caller syncs the directory to make the rename durable.
pub(super) fn publish(tmp: NamedTempFile, dest: &Path) -> io::Result<()> {
    #[cfg(windows)]
    return windows_impl::replace(tmp, dest);
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
    use std::fs::OpenOptions;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;

    use tempfile::NamedTempFile;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{ERROR_INVALID_FUNCTION, ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        FileRenameInfoEx, MoveFileExW, SetFileInformationByHandle, DELETE, FILE_RENAME_INFO, MOVEFILE_REPLACE_EXISTING,
        MOVEFILE_WRITE_THROUGH,
    };

    /// `FILE_RENAME_FLAG_REPLACE_IF_EXISTS` and `FILE_RENAME_FLAG_POSIX_SEMANTICS`
    /// of `FILE_RENAME_INFO::Flags`. With both, the target is replaced even
    /// while it has open handles: they keep the replaced file, and every later
    /// open of the name gets the renamed one. Needs Windows 10 version 1607 and
    /// a volume that supports it (NTFS does); elsewhere the replace falls back
    /// to `MoveFileExW`, which an open reader can make fail.
    const REPLACE_POSIX: u32 = 0x1 | 0x2;

    /// A `windows` error as the `io::Error` of the Win32 code inside it.
    fn io_error(e: windows::core::Error) -> io::Error {
        // An `HRESULT_FROM_WIN32` value keeps the Win32 code in its low word.
        match e.code().0 as u32 >> 16 {
            0x8007 => io::Error::from_raw_os_error((e.code().0 as u32 & 0xFFFF) as i32),
            _ => io::Error::other(e),
        }
    }

    pub(super) fn replace(tmp: NamedTempFile, dest: &Path) -> io::Result<()> {
        publish_with(tmp, dest, rename_posix, rename_replace_legacy)
    }

    /// Renames the temp file over `dest` with `posix`, or with `legacy` when
    /// `posix` answers that the volume does not support it. Any other error
    /// is returned, and the temp file is removed on every failure.
    pub(super) fn publish_with(
        tmp: NamedTempFile,
        dest: &Path,
        posix: impl FnOnce(&Path, &Path) -> io::Result<()>,
        legacy: impl FnOnce(&Path, &Path) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut from = tmp.into_temp_path();
        match posix(&from, dest) {
            Err(e) if posix_rename_unsupported(&e) => legacy(&from, dest)?,
            result => result?,
        }
        // Moved: the temp name is no longer ours to delete.
        from.disable_cleanup(true);
        Ok(())
    }

    /// The volume or the OS rejects `FileRenameInfoEx` with POSIX semantics:
    /// `ERROR_INVALID_PARAMETER` (measured on a 9P volume), `ERROR_NOT_SUPPORTED`
    /// or `ERROR_INVALID_FUNCTION`. `std` reads the same three as "unsupported"
    /// for the POSIX-semantics delete, which FAT32 refuses the same way.
    pub(super) fn posix_rename_unsupported(e: &io::Error) -> bool {
        let Some(code) = e.raw_os_error() else { return false };
        [ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED, ERROR_INVALID_FUNCTION]
            .iter()
            .any(|unsupported| unsupported.0 as i32 == code)
    }

    pub(super) fn rename_replace_legacy(from: &Path, to: &Path) -> io::Result<()> {
        let wide = |p: &Path| p.as_os_str().encode_wide().chain(Some(0)).collect::<Vec<u16>>();
        let (from, to) = (wide(from), wide(to));
        // SAFETY: both buffers are NUL-terminated and outlive the call.
        unsafe {
            MoveFileExW(
                PCWSTR(from.as_ptr()),
                PCWSTR(to.as_ptr()),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        }
        .map_err(io_error)
    }

    fn rename_posix(from: &Path, to: &Path) -> io::Result<()> {
        // `DELETE` is the access a rename needs; `std` shares read, write and
        // delete, so an existing reader of `from` does not conflict.
        let file = OpenOptions::new().access_mode(DELETE.0).open(from)?;

        let name: Vec<u16> = to.as_os_str().encode_wide().collect();
        let name_bytes = name.len() * 2;
        let header = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
        let size = header + name_bytes;
        // `u64` units: the buffer is aligned for `FILE_RENAME_INFO`'s handle.
        let mut buf = vec![0u64; size.div_ceil(8)];
        let info = buf.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        // SAFETY: `buf` is zeroed, 8-aligned and at least `header + name_bytes`
        // long; the name is copied after the header, where `FileName` starts.
        unsafe {
            (*info).Anonymous.Flags = REPLACE_POSIX;
            (*info).FileNameLength = name_bytes as u32;
            std::ptr::copy_nonoverlapping(
                name.as_ptr(),
                buf.as_mut_ptr().cast::<u8>().add(header).cast::<u16>(),
                name.len(),
            );
            SetFileInformationByHandle(
                HANDLE(file.as_raw_handle()),
                FileRenameInfoEx,
                info.cast_const().cast(),
                size as u32,
            )
        }
        .map_err(io_error)
    }

    /// Fails with `AlreadyExists` when `to` exists, and is written through.
    pub(super) fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
        let wide = |p: &Path| p.as_os_str().encode_wide().chain(Some(0)).collect::<Vec<u16>>();
        let (from, to) = (wide(from), wide(to));
        // SAFETY: both buffers are NUL-terminated and outlive the call.
        unsafe { MoveFileExW(PCWSTR(from.as_ptr()), PCWSTR(to.as_ptr()), MOVEFILE_WRITE_THROUGH) }.map_err(io_error)
    }
}
