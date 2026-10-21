//! Replace one file by another in a single filesystem call.

use std::io;
use std::path::Path;

/// Moves `staged` onto `dest`, replacing it even when it is read-only. A reader that opened
/// `dest` with share-delete access (as `std` does) keeps its old content; a holder without it
/// fails the replace with `ERROR_SHARING_VIOLATION`, and a running image with
/// `ERROR_ACCESS_DENIED`.
///
/// Unix `rename(2)` does this. Windows `std::fs::rename` fails with "Access is denied" over a
/// read-only `dest` (its POSIX-semantics rename omits the flag that ignores the attribute), so
/// Windows issues that rename itself. On a filesystem that refuses POSIX rename it falls back to
/// `std::fs::rename`, which cannot replace a read-only `dest` there.
pub(super) fn replace_file(staged: &Path, dest: &Path) -> io::Result<()> {
    #[cfg(windows)]
    return windows_impl::replace_file(staged, dest);
    #[cfg(not(windows))]
    return std::fs::rename(staged, dest);
}

#[cfg(windows)]
mod windows_impl {
    use std::io;
    use std::mem::offset_of;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;

    use ::windows::Win32::Foundation::HANDLE;
    use ::windows::Win32::Storage::FileSystem::{
        FileRenameInfoEx, SetFileInformationByHandle, DELETE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_RENAME_INFO,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    // `FILE_RENAME_INFORMATION.Flags`, documented in ntifs.h; the `windows` crate omits them.
    const FILE_RENAME_FLAG_REPLACE_IF_EXISTS: u32 = 0x1;
    const FILE_RENAME_FLAG_POSIX_SEMANTICS: u32 = 0x2;
    const FILE_RENAME_FLAG_IGNORE_READONLY_ATTRIBUTE: u32 = 0x40;

    // What a filesystem without POSIX rename answers: `ERROR_INVALID_PARAMETER` is measured on a
    // 9P volume (`hole_util::versioned_file::sys`); `std` reads all three as "POSIX semantics
    // unsupported" for the POSIX-semantics delete.
    const ERROR_INVALID_FUNCTION: i32 = 1;
    const ERROR_NOT_SUPPORTED: i32 = 50;
    const ERROR_INVALID_PARAMETER: i32 = 87;

    pub(super) fn replace_file(staged: &Path, dest: &Path) -> io::Result<()> {
        replace_with(staged, dest, posix_rename, |staged, dest| std::fs::rename(staged, dest))
    }

    /// Replaces with `posix`, or with `fallback` when `posix` answers that the OS or filesystem
    /// does not implement it. Any other error is returned.
    pub(super) fn replace_with(
        staged: &Path,
        dest: &Path,
        posix: impl FnOnce(&Path, &Path) -> io::Result<()>,
        fallback: impl FnOnce(&Path, &Path) -> io::Result<()>,
    ) -> io::Result<()> {
        match posix(staged, dest) {
            Err(e) if refuses_posix_rename(&e) => fallback(staged, dest),
            result => result,
        }
    }

    /// Whether `e` says the OS or filesystem does not implement `FileRenameInfoEx` with POSIX
    /// semantics (Windows before 10 1809; FAT and the like). These are the three codes std's
    /// `File::delete` takes as "POSIX semantics unsupported" for the same family of calls:
    /// `ERROR_INVALID_FUNCTION`, `ERROR_NOT_SUPPORTED` and `ERROR_INVALID_PARAMETER`.
    pub(super) fn refuses_posix_rename(e: &io::Error) -> bool {
        matches!(
            e.raw_os_error(),
            Some(ERROR_INVALID_FUNCTION | ERROR_NOT_SUPPORTED | ERROR_INVALID_PARAMETER)
        )
    }

    /// The `io::Error` of a failed Win32 call, whose `windows` error carries `HRESULT_FROM_WIN32(code)`.
    /// `io::Error::from` would keep the whole HRESULT as the OS error, so no code would match.
    pub(super) fn win32_error(e: ::windows::core::Error) -> io::Error {
        let hresult = e.code().0 as u32;
        const FACILITY_WIN32: u32 = 0x8007_0000;
        match hresult & 0xFFFF_0000 == FACILITY_WIN32 {
            true => io::Error::from_raw_os_error((hresult & 0xFFFF) as i32),
            false => io::Error::other(e),
        }
    }

    /// The `FileName` of the rename: `dest` made absolute (`.`, `..` resolved) and in verbatim
    /// form, `\\?\` or `\\?\UNC\`, which lifts MAX_PATH. No terminating NUL.
    pub(super) fn target_name(dest: &Path) -> io::Result<Vec<u16>> {
        let absolute: Vec<u16> = std::path::absolute(dest)?.as_os_str().encode_wide().collect();
        let starts_with = |prefix: &str| absolute.starts_with(&prefix.encode_utf16().collect::<Vec<u16>>());

        // Verbatim and device paths are already in the form the call reads as is.
        if starts_with(r"\\?\") || starts_with(r"\\.\") {
            return Ok(absolute);
        }
        let (prefix, rest) = match starts_with(r"\\") {
            true => (r"\\?\UNC\", &absolute[2..]),
            false => (r"\\?\", &absolute[..]),
        };
        let mut wide: Vec<u16> = prefix.encode_utf16().collect();
        wide.extend_from_slice(rest);
        Ok(wide)
    }

    fn posix_rename(staged: &Path, dest: &Path) -> io::Result<()> {
        let target = target_name(dest)?;
        let name_bytes = target.len() * 2;

        // The entry itself (not a link target) is renamed; DELETE is the right a rename needs.
        let handle = std::fs::OpenOptions::new()
            .access_mode(DELETE.0)
            .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(staged)?;

        // `FILE_RENAME_INFO` is a header followed by the name; the zeroed tail is its NUL.
        let size = offset_of!(FILE_RENAME_INFO, FileName) + name_bytes + 2;
        let too_long = || io::Error::new(io::ErrorKind::InvalidInput, "dest path is too long");
        let size_u32 = u32::try_from(size).map_err(|_| too_long())?;
        let name_bytes_u32 = u32::try_from(name_bytes).map_err(|_| too_long())?;
        let mut buffer = vec![0_u64; size.div_ceil(size_of::<u64>())];
        let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        // SAFETY: `buffer` is 8-aligned, zeroed and `size` bytes long, which holds the header
        // and `target`; `info` is not used after the call, and `buffer` outlives it.
        unsafe {
            (*info).Anonymous.Flags = FILE_RENAME_FLAG_REPLACE_IF_EXISTS
                | FILE_RENAME_FLAG_POSIX_SEMANTICS
                | FILE_RENAME_FLAG_IGNORE_READONLY_ATTRIBUTE;
            (*info).FileNameLength = name_bytes_u32;
            std::ptr::copy_nonoverlapping(
                target.as_ptr(),
                std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
                target.len(),
            );
            SetFileInformationByHandle(HANDLE(handle.as_raw_handle()), FileRenameInfoEx, info.cast(), size_u32)
        }
        .map_err(win32_error)
    }
}

#[cfg(all(test, windows))]
#[path = "replace_tests.rs"]
mod replace_tests;
