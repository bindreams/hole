//! Replace one file by another in a single filesystem call.

use std::io;
use std::path::Path;

/// Moves `staged` onto `dest`, replacing it whatever its attributes. A reader that already holds
/// `dest` keeps its old content.
///
/// Unix `rename(2)` does this. Windows `std::fs::rename` fails with "Access is denied" over a
/// read-only `dest` (its POSIX-semantics rename omits the flag that ignores the attribute), so
/// Windows issues that rename itself.
pub(super) fn replace_file(staged: &Path, dest: &Path) -> io::Result<()> {
    #[cfg(windows)]
    return windows::replace_file(staged, dest);
    #[cfg(not(windows))]
    return std::fs::rename(staged, dest);
}

#[cfg(windows)]
mod windows {
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

    const ERROR_INVALID_FUNCTION: i32 = 1;
    const ERROR_NOT_SUPPORTED: i32 = 50;
    const ERROR_INVALID_PARAMETER: i32 = 87;

    pub(super) fn replace_file(staged: &Path, dest: &Path) -> io::Result<()> {
        match posix_rename(staged, dest) {
            Err(e) if refuses_posix_rename(&e) => std::fs::rename(staged, dest),
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

    fn posix_rename(staged: &Path, dest: &Path) -> io::Result<()> {
        // `FileName` must be an absolute path. A verbatim one also lifts MAX_PATH.
        let parent = dest
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "dest has no parent directory"))?;
        let file_name = dest
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "dest has no file name"))?;
        let target: Vec<u16> = std::fs::canonicalize(parent)?
            .join(file_name)
            .as_os_str()
            .encode_wide()
            .collect();
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
