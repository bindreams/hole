//! Windows half of [`super::Exclusive`]: `LockFileEx` and handle-based vetting.

use std::fs::File;
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use windows::Win32::Foundation::{ERROR_LOCK_VIOLATION, HANDLE};
use windows::Win32::Storage::FileSystem::{
    GetFileInformationByHandle, GetFileType, LockFileEx, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_TYPE_DISK,
    LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
};
use windows::Win32::System::IO::OVERLAPPED;

use super::{Refusal, Refused};

/// What the open handle says about the lock file; the only input to [`vet`].
#[derive(Clone, Copy, Debug)]
pub(super) struct Facts {
    pub disk_file: bool,
    pub attributes: u32,
    pub links: u32,
}

/// Decides whether an opened file may be used as the lock file.
pub(super) fn vet(facts: Facts) -> Result<(), Refusal> {
    if facts.attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(Refusal::Symlink);
    }
    if !facts.disk_file || facts.attributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0 {
        return Err(Refusal::NotRegular);
    }
    if facts.links != 1 {
        return Err(Refusal::ExtraLinks {
            links: u64::from(facts.links),
        });
    }
    Ok(())
}

fn facts_of(file: &File) -> io::Result<Facts> {
    let handle = HANDLE(file.as_raw_handle());
    // SAFETY: `handle` is a valid, open file handle for the duration of the call.
    let kind = unsafe { GetFileType(handle) };
    if kind != FILE_TYPE_DISK {
        // A device or pipe has no file information to read; `vet` refuses on `disk_file` alone.
        return Ok(Facts {
            disk_file: false,
            attributes: 0,
            links: 1,
        });
    }
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `handle` is a valid, open file handle and `info` a live local, both for the duration of the call.
    unsafe { GetFileInformationByHandle(handle, &mut info) }?;
    Ok(Facts {
        disk_file: true,
        attributes: info.dwFileAttributes,
        links: info.nNumberOfLinks,
    })
}

/// Who is acquiring. Nothing on Windows depends on it.
pub(super) struct Caller;

/// The running process as a [`Caller`].
pub(super) fn caller() -> Caller {
    Caller
}

/// Windows has no direct `O_NOFOLLOW`; the equivalent is to open with
/// `FILE_FLAG_OPEN_REPARSE_POINT` (so `CreateFileW` does not transparently
/// follow a symlink/junction planted at `path`) and then refuse, through the
/// handle, a file that is a reparse point, not a regular disk file, or has
/// more than one link. The `owner` is a POSIX concept and is ignored here.
pub(super) fn open_locked(
    path: &Path,
    block: bool,
    _owner: Option<(u32, u32)>,
    _caller: Caller,
) -> io::Result<Option<File>> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .custom_flags((FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS).0)
        .open(path)
        .map_err(|err| Refused::from_failed_open(path, err))?;

    vet(facts_of(&file)?).map_err(|why| {
        Refused {
            path: path.to_path_buf(),
            why,
        }
        .into_io_error()
    })?;

    let handle = HANDLE(file.as_raw_handle());
    let flags = if block {
        LOCKFILE_EXCLUSIVE_LOCK
    } else {
        LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY
    };
    let mut overlapped = OVERLAPPED::default();
    // SAFETY: `handle` is a valid, open file handle for the duration of
    // this call; `overlapped` is a local, live for the same duration; the
    // lock region (0..=u32::MAX twice) covers the whole file, which is
    // never more than a few hundred bytes of JSON.
    let result = unsafe { LockFileEx(handle, flags, None, u32::MAX, u32::MAX, &mut overlapped) };
    match result {
        Ok(()) => Ok(Some(file)),
        Err(e) => {
            if !block && e.code() == ERROR_LOCK_VIOLATION.to_hresult() {
                return Ok(None);
            }
            Err(io::Error::from(e))
        }
    }
}

/// Windows has no `fchown` equivalent; ownership here is a POSIX-only
/// concept (NTFS ownership is a DACL/SID, set by the caller's install path).
/// Always a no-op.
pub(super) fn chown_fd(_file: &File, _owner: Option<(u32, u32)>) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
