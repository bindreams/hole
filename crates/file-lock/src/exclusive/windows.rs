//! Windows half of [`super::Exclusive`]: `LockFileEx` and handle-based vetting.

use std::fs::File;
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use windows::Win32::Foundation::{ERROR_LOCK_VIOLATION, HANDLE};
use windows::Win32::Storage::FileSystem::{
    GetFileInformationByHandle, GetFileType, LockFileEx, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_TYPE_DISK, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
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

/// Opens the lock name without following a reparse point and shares everything but
/// `DELETE`, so nobody can remove or rename the name while the handle is open.
/// `Ok(None)` when the name vanished between the two opens.
fn open_name(path: &Path) -> io::Result<Option<File>> {
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .write(true)
        .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE).0)
        .custom_flags((FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS).0);
    match options.clone().create_new(true).open(path) {
        Ok(file) => return Ok(Some(file)),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(Refused::from_failed_open(path, err)),
    }
    match options.open(path) {
        Ok(file) => Ok(Some(file)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(Refused::from_failed_open(path, err)),
    }
}

/// Opens the lock file, vets the handle and locks it; see the module doc for the
/// protocol. `owner` is ignored.
pub(super) fn open_locked(
    path: &Path,
    block: bool,
    _owner: Option<(u32, u32)>,
    _caller: Caller,
) -> io::Result<Option<File>> {
    let file = loop {
        if let Some(file) = open_name(path)? {
            break file;
        }
    };

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
    // SAFETY: `handle` and `overlapped` are valid for the call; the lock region (0..=u64::MAX)
    // covers the whole file.
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

/// No-op: NTFS ownership is a DACL/SID set by the install path.
pub(super) fn chown_fd(_file: &File, _owner: Option<(u32, u32)>) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
