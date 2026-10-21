//! Windows half of [`super::Dir`]: `NtCreateFile` and `NtSetInformationFile` relative to a directory handle.
//!
//! Win32 has no call that opens or renames relative to a handle, so this goes to the native API (every NT
//! version has it). A component is opened with `FILE_OPEN_REPARSE_POINT`, which opens a symlink or
//! junction as itself, and the handle's attributes then say whether it is one.

use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Component, Path, Prefix};

use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows::Wdk::Storage::FileSystem::{
    FileDispositionInformation, FileRenameInformation, FileRenameInformationEx, NtCreateFile, NtSetInformationFile,
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_DISPOSITION_INFORMATION, FILE_INFORMATION_CLASS, FILE_NON_DIRECTORY_FILE,
    FILE_OPEN, FILE_OPEN_FOR_BACKUP_INTENT, FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION,
    FILE_SYNCHRONOUS_IO_NONALERT, NTCREATEFILE_CREATE_DISPOSITION, NTCREATEFILE_CREATE_OPTIONS,
};
use windows::Win32::Foundation::{
    RtlNtStatusToDosError, ERROR_INVALID_FUNCTION, ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED, HANDLE, NTSTATUS,
    OBJECT_ATTRIBUTE_FLAGS, OBJ_CASE_INSENSITIVE, UNICODE_STRING,
};
use windows::Win32::Storage::FileSystem::{
    GetFileInformationByHandle, GetFileType, BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ACCESS_RIGHTS, FILE_ADD_FILE,
    FILE_ADD_SUBDIRECTORY, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_MODE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_TYPE_DISK, READ_CONTROL, SYNCHRONIZE, WRITE_DAC,
};
use windows::Win32::System::IO::IO_STATUS_BLOCK;

use super::{EntryKind, OpenFile, Refusal};

/// Nothing on Windows depends on who is opening.
pub struct Caller;

/// The running process as a [`Caller`].
pub(super) fn caller() -> Caller {
    Caller
}

/// `(volume serial number, file index)`.
pub(super) type FileId = (u64, u64);

const SHARE_ALL: FILE_SHARE_MODE = FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0);
/// What a file the caller opens shares: everything but `DELETE`, so the name stays bound to the open file.
const SHARE_NO_DELETE: FILE_SHARE_MODE = FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0);

/// The OS error of a failed `NTSTATUS`.
fn nt(status: NTSTATUS) -> io::Result<()> {
    if status.0 >= 0 {
        return Ok(());
    }
    // SAFETY: `RtlNtStatusToDosError` takes a status by value and has no preconditions.
    let code = unsafe { RtlNtStatusToDosError(status) };
    Err(io::Error::from_raw_os_error(code as i32))
}

fn options(flags: &[NTCREATEFILE_CREATE_OPTIONS]) -> NTCREATEFILE_CREATE_OPTIONS {
    NTCREATEFILE_CREATE_OPTIONS(flags.iter().fold(0, |all, flag| all | flag.0))
}

fn access(rights: &[FILE_ACCESS_RIGHTS]) -> FILE_ACCESS_RIGHTS {
    FILE_ACCESS_RIGHTS(rights.iter().fold(0, |all, right| all | right.0))
}

/// `NtCreateFile` of `name` (relative to `root`, or an absolute NT path when `root` is `None`) as a
/// synchronous handle.
fn nt_open(
    root: Option<&File>,
    name: &[u16],
    rights: FILE_ACCESS_RIGHTS,
    share: FILE_SHARE_MODE,
    disposition: NTCREATEFILE_CREATE_DISPOSITION,
    flags: NTCREATEFILE_CREATE_OPTIONS,
) -> io::Result<File> {
    let bytes = u16::try_from(name.len() * 2).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let unicode = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: windows::core::PWSTR(name.as_ptr().cast_mut()),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: root.map_or(HANDLE::default(), |handle| HANDLE(handle.as_raw_handle())),
        ObjectName: &unicode,
        Attributes: OBJECT_ATTRIBUTE_FLAGS(OBJ_CASE_INSENSITIVE.0),
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut handle = HANDLE::default();
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: `attributes` and the `unicode` and `name` it points to outlive the call; the out-pointers are
    // live locals; no extended attributes are passed (null, length 0).
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access(&[rights, SYNCHRONIZE]),
            &attributes,
            &mut status_block,
            None,
            FILE_ATTRIBUTE_NORMAL,
            share,
            disposition,
            options(&[flags, FILE_SYNCHRONOUS_IO_NONALERT]),
            None,
            0,
        )
    };
    nt(status)?;
    // SAFETY: `NtCreateFile` succeeded and returned a handle that nothing else owns.
    Ok(File::from(unsafe { OwnedHandle::from_raw_handle(handle.0) }))
}

fn wide(name: &OsStr) -> io::Result<Vec<u16>> {
    // `:` would name an alternate data stream.
    if name.encode_wide().any(|unit| unit == u16::from(b':')) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "name contains ':'"));
    }
    Ok(name.encode_wide().collect())
}

fn info(handle: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle is open and `info` is a live local, both for the call.
    unsafe { GetFileInformationByHandle(HANDLE(handle.as_raw_handle()), &mut info) }?;
    Ok(info)
}

fn kind_from(handle: &File) -> io::Result<EntryKind> {
    // SAFETY: the handle is open for the call.
    if unsafe { GetFileType(HANDLE(handle.as_raw_handle())) } != FILE_TYPE_DISK {
        return Ok(EntryKind::Other);
    }
    let attributes = info(handle)?.dwFileAttributes;
    Ok(if attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        EntryKind::Symlink
    } else if attributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0 {
        EntryKind::Directory
    } else {
        EntryKind::File
    })
}

// Path resolution -----------------------------------------------------------------------------------------------------

/// The NT path of the root directory a Windows path starts at, and the names below it.
fn split(path: &Path) -> io::Result<(Vec<u16>, VecDeque<OsString>)> {
    let invalid = |why| io::Error::new(io::ErrorKind::InvalidInput, why);
    let absolute = std::path::absolute(path)?;
    let mut components = absolute.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return Err(invalid("expected a path with a drive or share"));
    };
    let root = match prefix.kind() {
        Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => {
            format!(r"\??\{}:\", letter as char).encode_utf16().collect()
        }
        Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => {
            let mut root: Vec<u16> = r"\??\UNC\".encode_utf16().collect();
            root.extend(server.encode_wide());
            root.push(u16::from(b'\\'));
            root.extend(share.encode_wide());
            root.push(u16::from(b'\\'));
            root
        }
        _ => return Err(invalid("unsupported path prefix")),
    };
    let mut names = VecDeque::new();
    for component in components {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => names.push_back(name.to_os_string()),
            _ => return Err(invalid("expected a path without `..`")),
        }
    }
    Ok((root, names))
}

/// Rights to open a directory with: read its attributes (to see a reparse point); a final one also
/// adds files and subdirectories. Listing is not asked for: a directory a user can traverse but not
/// list is still on the path to a file they can reach.
fn dir_rights(last: bool) -> FILE_ACCESS_RIGHTS {
    match last {
        true => access(&[FILE_READ_ATTRIBUTES, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY]),
        false => access(&[FILE_READ_ATTRIBUTES]),
    }
}

const OPEN_AS_ITSELF: &[NTCREATEFILE_CREATE_OPTIONS] = &[FILE_OPEN_REPARSE_POINT, FILE_OPEN_FOR_BACKUP_INTENT];

/// What the entry `name` in `dir` is, whether or not it can be opened for use.
fn classify(dir: &File, name: &[u16]) -> io::Result<Option<EntryKind>> {
    match nt_open(
        Some(dir),
        name,
        access(&[FILE_READ_ATTRIBUTES]),
        SHARE_ALL,
        FILE_OPEN,
        options(OPEN_AS_ITSELF),
    ) {
        Ok(handle) => kind_from(&handle).map(Some),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

/// Opens the directory `name` in `dir`; a missing one is created when `create`.
fn descend(dir: &File, name: &OsStr, create: bool, rights: FILE_ACCESS_RIGHTS) -> io::Result<File> {
    let name = wide(name)?;
    loop {
        let open_err = match nt_open(Some(dir), &name, rights, SHARE_ALL, FILE_OPEN, options(OPEN_AS_ITSELF)) {
            Ok(handle) => match kind_from(&handle)? {
                EntryKind::Directory => return Ok(handle),
                EntryKind::Symlink => return Err(Refusal::Symlink.into_io_error()),
                _ => return Err(Refusal::NotDirectory.into_io_error()),
            },
            Err(err) => err,
        };
        match classify(dir, &name) {
            Ok(None) if create => match nt_open(
                Some(dir),
                &name,
                rights,
                SHARE_ALL,
                FILE_CREATE,
                options(&[FILE_DIRECTORY_FILE, FILE_OPEN_FOR_BACKUP_INTENT]),
            ) {
                Ok(handle) => return Ok(handle),
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(err),
            },
            Ok(None) => return Err(open_err),
            Ok(Some(EntryKind::Symlink)) => return Err(Refusal::Symlink.into_io_error()),
            Ok(Some(EntryKind::Directory)) => return Err(open_err),
            Ok(Some(EntryKind::File | EntryKind::Other)) => return Err(Refusal::NotDirectory.into_io_error()),
            Err(_) => return Err(open_err),
        }
    }
}

pub(super) fn open_dir(path: &Path, create: bool, _owner: Option<(u32, u32)>, _caller: Caller) -> io::Result<File> {
    open_dir_with(path, create, FILE_ACCESS_RIGHTS(0))
}

/// [`open_dir`] with `extra` rights on the final directory.
pub(super) fn open_dir_with(path: &Path, create: bool, extra: FILE_ACCESS_RIGHTS) -> io::Result<File> {
    let rights_for = |last| match last {
        true => access(&[dir_rights(true), extra]),
        false => dir_rights(false),
    };
    let (root, mut names) = split(path)?;
    let mut current = nt_open(
        None,
        &root,
        rights_for(names.is_empty()),
        SHARE_ALL,
        FILE_OPEN,
        options(OPEN_AS_ITSELF),
    )?;
    if kind_from(&current)? != EntryKind::Directory {
        return Err(Refusal::NotDirectory.into_io_error());
    }
    while let Some(name) = names.pop_front() {
        current = descend(&current, &name, create, rights_for(names.is_empty()))?;
    }
    Ok(current)
}

// Operations relative to a directory ----------------------------------------------------------------------------------

pub(super) fn open_file(dir: &File, name: &OsStr, how: OpenFile) -> io::Result<File> {
    open_file_with(dir, name, how, FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0)
}

fn open_file_with(dir: &File, name: &OsStr, how: OpenFile, rights: u32) -> io::Result<File> {
    let (disposition, flags) = match how {
        OpenFile::CreateNew { .. } => (
            FILE_CREATE,
            options(&[
                FILE_NON_DIRECTORY_FILE,
                FILE_OPEN_FOR_BACKUP_INTENT,
                FILE_OPEN_REPARSE_POINT,
            ]),
        ),
        OpenFile::Existing => (FILE_OPEN, options(OPEN_AS_ITSELF)),
    };
    nt_open(
        Some(dir),
        &wide(name)?,
        FILE_ACCESS_RIGHTS(rights),
        SHARE_NO_DELETE,
        disposition,
        flags,
    )
}

/// A new file for [`super::Dir::write_atomic`]: opened for `DELETE`, which renaming it needs, and
/// `WRITE_DAC`, for the ACL its `protect` step sets (the creator is always allowed it).
pub(super) fn create_temp(dir: &File, name: &OsStr) -> io::Result<File> {
    open_file_with(
        dir,
        name,
        OpenFile::CreateNew { mode: 0o600 },
        FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | DELETE.0 | WRITE_DAC.0,
    )
}

pub(super) fn id_of(dir: &File, name: &OsStr) -> io::Result<Option<FileId>> {
    match nt_open(
        Some(dir),
        &wide(name)?,
        access(&[FILE_READ_ATTRIBUTES]),
        SHARE_ALL,
        FILE_OPEN,
        options(OPEN_AS_ITSELF),
    ) {
        Ok(handle) => file_id(&handle).map(Some),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

pub(super) fn kind_of(dir: &File, name: &OsStr) -> io::Result<Option<EntryKind>> {
    classify(dir, &wide(name)?)
}

pub(super) fn file_id(file: &File) -> io::Result<FileId> {
    let info = info(file)?;
    Ok((
        u64::from(info.dwVolumeSerialNumber),
        u64::from(info.nFileIndexHigh) << 32 | u64::from(info.nFileIndexLow),
    ))
}

pub(super) fn unlink(dir: &File, name: &OsStr) -> io::Result<()> {
    let handle = nt_open(
        Some(dir),
        &wide(name)?,
        access(&[DELETE]),
        SHARE_ALL,
        FILE_OPEN,
        options(OPEN_AS_ITSELF),
    )?;
    let disposition = FILE_DISPOSITION_INFORMATION { DeleteFile: true };
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: the handle is open with `DELETE`; `disposition` is a live local of the size passed.
    let status = unsafe {
        NtSetInformationFile(
            HANDLE(handle.as_raw_handle()),
            &mut status_block,
            (&raw const disposition).cast(),
            size_of::<FILE_DISPOSITION_INFORMATION>() as u32,
            FileDispositionInformation,
        )
    };
    nt(status)
}

/// `FILE_RENAME_REPLACE_IF_EXISTS`, and with `FILE_RENAME_POSIX_SEMANTICS`: the target is replaced
/// even while another handle has it open (that handle keeps the old file). The second needs Windows 10
/// version 1607 and a volume that supports it (NTFS does).
const REPLACE: u32 = 0x1;
const REPLACE_POSIX: u32 = 0x1 | 0x2;

/// Renames `temp`, the open file named `_from`, to `to` in `dir`, replacing `to`. The rename is by
/// the handle, so it moves that file whatever its name has become. With POSIX semantics where the
/// volume has them; a volume that rejects them (`ERROR_INVALID_PARAMETER` measured on a 9P volume,
/// `ERROR_NOT_SUPPORTED`, `ERROR_INVALID_FUNCTION`: the three `util`'s `versioned_file` reads the same
/// way) gets the plain replace, which fails while another handle has the target open.
pub(super) fn rename(dir: &File, temp: &File, _from: &OsStr, to: &OsStr) -> io::Result<()> {
    let to = wide(to)?;
    match rename_with(dir, temp, &to, FileRenameInformationEx, REPLACE_POSIX) {
        Err(err) if posix_rename_unsupported(&err) => rename_with(dir, temp, &to, FileRenameInformation, REPLACE),
        result => result,
    }
}

fn posix_rename_unsupported(err: &io::Error) -> bool {
    let Some(code) = err.raw_os_error() else { return false };
    [ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED, ERROR_INVALID_FUNCTION]
        .iter()
        .any(|unsupported| unsupported.0 as i32 == code)
}

fn rename_with(dir: &File, temp: &File, to: &[u16], class: FILE_INFORMATION_CLASS, flags: u32) -> io::Result<()> {
    let header = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
    let name_bytes = to.len() * 2;
    let size = header + name_bytes;
    // `u64` units: aligned for the handle inside, and zeroed.
    let mut buffer = vec![0u64; size.div_ceil(8).max(size_of::<FILE_RENAME_INFORMATION>().div_ceil(8))];
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    // SAFETY: `buffer` is zeroed, 8-aligned and at least `size` bytes; the name is copied to where
    // `FileName` starts, inside it.
    unsafe {
        (*info).Anonymous.Flags = flags;
        (*info).RootDirectory = HANDLE(dir.as_raw_handle());
        (*info).FileNameLength = name_bytes as u32;
        std::ptr::copy_nonoverlapping(
            to.as_ptr(),
            buffer.as_mut_ptr().cast::<u8>().add(header).cast::<u16>(),
            to.len(),
        );
    }
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: the handle is open with `DELETE`; the buffer holds a `FILE_RENAME_INFORMATION` of `size` bytes
    // whose root directory is open for the call.
    let status = unsafe {
        NtSetInformationFile(
            HANDLE(temp.as_raw_handle()),
            &mut status_block,
            buffer.as_ptr().cast(),
            size as u32,
            class,
        )
    };
    nt(status)
}

/// No unix ids or modes: the access control of a Windows file is its ACL, set through [`super::Dir::file`].
pub(super) fn secure_dir(_dir: &File, _owner: Option<(u32, u32)>, _mode: Option<u32>) -> io::Result<()> {
    Ok(())
}

/// No unix ids or modes; see [`secure_dir`].
pub(super) fn seal(_file: &File, _owner: Option<(u32, u32)>) -> io::Result<()> {
    Ok(())
}

/// The right to read and rewrite the directory's ACL; opening for use does not ask for it.
pub(super) const ACL_RIGHTS: FILE_ACCESS_RIGHTS = FILE_ACCESS_RIGHTS(WRITE_DAC.0 | READ_CONTROL.0);

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
