//! Windows half of [`super::Dir`]: `NtCreateFile` and `NtSetInformationFile` relative to a directory handle.
//!
//! Win32 has no call that opens or renames relative to a handle, so this goes to the native API (every NT
//! version has it). A component is opened with `FILE_OPEN_REPARSE_POINT`, which opens a symlink or
//! junction as itself, and the handle's attributes then say whether it is one.

use std::collections::{HashSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Component, Path, Prefix};

use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows::Wdk::Storage::FileSystem::{
    FileDispositionInformation, FileDispositionInformationEx, FileLinkInformation, FileRenameInformation,
    FileRenameInformationEx, NtCreateFile, NtSetInformationFile, FILE_CREATE, FILE_DIRECTORY_FILE,
    FILE_DISPOSITION_DELETE, FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE, FILE_DISPOSITION_INFORMATION,
    FILE_DISPOSITION_INFORMATION_EX, FILE_DISPOSITION_INFORMATION_EX_FLAGS, FILE_DISPOSITION_POSIX_SEMANTICS,
    FILE_INFORMATION_CLASS, FILE_LINK_INFORMATION, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_FOR_BACKUP_INTENT,
    FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION, FILE_SYNCHRONOUS_IO_NONALERT,
    NTCREATEFILE_CREATE_DISPOSITION, NTCREATEFILE_CREATE_OPTIONS,
};
use windows::Win32::Foundation::{
    LocalFree, RtlNtStatusToDosError, ERROR_INVALID_FUNCTION, ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED,
    ERROR_SUCCESS, HANDLE, HLOCAL, NTSTATUS, OBJECT_ATTRIBUTE_FLAGS, OBJ_CASE_INSENSITIVE, UNICODE_STRING,
};
use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows::Win32::Security::{GetLengthSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};
use windows::Win32::Storage::FileSystem::{
    GetFileInformationByHandle, GetFileType, BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ACCESS_RIGHTS, FILE_ADD_FILE,
    FILE_ADD_SUBDIRECTORY, FILE_APPEND_DATA, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK, FILE_WRITE_ATTRIBUTES, READ_CONTROL,
    SYNCHRONIZE, WRITE_DAC,
};
use windows::Win32::System::Ioctl::FSCTL_GET_REPARSE_POINT;
use windows::Win32::System::IO::{DeviceIoControl, IO_STATUS_BLOCK};

use super::trail::{Folder, Owner, Trail};
use super::{EntryKind, OpenFile, Refusal};

mod link;
use link::{Sid, Step};

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

// Owners --------------------------------------------------------------------------------------------------------------

/// Who owns what `file` is open on, which must be open with `READ_CONTROL`.
pub(super) fn owner_of(file: &File) -> io::Result<Owner<Sid>> {
    let mut owner = PSID::default();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: the handle is open with `READ_CONTROL`; the out-pointers are live locals.
    let status = unsafe {
        GetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            Some(&mut descriptor),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status.0 as i32));
    }
    let bytes = (!owner.0.is_null()).then(|| {
        // SAFETY: `owner` points into `descriptor`, a valid SID, until it is freed below.
        unsafe { std::slice::from_raw_parts(owner.0.cast::<u8>(), GetLengthSid(owner) as usize) }.to_vec()
    });
    // SAFETY: `descriptor` was allocated by `GetSecurityInfo` for the caller to free, and nothing
    // points into it any more.
    unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
    bytes
        .map(|bytes| link::classify(&bytes))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "the file has no owner"))
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

/// Rights to open a directory with: read its attributes (to see a reparse point) and its owner (to
/// judge a link); a final one also adds files and subdirectories. Listing is not asked for: a
/// directory a user can traverse but not list is still on the path to a file they can reach.
fn dir_rights(last: bool) -> FILE_ACCESS_RIGHTS {
    match last {
        true => access(&[FILE_READ_ATTRIBUTES, READ_CONTROL, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY]),
        false => access(&[FILE_READ_ATTRIBUTES, READ_CONTROL]),
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

/// How a directory was reached, to open it again.
enum Entry {
    /// An NT root such as `\??\C:\`.
    Root(Vec<u16>),
    /// A name in the directory above it.
    Name(Vec<u16>),
}

/// A directory the walk stands in.
struct Standing {
    file: File,
    made: bool,
    entry: Entry,
    /// Opened with the rights a final directory needs. A directory the walk came back to through `..` was not.
    complete: bool,
}

impl Standing {
    /// The directory as the rule judges it.
    fn folder(&self) -> io::Result<Folder<Sid>> {
        match self.made {
            true => Ok(Folder::Made),
            false => owner_of(&self.file).map(Folder::Existing),
        }
    }
}

/// What the walk has left to do, what it has followed, and the directories it is inside of.
struct Walk {
    steps: VecDeque<Step>,
    trail: Trail<Sid>,
    /// Links already followed in this walk; one met twice is a loop.
    followed: HashSet<FileId>,
    /// From the root to the directory the walk stands in, which is the last.
    stack: Vec<Standing>,
}

impl Walk {
    fn here(&self) -> &Standing {
        self.stack.last().expect("a walk always stands in a directory")
    }
}

/// The NT root `root` as a directory.
fn open_root(root: &[u16], rights: FILE_ACCESS_RIGHTS, complete: bool) -> io::Result<Standing> {
    let file = nt_open(None, root, rights, SHARE_ALL, FILE_OPEN, options(OPEN_AS_ITSELF))?;
    if kind_from(&file)? != EntryKind::Directory {
        return Err(Refusal::NotDirectory.into_io_error());
    }
    Ok(Standing {
        file,
        made: false,
        entry: Entry::Root(root.to_vec()),
        complete,
    })
}

/// The reparse data of the link `link` is open on, as `FSCTL_GET_REPARSE_POINT` returns it.
fn reparse_data(link: &File) -> io::Result<Vec<u8>> {
    /// `MAXIMUM_REPARSE_DATA_BUFFER_SIZE`.
    const MAXIMUM: usize = 16 * 1024;
    let mut buffer = vec![0u8; MAXIMUM];
    let mut returned = 0u32;
    // SAFETY: the handle is open and synchronous; `buffer` is valid for the length passed and `returned`
    // is a live local.
    unsafe {
        DeviceIoControl(
            HANDLE(link.as_raw_handle()),
            FSCTL_GET_REPARSE_POINT,
            None,
            0,
            Some(buffer.as_mut_ptr().cast()),
            MAXIMUM as u32,
            Some(&mut returned),
            None,
        )
    }?;
    buffer.truncate(returned as usize);
    Ok(buffer)
}

/// Follows the link `link` (open as itself, with `READ_CONTROL`), which sits in the directory the walk
/// stands in: judges it, and puts what it points at in front of the walk's steps.
fn follow(walk: &mut Walk, link: &File) -> io::Result<()> {
    let dir_owner = owner_of(&walk.here().file)?;
    walk.trail
        .follow(&dir_owner, &owner_of(link)?)
        .map_err(Refusal::into_io_error)?;
    if !walk.followed.insert(file_id(link)?) {
        return Err(Refusal::Symlink.into_io_error());
    }
    let mut expansion = link::steps_of_reparse_data(&reparse_data(link)?).map_err(Refusal::into_io_error)?;
    expansion.append(&mut walk.steps);
    walk.steps = expansion;
    Ok(())
}

/// Opens the directory `name` in the directory the walk stands in (a missing one is created when `create`), or
/// makes progress towards it: `Ok(Some(next))` is the directory; `Ok(None)` is a followed link whose target was
/// put in front of the walk's steps.
fn descend(
    walk: &mut Walk,
    name: &OsStr,
    create: bool,
    rights: FILE_ACCESS_RIGHTS,
    last: bool,
) -> io::Result<Option<Standing>> {
    let name = wide(name)?;
    loop {
        let cur = &walk.here().file;
        let open_err = match nt_open(Some(cur), &name, rights, SHARE_ALL, FILE_OPEN, options(OPEN_AS_ITSELF)) {
            Ok(handle) => {
                return match kind_from(&handle)? {
                    EntryKind::Directory => Ok(Some(Standing {
                        file: handle,
                        made: false,
                        entry: Entry::Name(name),
                        complete: last,
                    })),
                    EntryKind::Symlink => follow(walk, &handle).map(|()| None),
                    _ => Err(Refusal::NotDirectory.into_io_error()),
                };
            }
            Err(err) => err,
        };
        // The rights for use may be what was refused; what the entry is decides.
        match classify(cur, &name) {
            Ok(None) if create => {
                walk.trail
                    .create_in(&walk.here().folder()?)
                    .map_err(Refusal::into_io_error)?;
                match nt_open(
                    Some(&walk.here().file),
                    &name,
                    rights,
                    SHARE_ALL,
                    FILE_CREATE,
                    options(&[FILE_DIRECTORY_FILE, FILE_OPEN_FOR_BACKUP_INTENT]),
                ) {
                    Ok(handle) => {
                        return Ok(Some(Standing {
                            file: handle,
                            made: true,
                            entry: Entry::Name(name),
                            complete: last,
                        }));
                    }
                    Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(err) => return Err(err),
                }
            }
            Ok(None) => return Err(open_err),
            Ok(Some(EntryKind::Symlink)) => {
                let link = nt_open(
                    Some(cur),
                    &name,
                    access(&[FILE_READ_ATTRIBUTES, READ_CONTROL]),
                    SHARE_ALL,
                    FILE_OPEN,
                    options(OPEN_AS_ITSELF),
                )?;
                follow(walk, &link)?;
                return Ok(None);
            }
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
    let (root, names) = split(path)?;
    let mut walk = Walk {
        steps: names.into_iter().map(Step::Name).collect(),
        trail: Trail::new(),
        followed: HashSet::new(),
        stack: Vec::new(),
    };
    let first = open_root(&root, rights_for(walk.steps.is_empty()), walk.steps.is_empty())?;
    walk.stack.push(first);
    while let Some(step) = walk.steps.pop_front() {
        let last = walk.steps.is_empty();
        match step {
            Step::Root(root) => walk.stack = vec![open_root(&root, rights_for(last), last)?],
            Step::Parent => {
                if walk.stack.len() < 2 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "a link leads above its root",
                    ));
                }
                walk.stack.pop();
            }
            Step::Name(name) => {
                if let Some(next) = descend(&mut walk, &name, create, rights_for(last), last)? {
                    walk.stack.push(next);
                }
            }
        }
    }

    walk.trail
        .end_at(&walk.here().folder()?)
        .map_err(Refusal::into_io_error)?;
    let end = walk.stack.pop().expect("a walk always stands in a directory");
    match end.complete {
        true => Ok(end.file),
        false => reopen_complete(&walk, end, rights_for(true)),
    }
}

/// `end`, which the walk came back to through `..` and so holds for lookup only, opened again with `rights`: from
/// the directory above it by the name it was entered by, and checked to be the same directory.
fn reopen_complete(walk: &Walk, end: Standing, rights: FILE_ACCESS_RIGHTS) -> io::Result<File> {
    let again = match &end.entry {
        Entry::Root(root) => nt_open(None, root, rights, SHARE_ALL, FILE_OPEN, options(OPEN_AS_ITSELF))?,
        Entry::Name(name) => nt_open(
            Some(&walk.here().file),
            name,
            rights,
            SHARE_ALL,
            FILE_OPEN,
            options(OPEN_AS_ITSELF),
        )?,
    };
    if file_id(&again)? != file_id(&end.file)? || kind_from(&again)? != EntryKind::Directory {
        return Err(Refusal::Symlink.into_io_error());
    }
    Ok(again)
}

// Operations relative to a directory ----------------------------------------------------------------------------------

pub(super) fn open_file(dir: &File, name: &OsStr, how: OpenFile) -> io::Result<File> {
    open_file_with(dir, name, how, FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0)
}

fn open_file_with(dir: &File, name: &OsStr, how: OpenFile, rights: u32) -> io::Result<File> {
    let own_file = [
        FILE_NON_DIRECTORY_FILE,
        FILE_OPEN_FOR_BACKUP_INTENT,
        FILE_OPEN_REPARSE_POINT,
    ];
    let (rights, share, disposition, flags) = match how {
        OpenFile::CreateNew { .. } => (rights, SHARE_NO_DELETE, FILE_CREATE, options(&own_file)),
        OpenFile::Existing => (rights, SHARE_NO_DELETE, FILE_OPEN, options(OPEN_AS_ITSELF)),
        OpenFile::Read => (FILE_GENERIC_READ.0, SHARE_ALL, FILE_OPEN, options(&own_file)),
        // `FILE_APPEND_DATA` without `FILE_WRITE_DATA`: every write lands at the end.
        OpenFile::Append { .. } => (
            FILE_APPEND_DATA.0 | FILE_READ_ATTRIBUTES.0,
            SHARE_ALL,
            FILE_OPEN_IF,
            options(&own_file),
        ),
    };
    let file = nt_open(
        Some(dir),
        &wide(name)?,
        FILE_ACCESS_RIGHTS(rights),
        share,
        disposition,
        flags,
    )?;
    // Opened as itself, a symlink is the link and not what it points at: it is not a file to read or append to.
    if matches!(how, OpenFile::Read | OpenFile::Append { .. }) && kind_from(&file)? == EntryKind::Symlink {
        return Err(Refusal::Symlink.into_io_error());
    }
    Ok(file)
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
    let handle = open_for_delete(dir, name)?;
    // `unlinkat` without `AT_REMOVEDIR` does not remove a directory, and this must not either (a symlink to one is
    // a link and goes, as `DeleteFile` has it).
    if kind_from(&handle)? == EntryKind::Directory {
        return Err(io::ErrorKind::IsADirectory.into());
    }
    // With POSIX semantics the name goes at once, even while a reader that shares delete has the file open; a
    // volume without them (the three codes `posix_rename_unsupported` reads) gets the delete that waits for the
    // last handle.
    posix_or_legacy(|| set_disposition(&handle, true), || set_disposition(&handle, false))
}

/// The entry `name` as itself, open for `DELETE`, which unlinking and renaming it need (and for its attributes, to
/// tell what it is).
fn open_for_delete(dir: &File, name: &OsStr) -> io::Result<File> {
    nt_open(
        Some(dir),
        &wide(name)?,
        access(&[DELETE, FILE_READ_ATTRIBUTES]),
        SHARE_ALL,
        FILE_OPEN,
        options(OPEN_AS_ITSELF),
    )
}

/// `FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS | FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE` (as
/// `std::fs::remove_file`), or with `posix` false the plain `DeleteFile` that waits for the last handle.
fn set_disposition(handle: &File, posix: bool) -> io::Result<()> {
    let mut status_block = IO_STATUS_BLOCK::default();
    let status = match posix {
        // SAFETY: the handle is open with `DELETE`; the info is a live local of the size passed.
        true => unsafe {
            let info = FILE_DISPOSITION_INFORMATION_EX {
                Flags: FILE_DISPOSITION_INFORMATION_EX_FLAGS(
                    FILE_DISPOSITION_DELETE.0
                        | FILE_DISPOSITION_POSIX_SEMANTICS.0
                        | FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE.0,
                ),
            };
            NtSetInformationFile(
                HANDLE(handle.as_raw_handle()),
                &mut status_block,
                (&raw const info).cast(),
                size_of::<FILE_DISPOSITION_INFORMATION_EX>() as u32,
                FileDispositionInformationEx,
            )
        },
        // SAFETY: as above.
        false => unsafe {
            let info = FILE_DISPOSITION_INFORMATION { DeleteFile: true };
            NtSetInformationFile(
                HANDLE(handle.as_raw_handle()),
                &mut status_block,
                (&raw const info).cast(),
                size_of::<FILE_DISPOSITION_INFORMATION>() as u32,
                FileDispositionInformation,
            )
        },
    };
    nt(status)
}

/// `FILE_RENAME_REPLACE_IF_EXISTS`, and with `FILE_RENAME_POSIX_SEMANTICS`: the target is replaced
/// even while another handle has it open (that handle keeps the old file). The second needs Windows 10
/// version 1607 and a volume that supports it (NTFS does).
const REPLACE: u32 = 0x1;
const REPLACE_POSIX: u32 = 0x1 | 0x2;
/// Neither: the target must not exist.
const NO_REPLACE: u32 = 0;

/// Renames `temp`, the open file named `_from`, to `to` in `dir`, replacing `to`. The rename is by
/// the handle, so it moves that file whatever its name has become. With POSIX semantics where the
/// volume has them; a volume that rejects them (`ERROR_INVALID_PARAMETER` measured on a 9P volume,
/// `ERROR_NOT_SUPPORTED`, `ERROR_INVALID_FUNCTION`) gets the plain replace, which fails while another
/// handle has the target open.
pub(super) fn rename(dir: &File, temp: &File, _from: &OsStr, to: &OsStr) -> io::Result<()> {
    let to = wide(to)?;
    posix_or_legacy(
        || set_name(dir, temp, &to, FileRenameInformationEx, REPLACE_POSIX),
        || set_name(dir, temp, &to, FileRenameInformation, REPLACE),
    )
}

/// `posix`, or `legacy` when `posix` answers that the volume does not support it. Any other error is returned.
fn posix_or_legacy(posix: impl FnOnce() -> io::Result<()>, legacy: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
    match posix() {
        Err(err) if posix_rename_unsupported(&err) => legacy(),
        result => result,
    }
}

/// [`rename`] for a file known by its name, which is opened as itself (a symlink is renamed, not what it points at).
pub(super) fn rename_by_name(dir: &File, from: &OsStr, to: &OsStr) -> io::Result<()> {
    rename(dir, &open_for_delete(dir, from)?, from, to)
}

/// `from` to `to` in `dir`, failing with `AlreadyExists` instead of replacing `to`.
pub(super) fn rename_noreplace(dir: &File, from: &OsStr, to: &OsStr) -> io::Result<()> {
    set_name(
        dir,
        &open_for_delete(dir, from)?,
        &wide(to)?,
        FileRenameInformation,
        NO_REPLACE,
    )
}

/// A second name `new` in `dir` for the file `existing`, failing with `AlreadyExists` if `new` is taken. Needs a
/// volume with hard links (NTFS does).
pub(super) fn link(dir: &File, existing: &OsStr, new: &OsStr) -> io::Result<()> {
    let source = nt_open(
        Some(dir),
        &wide(existing)?,
        access(&[FILE_WRITE_ATTRIBUTES]),
        SHARE_ALL,
        FILE_OPEN,
        options(OPEN_AS_ITSELF),
    )?;
    set_name(dir, &source, &wide(new)?, FileLinkInformation, NO_REPLACE)
}

fn posix_rename_unsupported(err: &io::Error) -> bool {
    let Some(code) = err.raw_os_error() else { return false };
    [ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED, ERROR_INVALID_FUNCTION]
        .iter()
        .any(|unsupported| unsupported.0 as i32 == code)
}

/// Sets the name of `file` to `to` in `dir`, with `flags` and the `class` of information that takes them:
/// `FILE_RENAME_INFORMATION` and `FILE_LINK_INFORMATION` have one layout, which is why one buffer serves both.
fn set_name(dir: &File, file: &File, to: &[u16], class: FILE_INFORMATION_CLASS, flags: u32) -> io::Result<()> {
    const _: () = assert!(
        std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName)
            == std::mem::offset_of!(FILE_LINK_INFORMATION, FileName)
            && size_of::<FILE_RENAME_INFORMATION>() == size_of::<FILE_LINK_INFORMATION>()
    );
    let header = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
    let name_bytes = to.len() * 2;
    // At least the whole struct, whose `FileName[1]` a one-character name does not reach.
    let size = (header + name_bytes).max(size_of::<FILE_RENAME_INFORMATION>());
    // `u64` units: aligned for the handle inside, and zeroed.
    let mut buffer = vec![0u64; size.div_ceil(8)];
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
    // SAFETY: the handle is open with the right the class needs; the buffer holds the information of `size` bytes
    // whose root directory is open for the call.
    let status = unsafe {
        NtSetInformationFile(
            HANDLE(file.as_raw_handle()),
            &mut status_block,
            buffer.as_ptr().cast(),
            size as u32,
            class,
        )
    };
    nt(status)
}

/// No unix ids; see [`secure_dir`].
pub(super) fn give_file(_file: &File, _owner: Option<(u32, u32)>) {}

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
