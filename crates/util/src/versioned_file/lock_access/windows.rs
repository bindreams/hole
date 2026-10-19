//! Windows: the lock's DACL is the guarded file's, cut down to what the lock
//! needs. Each allow ACE that gives write is kept for its principal as read
//! and write; each deny ACE is kept; nothing else is, and nothing is
//! inherited. The owner always keeps the lock, through OWNER RIGHTS.
//!
//! The lock is created by `CreateFileW(CREATE_NEW)` carrying that DACL, so
//! access is checked against it at every open there ever is, and the normal
//! share mode is enough: no one can hold a handle the DACL would not have
//! given them. A file made first and narrowed after would leave the
//! directory's inherited DACL in force for the first opener, and Windows checks
//! access at open time, so that handle would keep it.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::FromRawHandle;
use std::path::Path;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows::Win32::Security::{
    AclSizeInformation, AddAce, GetAce, GetAclInformation, InitializeAcl, InitializeSecurityDescriptor,
    SetSecurityDescriptorControl, SetSecurityDescriptorDacl, ACL, ACL_REVISION, ACL_SIZE_INFORMATION,
    DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
    SECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE,
};

use crate::versioned_file::sys::io_error;

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;
/// The ACE does not apply to the object itself, only to what is created in it.
const INHERIT_ONLY_ACE: u8 = 0x08;

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const GENERIC_READ_WRITE: u32 = 0x8000_0000 | 0x4000_0000;
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

const FILE_WRITE_DATA: u32 = 0x2;
const FILE_APPEND_DATA: u32 = 0x4;
const WRITE_DAC: u32 = 0x4_0000;
const WRITE_OWNER: u32 = 0x8_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
/// What the lock needs, and no `DELETE`: deleting the lock file would let two
/// writers lock two different files.
const FILE_GENERIC_READ: u32 = 0x12_0089;
const FILE_GENERIC_WRITE: u32 = 0x12_0116;
const LOCK_RIGHTS: u32 = FILE_GENERIC_READ | FILE_GENERIC_WRITE;

/// A mask that lets its holder change the file's bytes, or grant itself that.
const WRITES: u32 = FILE_WRITE_DATA | FILE_APPEND_DATA | WRITE_DAC | WRITE_OWNER | GENERIC_ALL | GENERIC_WRITE;

/// `S-1-1-0`, as SID bytes.
const EVERYONE: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
/// `S-1-3-4`, OWNER RIGHTS: the owner of the object, whoever that is.
const OWNER_RIGHTS: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 3, 4, 0, 0, 0];

/// The principals that may write one file, as the ACEs of the lock's DACL.
pub(in crate::versioned_file) struct Writers {
    aces: Vec<Vec<u8>>,
}

impl Writers {
    /// Those of `reference`, the file being guarded or about to be. `NotFound`
    /// when there is no such entry; a link is an entry, and its writers are its
    /// owner alone: `store` replaces the link, and `remove` and `move_aside`
    /// act on the name, whatever it points at.
    pub(in crate::versioned_file) fn of(reference: &Path) -> io::Result<Self> {
        let mut aces = Vec::new();
        if std::fs::symlink_metadata(reference)?.is_symlink() {
            aces.push(allow(&OWNER_RIGHTS, LOCK_RIGHTS | WRITE_DAC));
            return Ok(Self { aces });
        }
        match read_aces(reference)? {
            // No DACL at all grants every access to everyone.
            None => aces.push(allow(&EVERYONE, LOCK_RIGHTS)),
            Some(found) => aces.extend(found.iter().filter_map(|ace| for_lock(ace))),
        }
        aces.push(allow(&OWNER_RIGHTS, LOCK_RIGHTS | WRITE_DAC));
        Ok(Self { aces })
    }

    /// Makes the lock file at `path` with exactly this DACL: `AlreadyExists`
    /// when anything is there, a link included. `after_creation` runs at the
    /// first instant, before anything is changed.
    pub(in crate::versioned_file) fn create(
        &self,
        path: &Path,
        after_creation: impl FnOnce(&File),
    ) -> io::Result<File> {
        let acl = build_acl(&self.aces)?;
        let mut descriptor = std::mem::MaybeUninit::<SECURITY_DESCRIPTOR>::zeroed();
        let descriptor_ptr = PSECURITY_DESCRIPTOR(descriptor.as_mut_ptr() as *mut _);
        // SAFETY: `descriptor` is zeroed storage of the size the struct names,
        // and `acl` outlives the call that makes the file, the only reader.
        unsafe {
            InitializeSecurityDescriptor(descriptor_ptr, SECURITY_DESCRIPTOR_REVISION).map_err(io_error)?;
            SetSecurityDescriptorDacl(descriptor_ptr, true, Some(acl.as_ptr() as *const ACL), false)
                .map_err(io_error)?;
            // Unprotected, the directory's inheritable ACEs would join it.
            SetSecurityDescriptorControl(descriptor_ptr, SE_DACL_PROTECTED, SE_DACL_PROTECTED).map_err(io_error)?;
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor_ptr.0,
            bInheritHandle: false.into(),
        };
        let name = wide(path);
        // SAFETY: `name` is NUL-terminated and `attributes` names a valid
        // descriptor, both alive for the call.
        let handle = unsafe {
            CreateFileW(
                PCWSTR(name.as_ptr()),
                GENERIC_READ_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                Some(&attributes),
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
        }
        .map_err(io_error)?;
        // SAFETY: a handle `CreateFileW` just returned, owned by nothing else.
        let file = unsafe { File::from_raw_handle(handle.0) };
        after_creation(&file);
        Ok(file)
    }

    /// Gives the file at `path` exactly this DACL, whatever it has now.
    fn apply(&self, path: &Path) -> io::Result<()> {
        set_aces(path, &self.aces)
    }

    /// [`apply`](Self::apply), unless the file already has it: a writer that
    /// is not the owner can open the lock but could not change it.
    pub(in crate::versioned_file) fn conform(&self, _file: &File, path: &Path) -> io::Result<()> {
        if read_aces(path)?.as_deref() == Some(&self.aces[..]) {
            return Ok(());
        }
        self.apply(path)
    }
}

/// Opens the lock file at `path` for reading and writing. `NotFound` only when
/// there is nothing at `path`: a link, even a dangling one, is opened as the
/// link and refused. A directory is refused by the open itself.
pub(in crate::versioned_file) fn open_existing(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)?;
    let attributes = file.metadata()?.file_attributes();
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the lock path is a symbolic link or other reparse point",
        ));
    }
    Ok(file)
}

fn allow(sid: &[u8], mask: u32) -> Vec<u8> {
    let mut ace = vec![ACCESS_ALLOWED_ACE_TYPE, 0];
    ace.extend(((8 + sid.len()) as u16).to_le_bytes());
    ace.extend(mask.to_le_bytes());
    ace.extend(sid);
    ace
}

fn mask(ace: &[u8]) -> u32 {
    u32::from_le_bytes([ace[4], ace[5], ace[6], ace[7]])
}

/// What the lock keeps of one ACE of the guarded file's DACL, if anything.
/// An ACE kind that is not plainly an allow or a deny is dropped: the lock
/// errs towards fewer principals.
fn for_lock(ace: &[u8]) -> Option<Vec<u8>> {
    if ace[1] & INHERIT_ONLY_ACE != 0 {
        return None;
    }
    match ace[0] {
        ACCESS_DENIED_ACE_TYPE => {
            let mut kept = ace.to_vec();
            kept[1] = 0;
            Some(kept)
        }
        ACCESS_ALLOWED_ACE_TYPE if mask(ace) & WRITES != 0 => Some(allow(&ace[8..], LOCK_RIGHTS)),
        _ => None,
    }
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn win32(code: u32) -> io::Error {
    io::Error::from_raw_os_error(code as i32)
}

/// Every ACE of `path`'s DACL, in order; `None` for a file with no DACL.
fn read_aces(path: &Path) -> io::Result<Option<Vec<Vec<u8>>>> {
    let name = wide(path);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `name` is NUL-terminated; the out pointers are valid locals.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(name.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            &mut descriptor,
        )
    };
    if rc.0 != 0 {
        return Err(win32(rc.0));
    }
    let found = if dacl.is_null() {
        Ok(None)
    } else {
        copy_aces(dacl).map(Some)
    };
    // SAFETY: the descriptor came from `GetNamedSecurityInfoW`, and `copy_aces`
    // copied what it needed out of it.
    unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
    found
}

fn copy_aces(dacl: *mut ACL) -> io::Result<Vec<Vec<u8>>> {
    let mut size = ACL_SIZE_INFORMATION::default();
    // SAFETY: `dacl` is a valid ACL and `size` is the struct this class fills.
    unsafe {
        GetAclInformation(
            dacl,
            &mut size as *mut _ as *mut _,
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    }
    .map_err(io::Error::other)?;
    let mut aces = Vec::with_capacity(size.AceCount as usize);
    for index in 0..size.AceCount {
        let mut ace = std::ptr::null_mut();
        // SAFETY: `index` is below the ACE count.
        unsafe { GetAce(dacl, index, &mut ace) }.map_err(io::Error::other)?;
        let header = ace as *const u8;
        // SAFETY: an ACE starts with a header whose third and fourth bytes are its size.
        let len = unsafe { u16::from_le_bytes([*header.add(2), *header.add(3)]) } as usize;
        // SAFETY: the ACE is `len` bytes long, inside the ACL.
        aces.push(unsafe { std::slice::from_raw_parts(header, len) }.to_vec());
    }
    Ok(aces)
}

/// An ACL of exactly `aces`, as `u32`s: an ACL is DWORD-aligned.
fn build_acl(aces: &[Vec<u8>]) -> io::Result<Vec<u32>> {
    let total = 8 + aces.iter().map(Vec::len).sum::<usize>();
    let mut buffer = vec![0u32; total.div_ceil(4)];
    let acl = buffer.as_mut_ptr() as *mut ACL;
    // SAFETY: `buffer` is `total` aligned bytes, the room for the header and every ACE.
    unsafe { InitializeAcl(acl, total as u32, ACL_REVISION) }.map_err(io::Error::other)?;
    for ace in aces {
        // SAFETY: each ACE is a whole, valid ACE of the length it names.
        unsafe { AddAce(acl, ACL_REVISION, u32::MAX, ace.as_ptr() as *const _, ace.len() as u32) }
            .map_err(io::Error::other)?;
    }
    Ok(buffer)
}

/// Replaces `path`'s DACL with exactly `aces`, and stops it inheriting.
fn set_aces(path: &Path, aces: &[Vec<u8>]) -> io::Result<()> {
    let acl = build_acl(aces)?;
    let name = wide(path);
    // SAFETY: `name` is NUL-terminated and `acl` is a valid ACL.
    let rc = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(name.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(acl.as_ptr() as *const ACL),
            None,
        )
    };
    match rc.0 {
        0 => Ok(()),
        code => Err(win32(code)),
    }
}
