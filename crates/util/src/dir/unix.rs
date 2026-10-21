//! Unix half of [`super::Dir`]: `openat`, `mkdirat`, `fstatat`, `unlinkat`, `renameat`, `fchown`, `fchmod`.

use std::collections::{HashSet, VecDeque};
use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path};

use super::{EntryKind, OpenFile, Refusal};

/// Who is opening: this process's effective uid.
pub type Caller = u32;

/// The running process as a [`Caller`].
pub(super) fn caller() -> Caller {
    // SAFETY: geteuid takes no arguments and cannot fail.
    unsafe { libc::geteuid() }
}

/// `(device, inode)`.
pub(super) type FileId = (u64, u64);

/// What `fstat` or `fstatat` says; the only input to the trust and kind decisions.
#[derive(Clone, Copy, Debug)]
pub(super) struct Meta {
    pub dev: u64,
    pub ino: u64,
    pub uid: u32,
    pub mode: u32,
}

impl Meta {
    #[allow(clippy::useless_conversion)] // `mode_t` is `u16` on macOS, `u32` on Linux
    fn kind(&self) -> EntryKind {
        match self.mode & u32::from(libc::S_IFMT) {
            m if m == u32::from(libc::S_IFLNK) => EntryKind::Symlink,
            m if m == u32::from(libc::S_IFDIR) => EntryKind::Directory,
            m if m == u32::from(libc::S_IFREG) => EntryKind::File,
            _ => EntryKind::Other,
        }
    }
}

/// Whether a symlink may be followed: root owns it and the directory it sits in, and nobody else can
/// write that directory. Such a link is system configuration (macOS's `/var`, `/tmp`, `/etc`), and
/// no other user can plant one in a directory they cannot write.
pub(super) fn trusted_symlink(link: Meta, parent: Meta) -> bool {
    link.uid == 0 && parent.uid == 0 && parent.mode & 0o022 == 0
}

// libc wrappers -------------------------------------------------------------------------------------------------------

fn cstr(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name contains NUL"))
}

fn check(rc: libc::c_int) -> io::Result<libc::c_int> {
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

fn open_fd(dir: RawFd, name: &CString, flags: libc::c_int, mode: u32) -> io::Result<OwnedFd> {
    // SAFETY: `name` is a valid NUL-terminated string and `dir` an open directory, both for the call.
    let fd = check(unsafe { libc::openat(dir, name.as_ptr(), flags | libc::O_CLOEXEC, mode) })?;
    // SAFETY: `openat` returned a new descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Opens a directory for lookup only, which asks the caller for search permission and not for read: a
/// directory a caller can pass through but not list (`0o311`) is on a usable path. A handle opened
/// this way names children (`openat`, `fstatat`, `mkdirat`, `readlinkat`, `fstat`) and is not for
/// `fchown`, `fchmod` or `fsync`. Other unix: an ordinary read open, which asks for read as well.
#[cfg(target_os = "linux")]
const SEARCH_ONLY: libc::c_int = libc::O_PATH;
#[cfg(target_os = "macos")]
const SEARCH_ONLY: libc::c_int = libc::O_SEARCH;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const SEARCH_ONLY: libc::c_int = libc::O_RDONLY;

/// The directory `name` in `dir`, for lookup only; see [`SEARCH_ONLY`].
fn open_dir_at(dir: RawFd, name: &CString) -> io::Result<OwnedFd> {
    open_fd(dir, name, SEARCH_ONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW, 0)
}

/// `dir` again, for use: readable, so that `fchown`, `fchmod` and `fsync` work on it. Through the
/// handle in hand (`.`), so no path is resolved again.
fn reopen_for_use(dir: RawFd) -> io::Result<OwnedFd> {
    open_fd(
        dir,
        &CString::new(".").expect("no NUL"),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        0,
    )
}

#[allow(clippy::unnecessary_cast, clippy::useless_conversion)] // the stat fields differ in width per platform
fn meta_of(st: &libc::stat) -> Meta {
    Meta {
        dev: st.st_dev as u64,
        ino: st.st_ino as u64,
        uid: st.st_uid,
        mode: u32::from(st.st_mode),
    }
}

fn fstat(fd: RawFd) -> io::Result<Meta> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `fd` is open and `st` is a valid out-pointer.
    check(unsafe { libc::fstat(fd, st.as_mut_ptr()) })?;
    // SAFETY: `fstat` succeeded and filled `st`.
    Ok(meta_of(&unsafe { st.assume_init() }))
}

/// What `name` in `dir` is, not following a symlink.
fn fstatat_nofollow(dir: RawFd, name: &CString) -> io::Result<Meta> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `name` is a valid NUL-terminated string, `dir` is open and `st` is a valid out-pointer.
    check(unsafe { libc::fstatat(dir, name.as_ptr(), st.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) })?;
    // SAFETY: `fstatat` succeeded and filled `st`.
    Ok(meta_of(&unsafe { st.assume_init() }))
}

fn readlink_at(dir: RawFd, name: &CString) -> io::Result<OsString> {
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    // SAFETY: `buf` is valid for `buf.len()` bytes; the rest as above.
    let n = unsafe { libc::readlinkat(dir, name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(n as usize);
    Ok(OsString::from_vec(buf))
}

fn open_start(path: &str) -> io::Result<OwnedFd> {
    open_fd(
        libc::AT_FDCWD,
        &CString::new(path).expect("no NUL"),
        SEARCH_ONLY | libc::O_DIRECTORY,
        0,
    )
}

// Path resolution -----------------------------------------------------------------------------------------------------

enum Step {
    Root,
    Parent,
    Name(OsString),
}

fn steps_of(path: &Path) -> VecDeque<Step> {
    path.components()
        .filter_map(|component| match component {
            Component::RootDir => Some(Step::Root),
            Component::ParentDir => Some(Step::Parent),
            Component::Normal(name) => Some(Step::Name(name.to_os_string())),
            Component::CurDir | Component::Prefix(_) => None,
        })
        .collect()
}

/// Opens the directory `name` in `cur`, or makes progress towards it: `Ok(Some(fd))` is the directory;
/// `Ok(None)` is a followed symlink whose target was put in front of `steps`.
fn descend(
    cur: &OwnedFd,
    name: &OsStr,
    create: bool,
    steps: &mut VecDeque<Step>,
    followed: &mut HashSet<FileId>,
) -> io::Result<Option<OwnedFd>> {
    let cname = cstr(name)?;
    loop {
        let open_err = match open_dir_at(cur.as_raw_fd(), &cname) {
            Ok(fd) => return Ok(Some(fd)),
            Err(err) => err,
        };
        // The errno of a failed no-follow open differs per platform and per kind of entry, so
        // what the entry is decides, not the errno.
        let entry = match fstatat_nofollow(cur.as_raw_fd(), &cname) {
            Ok(entry) => entry,
            Err(err) if err.kind() == io::ErrorKind::NotFound && create => {
                // SAFETY: `cname` is a valid NUL-terminated string and `cur` an open directory.
                match check(unsafe { libc::mkdirat(cur.as_raw_fd(), cname.as_ptr(), 0o777) }) {
                    Ok(_) => {}
                    Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(err) => return Err(err),
                }
                continue;
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Err(err),
            Err(_) => return Err(open_err),
        };
        return match entry.kind() {
            EntryKind::Symlink => {
                let parent = fstat(cur.as_raw_fd())?;
                // A link met twice in one resolution is a loop.
                if !trusted_symlink(entry, parent) || !followed.insert((entry.dev, entry.ino)) {
                    return Err(Refusal::Symlink.into_io_error());
                }
                let target = readlink_at(cur.as_raw_fd(), &cname)?;
                let mut expansion = steps_of(Path::new(&target));
                expansion.append(steps);
                *steps = expansion;
                Ok(None)
            }
            EntryKind::Directory => Err(open_err),
            EntryKind::File | EntryKind::Other => Err(Refusal::NotDirectory.into_io_error()),
        };
    }
}

pub(super) fn open_dir(path: &Path, create: bool, owner: Option<(u32, u32)>, caller: Caller) -> io::Result<File> {
    let mut steps = steps_of(path);
    let mut cur = open_start(if matches!(steps.front(), Some(Step::Root)) {
        "/"
    } else {
        "."
    })?;
    if matches!(steps.front(), Some(Step::Root)) {
        steps.pop_front();
    }
    let mut followed = HashSet::new();
    while let Some(step) = steps.pop_front() {
        match step {
            Step::Root => cur = open_start("/")?,
            Step::Parent => cur = open_dir_at(cur.as_raw_fd(), &CString::new("..").expect("no NUL"))?,
            Step::Name(name) => {
                if let Some(next) = descend(&cur, &name, create, &mut steps, &mut followed)? {
                    cur = next;
                }
            }
        }
    }

    if let Some((uid, _)) = owner {
        let found = fstat(cur.as_raw_fd())?.uid;
        if found != uid && found != caller {
            return Err(Refusal::ForeignOwner { uid: found }.into_io_error());
        }
    }
    Ok(File::from(reopen_for_use(cur.as_raw_fd())?))
}

// Operations relative to a directory ----------------------------------------------------------------------------------

pub(super) fn open_file(dir: &File, name: &OsStr, how: OpenFile) -> io::Result<File> {
    let (flags, mode) = match how {
        OpenFile::CreateNew { mode } => (libc::O_RDWR | libc::O_CREAT | libc::O_EXCL, mode),
        OpenFile::Existing => (libc::O_RDWR, 0),
        OpenFile::Read => (libc::O_RDONLY, 0),
        OpenFile::Append { mode } => (libc::O_WRONLY | libc::O_APPEND | libc::O_CREAT, mode),
    };
    open_fd(dir.as_raw_fd(), &cstr(name)?, flags | libc::O_NOFOLLOW, mode).map(File::from)
}

/// A new file for [`super::Dir::write_atomic`].
pub(super) fn create_temp(dir: &File, name: &OsStr) -> io::Result<File> {
    open_file(dir, name, OpenFile::CreateNew { mode: 0o600 })
}

pub(super) fn id_of(dir: &File, name: &OsStr) -> io::Result<Option<FileId>> {
    match fstatat_nofollow(dir.as_raw_fd(), &cstr(name)?) {
        Ok(meta) => Ok(Some((meta.dev, meta.ino))),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

pub(super) fn kind_of(dir: &File, name: &OsStr) -> io::Result<Option<EntryKind>> {
    match fstatat_nofollow(dir.as_raw_fd(), &cstr(name)?) {
        Ok(meta) => Ok(Some(meta.kind())),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

pub(super) fn file_id(file: &File) -> io::Result<FileId> {
    let meta = file.metadata()?;
    Ok((meta.dev(), meta.ino()))
}

pub(super) fn unlink(dir: &File, name: &OsStr) -> io::Result<()> {
    // SAFETY: the name is a valid NUL-terminated string and `dir` an open directory.
    check(unsafe { libc::unlinkat(dir.as_raw_fd(), cstr(name)?.as_ptr(), 0) }).map(|_| ())
}

/// `from` to `to`, both in `dir`, replacing `to`. `_temp` is the open file at `from`: Windows renames by its handle.
pub(super) fn rename(dir: &File, _temp: &File, from: &OsStr, to: &OsStr) -> io::Result<()> {
    rename_by_name(dir, from, to)
}

/// `from` to `to`, both in `dir`, replacing `to`.
pub(super) fn rename_by_name(dir: &File, from: &OsStr, to: &OsStr) -> io::Result<()> {
    let (from, to) = (cstr(from)?, cstr(to)?);
    // SAFETY: both names are valid NUL-terminated strings and `dir` an open directory.
    check(unsafe { libc::renameat(dir.as_raw_fd(), from.as_ptr(), dir.as_raw_fd(), to.as_ptr()) }).map(|_| ())
}

/// `from` to `to`, both in `dir`, in one step that fails with `AlreadyExists` instead of replacing `to`.
/// `Unsupported` when the kernel or the filesystem has no such rename.
#[cfg(target_os = "linux")]
pub(super) fn rename_noreplace(dir: &File, from: &OsStr, to: &OsStr) -> io::Result<()> {
    let (from, to) = (cstr(from)?, cstr(to)?);
    // SAFETY: both names are valid NUL-terminated strings and `dir` an open directory, all for the call.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            dir.as_raw_fd(),
            from.as_ptr(),
            dir.as_raw_fd(),
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if rc == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        // `EPERM` is not among these: it is a refusal of this rename (a sticky directory, a security
        // module), and the caller's hard-link fallback is allowed where it was not.
        Some(libc::ENOSYS | libc::EINVAL | libc::EOPNOTSUPP) => Err(io::ErrorKind::Unsupported.into()),
        _ => Err(err),
    }
}

#[cfg(target_os = "macos")]
pub(super) fn rename_noreplace(dir: &File, from: &OsStr, to: &OsStr) -> io::Result<()> {
    let (from, to) = (cstr(from)?, cstr(to)?);
    // SAFETY: both names are valid NUL-terminated strings and `dir` an open directory, all for the call.
    let rc = unsafe {
        libc::renameatx_np(
            dir.as_raw_fd(),
            from.as_ptr(),
            dir.as_raw_fd(),
            to.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if rc == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        // The volume does not support `RENAME_EXCL`.
        Some(libc::ENOTSUP | libc::EINVAL) => Err(io::ErrorKind::Unsupported.into()),
        _ => Err(err),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(super) fn rename_noreplace(_dir: &File, _from: &OsStr, _to: &OsStr) -> io::Result<()> {
    Err(io::ErrorKind::Unsupported.into())
}

/// A second name `new` for `existing`, both in `dir`. `linkat` without `AT_SYMLINK_FOLLOW` links a symlink as
/// itself.
pub(super) fn link(dir: &File, existing: &OsStr, new: &OsStr) -> io::Result<()> {
    let (existing, new) = (cstr(existing)?, cstr(new)?);
    // SAFETY: both names are valid NUL-terminated strings and `dir` an open directory.
    check(unsafe { libc::linkat(dir.as_raw_fd(), existing.as_ptr(), dir.as_raw_fd(), new.as_ptr(), 0) }).map(|_| ())
}

/// `fchown`; a failure is logged and swallowed (see [`super::Dir::secure`]).
fn chown_best_effort(file: &File, owner: Option<(u32, u32)>) {
    let Some((uid, gid)) = owner else { return };
    // SAFETY: the descriptor is open for the call.
    if let Err(err) = check(unsafe { libc::fchown(file.as_raw_fd(), uid, gid) }) {
        tracing::warn!(error = %err, "chown failed");
    }
}

pub(super) fn secure_dir(dir: &File, owner: Option<(u32, u32)>, mode: Option<u32>) -> io::Result<()> {
    chown_best_effort(dir, owner);
    match mode {
        Some(mode) => dir.set_permissions(std::fs::Permissions::from_mode(mode)),
        None => Ok(()),
    }
}

pub(super) fn seal(file: &File, owner: Option<(u32, u32)>) -> io::Result<()> {
    chown_best_effort(file, owner);
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
}

#[cfg(test)]
#[path = "unix_tests.rs"]
mod unix_tests;
