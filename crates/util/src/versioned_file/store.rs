//! Reading and writing one versioned file.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::{frame, CannotRead, Chain, ChainError, VersionedState};
use crate::dir::{Dir, EntryKind, ReadDir, Staged};
use crate::parse_error::ParseFailure;

/// The file-system calls the type makes, so a test can fail or hold one
/// without touching the rest. Every method defaults to the real call, through
/// the directory handle the type holds: a name is always a single name inside
/// it.
///
/// Reachable outside this crate only with the `test-support` feature.
pub trait Fs: Send + Sync {
    fn remove_file(&self, dir: &Dir, name: &OsStr) -> io::Result<()> {
        dir.unlink(name)
    }

    /// `Unsupported` when the platform cannot rename without replacing.
    fn rename_noreplace(&self, dir: &Dir, from: &OsStr, to: &OsStr) -> io::Result<()> {
        dir.rename_noreplace(from, to)
    }

    /// The vouched read: a file the folder's owner cannot vouch for is refused (`Refusal::ForeignFile`).
    fn read(&self, dir: &ReadDir, name: &OsStr) -> io::Result<Vec<u8>> {
        dir.read_vouched(name)
    }

    /// What the name holds, asked once after a read of it failed.
    fn kind_of(&self, dir: &ReadDir, name: &OsStr) -> io::Result<Option<EntryKind>> {
        dir.kind_of(name)
    }

    fn hard_link(&self, dir: &Dir, original: &OsStr, link: &OsStr) -> io::Result<()> {
        dir.link(original, link)
    }

    fn publish(&self, staged: Staged<'_>) -> io::Result<()> {
        staged.publish()
    }
}

struct StdFs;

impl Fs for StdFs {}

/// What differs per file about where and how it is written, and is not the
/// type's business: the directory's owner, the file's owner and ACL.
///
/// The directory is opened once, without following a symlink, and every step
/// goes through that handle ([`Dir`]): the state directory may belong to the
/// user whose privileged writer this is, so no step is a path.
pub trait Placement {
    fn owner(&self) -> Option<(u32, u32)> {
        None
    }

    /// The owner the staged file is given when it will replace the file at `name` (unix; Windows has no such pair).
    /// By default [`owner`](Self::owner); a placement that keeps a file's owner answers the replaced file's, `None`
    /// when `name` is absent. An error here fails the write before anything is staged.
    fn file_owner(&self, _dir: &Dir, _name: &OsStr) -> io::Result<Option<(u32, u32)>> {
        Ok(self.owner())
    }

    /// Before anything is written: the directory exists (the type created it)
    /// and is as it should be. By default it is handed to [`owner`](Self::owner).
    fn prepare_dir(&self, dir: &Dir) -> io::Result<()> {
        dir.secure(self.owner(), None)
    }

    /// The temp file is complete, synced and not yet published, and already
    /// owned by [`owner`](Self::owner) with mode `0600` (unix): set the rest of
    /// its mode and its ACL here, through its own handle. On Windows do not set
    /// `FILE_ATTRIBUTE_READONLY`: no later `store` could replace the file.
    fn prepare_tmp(&self, _tmp: &File) -> io::Result<()> {
        Ok(())
    }

    /// The new file is in place. Not for its mode, owner or ACL: use
    /// [`prepare_tmp`](Placement::prepare_tmp). Nothing here may act on `name`
    /// by anything but the handle: it is the user's to swap.
    fn after_publish(&self, _dir: &Dir, _name: &OsStr) -> io::Result<()> {
        Ok(())
    }

    /// Whether `update` and `create_new` open the directory with the right to rewrite its ACL (Windows), for a
    /// `prepare_dir` that protects it. Not consulted on other platforms; `observe` never asks for it.
    fn open_for_acl(&self) -> bool {
        false
    }

    /// Makes the rename durable: the directory's buffers are flushed. On
    /// Windows that is `FlushFileBuffers` on a handle to the directory, and
    /// Microsoft does not document it as committing a rename: the durability
    /// of the replace there rests on that reading, not on a documented
    /// guarantee. A volume with no directory flush (an SMB share or a 9P
    /// volume on Windows; a filesystem without directory fsync on unix) is
    /// `Ok`, and the durability there is whatever the volume gives.
    fn sync_dir(&self, dir: &Dir) -> io::Result<()> {
        sync_dir(dir)
    }
}

/// Flushes the directory. A filesystem that offers no directory flush (see
/// [`no_directory_flush`]) is not an error.
fn sync_dir(dir: &Dir) -> io::Result<()> {
    sync_dir_with(dir, Dir::sync)
}

/// [`sync_dir`] over an injectable flush, so the tolerance is tested where it
/// is wired.
fn sync_dir_with(dir: &Dir, flush: impl FnOnce(&Dir) -> io::Result<()>) -> io::Result<()> {
    tolerate_missing_directory_flush(flush(dir))
}

fn tolerate_missing_directory_flush(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(e) if no_directory_flush(&e) => Ok(()),
        result => result,
    }
}

/// The volume has no directory flush. Windows: `ERROR_INVALID_FUNCTION`
/// (measured on an SMB share and on a 9P volume) or `ERROR_NOT_SUPPORTED`.
/// Unix: `EINVAL`, which `fsync(2)` documents for a file that does not
/// support synchronization, or `ENOTSUP`/`EOPNOTSUPP`.
fn no_directory_flush(e: &io::Error) -> bool {
    let Some(code) = e.raw_os_error() else { return false };
    #[cfg(windows)]
    let unsupported = {
        use windows::Win32::Foundation::{ERROR_INVALID_FUNCTION, ERROR_NOT_SUPPORTED};
        [ERROR_INVALID_FUNCTION.0 as i32, ERROR_NOT_SUPPORTED.0 as i32]
    };
    #[cfg(unix)]
    let unsupported = [libc::EINVAL, libc::ENOTSUP, libc::EOPNOTSUPP];
    unsupported.contains(&code)
}

/// [`Placement`] with only an owner.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultPlacement {
    pub owner: Option<(u32, u32)>,
}

impl Placement for DefaultPlacement {
    fn owner(&self) -> Option<(u32, u32)> {
        self.owner
    }
}

/// [`Placement`] that leaves a replaced file with its owner: the staged file takes the owner of the file it replaces
/// (a new file: the writer's), and the directory is never chowned. For a file a user's account may own, where the
/// writer rewrites it without changing whose it is. A file that is not a regular file with one name (a symlink, a hard
/// link a user planted) has no owner to keep, and the write fails: it would otherwise let that entry choose the owner.
#[derive(Debug, Clone, Copy, Default)]
pub struct KeepOwner;

impl Placement for KeepOwner {
    fn file_owner(&self, dir: &Dir, name: &OsStr) -> io::Result<Option<(u32, u32)>> {
        dir.owner_of(name)
    }

    fn prepare_dir(&self, _dir: &Dir) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The file on disk is newer or corrupt and its role refuses to replace it.
    /// The text names the file, never its directory: a state directory can sit
    /// in a user's profile.
    #[error("{} cannot be read ({cause}); it is left as it is", file.to_string_lossy())]
    Unreadable { file: OsString, cause: CannotRead },
    /// The read failed with an I/O error and the role refuses to replace a file
    /// it could not read. The text names the file only, like
    /// [`Unreadable`](Self::Unreadable).
    #[error("{} could not be read ({kind}); it is left as it is", file.to_string_lossy())]
    ReadFailed { file: OsString, kind: io::ErrorKind },
    /// The value cannot be framed, or would not read back as `S`. The reason
    /// is a fixed label, never content; the error's category is logged.
    #[error("cannot encode the state file: {0}")]
    Encode(&'static str),
    #[error("{0}")]
    Io(#[from] io::Error),
}

/// An absent `version` must read as a version this schema can have: not 0,
/// and not above its own.
const fn assert_unversioned_as_valid<S: VersionedState>() {
    if let Some(version) = S::UNVERSIONED_AS {
        assert!(
            version > 0 && version <= S::VERSION,
            "UNVERSIONED_AS must be in 1..=VERSION"
        );
    }
}

/// One state file, `S::FILE_NAME` in a directory.
pub struct VersionedFile<S: VersionedState> {
    pub(super) dir: PathBuf,
    pub(super) path: PathBuf,
    pub(super) fs: Arc<dyn Fs>,
    _schema: PhantomData<fn() -> S>,
}

impl<S: VersionedState> VersionedFile<S> {
    /// `dir` may be empty (the parent of a bare file name): that is the
    /// current directory.
    pub fn new(dir: &Path) -> Self {
        const { assert_unversioned_as_valid::<S>() };
        let dir = if dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            dir
        };
        Self {
            dir: dir.to_path_buf(),
            path: dir.join(S::FILE_NAME),
            fs: Arc::new(StdFs),
            _schema: PhantomData,
        }
    }

    /// A file whose reads, links and publishes go through `fs`.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_fs(dir: &Path, fs: Arc<dyn Fs>) -> Self {
        Self { fs, ..Self::new(dir) }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Moves the file to the first free `<name>.unreadable[.N].bak` and returns that path, whatever the file holds and
    /// whatever the role: the caller has decided. `None` when there is no file, and then nothing is made. Never replaces
    /// a backup that exists, and logs the one it makes.
    ///
    /// The move is one rename that refuses to replace, so the file backed up is the file moved. A filesystem with no
    /// such rename is an `Unsupported` error ([`Self::no_noreplace_rename`]): a link and a delete would leave the file
    /// under two names, and the path lock does not cover another process.
    pub(super) fn move_aside_in(&self, dir: &Dir) -> io::Result<Option<PathBuf>> {
        let mut attempt = 1u64;
        loop {
            let backup = self.backup_name(attempt);
            match self.fs.rename_noreplace(dir, self.file_name(), &backup) {
                Ok(()) => {
                    self.log_backup("moved a state file aside", &backup);
                    return Ok(Some(self.dir.join(backup)));
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => attempt += 1,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(e) if e.kind() == io::ErrorKind::Unsupported => return Err(self.no_noreplace_rename()),
                Err(e) => return Err(e),
            }
        }
    }

    /// The error where the directory's filesystem has no rename that refuses to replace (`Unsupported` from
    /// [`Dir::rename_noreplace`]): the claim and the move-aside need it, and neither falls back to a second name.
    pub(super) fn no_noreplace_rename(&self) -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "the filesystem holding {} has no no-replace rename, which it needs",
                S::FILE_NAME
            ),
        )
    }

    pub(super) fn file_name(&self) -> &OsStr {
        OsStr::new(S::FILE_NAME)
    }

    /// Hard-links the file to the first free backup name; the caller logs it once the write it precedes has
    /// published. `hard_link` fails atomically on an existing name, so two writers never take the same name and no
    /// backup is ever replaced. `None` when the file is not there.
    pub(super) fn link_to_free_backup(&self, dir: &Dir) -> io::Result<Option<OsString>> {
        let mut attempt = 1u64;
        loop {
            let backup = self.backup_name(attempt);
            match self.fs.hard_link(dir, self.file_name(), &backup) {
                Ok(()) => return Ok(Some(backup)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => attempt += 1,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(e),
            }
        }
    }

    /// Unlinks a backup made for a write that then failed to publish, so the original keeps one name: the vouched
    /// read refuses a file with two. A failed unlink leaves the backup (a second name, nothing lost) and is logged;
    /// the caller returns the publish error either way.
    pub(super) fn take_back_backup(&self, dir: &Dir, backup: &OsStr) {
        if let Err(e) = self.fs.remove_file(dir, backup) {
            tracing::warn!(
                file = S::FILE_NAME,
                backup = %backup.to_string_lossy(),
                error = &e as &dyn std::error::Error,
                "a write failed after its backup was made, and the backup could not be removed"
            );
        }
    }

    pub(super) fn log_backup(&self, what: &str, backup: &OsStr) {
        tracing::warn!(file = S::FILE_NAME, backup = %backup.to_string_lossy(), "{what}");
    }

    fn backup_name(&self, attempt: u64) -> OsString {
        match attempt {
            1 => format!("{}.unreadable.bak", S::FILE_NAME),
            n => format!("{}.unreadable.{n}.bak", S::FILE_NAME),
        }
        .into()
    }
}

/// The value as one flat JSON object with `"version"` first, proven to read
/// back as `S` before it is returned: anything `load` would call corrupt
/// (a float that serializes as `null`, a top-level enum whose tag lands beside
/// `version`, a payload with a `version` key of its own) is refused here.
pub(super) fn encode<S: VersionedState>(value: &S) -> Result<Vec<u8>, StoreError> {
    #[derive(serde::Serialize)]
    struct Framed<'a, S> {
        version: u32,
        #[serde(flatten)]
        payload: &'a S,
    }

    let bytes = serde_json::to_vec_pretty(&Framed {
        version: S::VERSION,
        payload: value,
    })
    .map_err(|e| refuse::<S>("the payload failed to serialize", ParseFailure::from(&e)))?;
    read_back::<S>(&bytes)
        .map_err(|failure| refuse::<S>("the framed payload does not read back as its schema", failure))?;
    Ok(bytes)
}

fn refuse<S: VersionedState>(label: &'static str, failure: ParseFailure) -> StoreError {
    tracing::warn!(file = S::FILE_NAME, %failure, "{label}");
    StoreError::Encode(label)
}

/// What `load` would make of `bytes`: the current version and a payload of the
/// current schema.
fn read_back<S: VersionedState>(bytes: &[u8]) -> Result<(), ParseFailure> {
    match frame::read_version(bytes, None)? {
        frame::Version::Known(version) if version == S::VERSION => {}
        _ => return Err(ParseFailure::framing("version does not read back")),
    }
    match <S as Chain>::decode(S::VERSION, bytes) {
        Ok(_) => Ok(()),
        Err(ChainError::Shape(failure)) => Err(failure),
        Err(ChainError::Obsolete) => unreachable!("the current version is never at or below the floor"),
    }
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod store_tests;

#[cfg(test)]
#[path = "store_dir_tests.rs"]
mod store_dir_tests;

#[cfg(test)]
#[path = "store_faults_tests.rs"]
mod store_faults_tests;

#[cfg(test)]
#[path = "store_io_failure_tests.rs"]
mod store_io_failure_tests;

#[cfg(test)]
#[path = "store_backup_tests.rs"]
mod store_backup_tests;

#[cfg(test)]
#[path = "store_link_tests.rs"]
mod store_link_tests;

#[cfg(test)]
#[path = "store_reader_tests.rs"]
mod store_reader_tests;

#[cfg(all(test, windows))]
#[path = "store_windows_tests.rs"]
mod store_windows_tests;
