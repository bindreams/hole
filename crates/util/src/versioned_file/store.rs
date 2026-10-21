//! Reading and writing one versioned file.

use std::io;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::loaded::{CannotRead, Loaded};
use super::{frame, Chain, ChainError, RemoveOver, StoreOver, VersionedState};
use crate::parse_error::ParseFailure;

/// The file-system calls the type makes, so a test can fail or hold one
/// without touching the rest. Every method defaults to the real call.
///
/// Reachable outside this crate only with the `test-support` feature.
pub trait Fs: Send + Sync {
    fn remove_file(&self, path: &Path) -> io::Result<()> {
        std::fs::remove_file(path)
    }

    /// `Unsupported` when the platform cannot rename without replacing.
    fn rename_noreplace(&self, from: &Path, to: &Path) -> io::Result<()> {
        super::sys::rename_noreplace(from, to)
    }

    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        std::fs::read(path)
    }

    fn hard_link(&self, original: &Path, link: &Path) -> io::Result<()> {
        std::fs::hard_link(original, link)
    }

    fn publish(&self, tmp: tempfile::NamedTempFile, dest: &Path) -> io::Result<()> {
        super::sys::publish(tmp, dest)
    }
}

struct StdFs;

impl Fs for StdFs {}

/// What differs per file about where and how it is written, and is not the
/// type's business: directory creation and mode, the file's mode and owner.
pub trait Placement {
    fn owner(&self) -> Option<(u32, u32)> {
        None
    }

    /// Before anything is written: the directory exists and is as it should be.
    fn prepare_dir(&self, dir: &Path) -> io::Result<()> {
        std::fs::create_dir_all(dir)?;
        crate::ownership::chown_if_some(dir, self.owner());
        Ok(())
    }

    /// The temp file is complete, synced and not yet published: set its mode,
    /// owner and ACL here. On Windows do not set `FILE_ATTRIBUTE_READONLY`:
    /// no later `store` could replace the file.
    fn prepare_tmp(&self, tmp: &Path) -> io::Result<()> {
        crate::ownership::chown_if_some(tmp, self.owner());
        Ok(())
    }

    /// The new file is in place. Not for its mode, owner or ACL: use
    /// [`prepare_tmp`](Placement::prepare_tmp).
    fn after_publish(&self, _path: &Path) -> io::Result<()> {
        Ok(())
    }

    /// Makes the rename durable: the directory's buffers are flushed. On
    /// Windows that is `FlushFileBuffers` on a handle to the directory, and
    /// Microsoft does not document it as committing a rename: the durability
    /// of the replace there rests on that reading, not on a documented
    /// guarantee. A volume with no directory flush (an SMB share or a 9P
    /// volume on Windows; a filesystem without directory fsync on unix) is
    /// `Ok`, and the durability there is whatever the volume gives.
    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        sync_dir(dir)
    }
}

/// Flushes the directory. A filesystem that offers no directory fsync (see
/// [`no_directory_flush`]) is not an error. Failing to open the directory
/// still is.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    sync_dir_with(dir, std::fs::File::sync_all)
}

/// [`sync_dir`] over an injectable flush, so the tolerance is tested where it
/// is wired.
#[cfg(unix)]
fn sync_dir_with(dir: &Path, flush: impl FnOnce(&std::fs::File) -> io::Result<()>) -> io::Result<()> {
    tolerate_missing_directory_flush(flush(&std::fs::File::open(dir)?))
}

/// Flushes the directory. A volume that offers no directory flush (see
/// [`no_directory_flush`]) is not an error: the replace there is as durable as
/// the volume makes it. Failing to open the directory still is.
///
/// `FlushFileBuffers` needs a handle with `GENERIC_WRITE`, and opening a
/// directory needs `FILE_FLAG_BACKUP_SEMANTICS`.
#[cfg(windows)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    sync_dir_with(dir, std::fs::File::sync_all)
}

/// [`sync_dir`] over an injectable flush, so the tolerance is tested where it
/// is wired.
#[cfg(windows)]
fn sync_dir_with(dir: &Path, flush: impl FnOnce(&std::fs::File) -> io::Result<()>) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    let handle = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(dir)?;
    tolerate_missing_directory_flush(flush(&handle))
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

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The file on disk is newer or corrupt and its role refuses to replace it.
    /// The text carries the full path: fine for the bridge log, but redact it
    /// before it reaches a toast.
    #[error("{} cannot be read ({cause}); it is left as it is", path.display())]
    Unreadable { path: PathBuf, cause: CannotRead },
    /// The read failed with an I/O error and the role refuses to replace a file
    /// it could not read. The text carries the full path, like
    /// [`Unreadable`](Self::Unreadable).
    #[error("{} could not be read ({kind}); it is left as it is", path.display())]
    ReadFailed { path: PathBuf, kind: io::ErrorKind },
    /// The value cannot be framed, or would not read back as `S`. The reason
    /// is a fixed label, never content; the error's category is logged.
    #[error("cannot encode the state file: {0}")]
    Encode(&'static str),
    /// The new file is already in place, but a step after the rename failed:
    /// the value IS stored, though not known to be durable or finalized.
    #[error("the state file was replaced, but finishing the write failed: {0}")]
    PublishedNotFinalized(io::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// What [`VersionedFile::remove`] did.
#[derive(Debug, PartialEq, Eq)]
pub enum Removal {
    Removed,
    Absent,
    /// A file this role never removes when it cannot read it.
    Kept,
    /// Moved to this path instead of removed.
    MovedAside(PathBuf),
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
    path: PathBuf,
    fs: Arc<dyn Fs>,
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

    /// Reads the file. Never rewrites it.
    pub fn load(&self) -> Loaded<S> {
        Loaded::from_read(self.fs.read(&self.path))
    }

    /// Writes `value`, framed with `S::VERSION`. In this order, so nothing is
    /// removed before its replacement is durable:
    ///
    /// 1. Write a same-directory temp file, sync it and have `place` set its
    ///    mode, owner and ACL.
    /// 2. Probe the current file. Absent, older or obsolete goes straight to
    ///    4. A newer or corrupt file, and one whose read failed with an I/O
    ///    error, is decided by `S::ROLE`: refused (nothing touched, the temp
    ///    file deleted, [`StoreError::ReadFailed`] for the I/O error),
    ///    overwritten, or backed up in 3. A read that failed says nothing
    ///    about the bytes, and no role overwrites them.
    /// 3. Back the old file up as `<name>.unreadable[.N].bak`, by hard link
    ///    (the same file object, so its mode and ACL stay). Every backup made
    ///    is logged and kept, even if 4 then fails.
    /// 4. Rename the temp over the file.
    ///
    /// A failure at 1, 2, 3 or 4 leaves the original at its name, so a
    /// decision file is never absent between its backup and its replacement.
    /// Once 4 has happened the value is stored: a failure after it is
    /// [`StoreError::PublishedNotFinalized`], not `Io`.
    ///
    /// # Exclusion
    ///
    /// The type probes the file (2) and then acts on what it found (3, 4); it
    /// takes no lock. The caller must ensure that no other process or task
    /// writes, removes or moves aside this file between the two: the probe is
    /// not rechecked, so a concurrent writer's file can be overwritten or
    /// backed up on the strength of a stale probe. For the bridge's state
    /// files that is the bridge's liveness lock
    /// (`crates/bridge/src/liveness.rs`: held by the running bridge and by
    /// the CLIs that write state, one holder per state directory) plus the
    /// caller's own ordering within the process. The state directory must
    /// not let another principal create files in it: the type acts by name
    /// and does not defend against a name changed under it.
    /// [`load`](Self::load) needs none of this and reads either file whole.
    ///
    /// On Windows the replace is a POSIX-semantics rename, which a reader that
    /// shares delete (every [`load`](Self::load), and `std`) cannot block; one
    /// that does not share delete makes the store fail with the OS error
    /// (a sharing violation). A volume that rejects POSIX rename (FAT, exFAT,
    /// some network shares) gets `MoveFileExW` instead, where any reader that
    /// has the file open at the instant of the replace can make the store fail
    /// with the OS error (`PermissionDenied`). The old file is then still in
    /// place. The file is published without `FILE_ATTRIBUTE_TEMPORARY` and
    /// with every other attribute `place.prepare_tmp` set, and a state
    /// directory path longer than `MAX_PATH` works. A volume with no directory
    /// flush does not fail the store (see [`Placement::sync_dir`]).
    ///
    /// Blocks the calling thread on file I/O: from async code call it where
    /// blocking is allowed. `serde_json` writes a non-finite float as `null`, so an
    /// `Option<f64>` holding NaN is stored, and read back, as `None`; a plain
    /// float that would do so is refused with [`StoreError::Encode`].
    pub fn store(&self, value: &S, place: &dyn Placement) -> Result<(), StoreError> {
        let bytes = encode(value)?;
        let dir = self.dir();
        place.prepare_dir(dir)?;

        let mut tmp = tempfile::Builder::new()
            .prefix(&format!(".{}.", S::FILE_NAME))
            .suffix(".tmp")
            .tempfile_in(dir)?;
        io::Write::write_all(&mut tmp, &bytes)?;
        tmp.as_file().sync_all()?;
        place.prepare_tmp(tmp.path())?;

        let back_up = store_over(&self.path, &self.load())?;

        if back_up {
            self.link_to_free_backup()?;
        }

        self.fs.publish(tmp, &self.path)?;
        // The directory is flushed even when `after_publish` failed: the rename
        // happened either way. The first failure is the one reported.
        let finalized = place.after_publish(&self.path);
        let flushed = place.sync_dir(dir);
        finalized.and(flushed).map_err(StoreError::PublishedNotFinalized)
    }

    /// Removes the file, or does what `S::ROLE` says for one that cannot be
    /// read, or whose read failed with an I/O error (kept, or moved aside:
    /// never deleted unread). When the file is not there, or its directory is
    /// not, it returns `Absent` without making anything. A link at the name
    /// is an entry: it is removed, never what it points at.
    ///
    /// The type probes the file and then acts on what it found. The caller
    /// must ensure that no other process or task writes, removes or moves
    /// aside this file in between; see [`store`](Self::store), "Exclusion".
    ///
    /// The directory is the caller's to write: where it cannot, `remove` of a
    /// file this role removes or moves aside fails with the OS error.
    pub fn remove(&self) -> io::Result<Removal> {
        match remove_over(&self.load()) {
            RemoveOver::Keep => Ok(Removal::Kept),
            RemoveOver::MoveAside => Ok(match self.move_aside()? {
                Some(backup) => Removal::MovedAside(backup),
                None => Removal::Absent,
            }),
            RemoveOver::Remove => match self.fs.remove_file(&self.path) {
                Ok(()) => Ok(Removal::Removed),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Removal::Absent),
                Err(e) => Err(e),
            },
        }
    }

    /// Moves the file to the first free `<name>.unreadable[.N].bak` and
    /// returns that path, whatever the file holds and whatever the role: the
    /// caller has decided. `None` when there is no file, and then nothing is
    /// made. Never replaces a backup that exists, and logs the one it makes.
    ///
    /// The move is one rename that refuses to replace, so the file backed up
    /// is the file moved even if another writer renames over it meanwhile. On
    /// a platform or filesystem without such a rename it is a hard link and
    /// then a delete, and a writer that replaces the file between the two
    /// loses its file. The caller must ensure there is none; see
    /// [`store`](Self::store), "Exclusion".
    pub fn move_aside(&self) -> io::Result<Option<PathBuf>> {
        let mut attempt = 1u64;
        loop {
            let backup = self.backup_path(attempt);
            match self.fs.rename_noreplace(&self.path, &backup) {
                Ok(()) => {
                    self.log_backup("moved a state file aside", &backup);
                    return Ok(Some(backup));
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => attempt += 1,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(e) if e.kind() == io::ErrorKind::Unsupported => return self.move_aside_by_link(),
                Err(e) => return Err(e),
            }
        }
    }

    fn move_aside_by_link(&self) -> io::Result<Option<PathBuf>> {
        let Some(backup) = self.link_to_free_backup()? else {
            return Ok(None);
        };
        match self.fs.remove_file(&self.path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        Ok(Some(backup))
    }

    fn dir(&self) -> &Path {
        self.path.parent().expect("a state file is always inside a directory")
    }

    /// Hard-links the file to the first free backup name and logs it.
    /// `hard_link` fails atomically on an existing name, so two writers never
    /// take the same name and no backup is ever replaced. `None` when the file
    /// is not there.
    fn link_to_free_backup(&self) -> io::Result<Option<PathBuf>> {
        let mut attempt = 1u64;
        loop {
            let backup = self.backup_path(attempt);
            match self.fs.hard_link(&self.path, &backup) {
                Ok(()) => {
                    self.log_backup("backed up a state file", &backup);
                    return Ok(Some(backup));
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => attempt += 1,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(e),
            }
        }
    }

    fn log_backup(&self, what: &str, backup: &Path) {
        tracing::warn!(file = S::FILE_NAME, backup = %file_name(backup), "{what}");
    }

    fn backup_path(&self, attempt: u64) -> PathBuf {
        let name = match attempt {
            1 => format!("{}.unreadable.bak", S::FILE_NAME),
            n => format!("{}.unreadable.{n}.bak", S::FILE_NAME),
        };
        self.dir().join(name)
    }
}

/// Whether `store` backs up the file as `loaded` found it before it writes,
/// or the error that refuses the write.
fn store_over<S: VersionedState>(path: &Path, loaded: &Loaded<S>) -> Result<bool, StoreError> {
    let (over, refusal) = match loaded {
        Loaded::Unreadable(e) => (
            S::ROLE.on_store_io_failure(),
            StoreError::ReadFailed {
                path: path.to_owned(),
                kind: e.kind(),
            },
        ),
        // Nothing a release cannot read is at the name: nothing to protect.
        Loaded::Absent => return Ok(false),
        // Dropped on purpose by the chain's floor.
        Loaded::Obsolete { .. } => return Ok(false),
        // This release reads it; the store replaces it with the newer value.
        Loaded::Current { .. } => return Ok(false),
        Loaded::Newer { .. } => (
            S::ROLE.on_store(CannotRead::Newer),
            StoreError::Unreadable {
                path: path.to_owned(),
                cause: CannotRead::Newer,
            },
        ),
        Loaded::Corrupt { .. } => (
            S::ROLE.on_store(CannotRead::Corrupt),
            StoreError::Unreadable {
                path: path.to_owned(),
                cause: CannotRead::Corrupt,
            },
        ),
    };
    match over {
        StoreOver::Refuse => Err(refusal),
        StoreOver::MoveAside => Ok(true),
        StoreOver::Overwrite => Ok(false),
    }
}

/// What `remove` does with a file as `loaded` found it.
fn remove_over<S: VersionedState>(loaded: &Loaded<S>) -> RemoveOver {
    match loaded {
        Loaded::Unreadable(_) => S::ROLE.on_remove_io_failure(),
        // Removing nothing is still the decision to remove.
        Loaded::Absent => RemoveOver::Remove,
        // Dropped on purpose by the chain's floor.
        Loaded::Obsolete { .. } => RemoveOver::Remove,
        // This release reads it and asked for it gone.
        Loaded::Current { .. } => RemoveOver::Remove,
        Loaded::Newer { .. } => S::ROLE.on_remove(CannotRead::Newer),
        Loaded::Corrupt { .. } => S::ROLE.on_remove(CannotRead::Corrupt),
    }
}

fn file_name(path: &Path) -> std::borrow::Cow<'_, str> {
    path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default()
}

/// The value as one flat JSON object with `"version"` first, proven to read
/// back as `S` before it is returned: anything `load` would call corrupt
/// (a float that serializes as `null`, a top-level enum whose tag lands beside
/// `version`, a payload with a `version` key of its own) is refused here.
fn encode<S: VersionedState>(value: &S) -> Result<Vec<u8>, StoreError> {
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
