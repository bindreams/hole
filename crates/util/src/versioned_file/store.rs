//! Reading and writing one versioned file.

use std::io;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::loaded::{CannotRead, Loaded};
use super::lock::Lock;
use super::{frame, Chain, ChainError, RemoveOver, StoreOver, VersionedState};
use crate::parse_error::ParseFailure;

/// The file-system calls the type makes, so a test can fail or hold one
/// without touching the rest. Every method defaults to the real call.
pub(crate) trait Fs: Send + Sync {
    /// Blocks until `file` holds the exclusive lock.
    fn lock(&self, file: &std::fs::File) -> io::Result<()> {
        super::sys::lock_exclusive(file)
    }

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

    /// The temp file is complete, synced and not yet published: set its mode and owner here.
    fn prepare_tmp(&self, tmp: &Path) -> io::Result<()> {
        crate::ownership::chown_if_some(tmp, self.owner());
        Ok(())
    }

    /// The `<name>.lock` file next to the state file, which `store` has locked:
    /// give it the state file's mode, owner and ACL. Defaults to
    /// [`prepare_tmp`](Placement::prepare_tmp).
    fn prepare_lock(&self, lock: &Path) -> io::Result<()> {
        self.prepare_tmp(lock)
    }

    /// The new file is in place.
    fn after_publish(&self, _path: &Path) -> io::Result<()> {
        Ok(())
    }

    /// Makes the rename itself durable.
    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        sync_dir(dir)
    }
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

/// A directory cannot be opened for a sync through `std` on Windows; the
/// replace is written through instead (`sys::publish`).
#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
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
    pub fn new(dir: &Path) -> Self {
        const { assert_unversioned_as_valid::<S>() };
        Self {
            path: dir.join(S::FILE_NAME),
            fs: Arc::new(StdFs),
            _schema: PhantomData,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_fs(dir: &Path, fs: Arc<dyn Fs>) -> Self {
        Self { fs, ..Self::new(dir) }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the file. Never rewrites it.
    pub fn load(&self) -> Loaded<S> {
        Loaded::from_read(self.fs.read(&self.path))
    }

    /// Writes `value`, framed with `S::VERSION`, under the file's lock
    /// (`<name>.lock`, held from the probe to the last write, so a concurrent
    /// `store`, `remove` or `move_aside` of this file in any process waits).
    /// In this order, so nothing is removed before its replacement is durable:
    ///
    /// 1. Probe the current file. Absent, older, obsolete or unreadable for an
    ///    I/O reason goes straight to 2. A newer or corrupt file is decided by
    ///    `S::ROLE`: refused (nothing touched), overwritten, or backed up in 3.
    /// 2. Write a same-directory temp file and sync it.
    /// 3. Back the old file up as `<name>.unreadable[.N].bak`, by hard link
    ///    (the same file object, so its mode and ACL stay). Every backup made
    ///    is logged and kept, even if 4 then fails.
    /// 4. Rename the temp over the file.
    ///
    /// A failure at 2, 3 or 4 leaves the original at its name, so a decision
    /// file is never absent between its backup and its replacement. Once 4 has
    /// happened the value is stored: a failure after it is
    /// [`StoreError::PublishedNotFinalized`], not `Io`.
    ///
    /// Only writers that take the lock are excluded: [`load`](Self::load)
    /// takes none, and reads either file whole.
    pub fn store(&self, value: &S, place: &dyn Placement) -> Result<(), StoreError> {
        let bytes = encode(value)?;
        let dir = self.dir();
        place.prepare_dir(dir)?;
        let _lock = self.lock()?;
        place.prepare_lock(&self.lock_path())?;

        let back_up = match self.load().cannot_read() {
            None => false,
            Some(cause) => match S::ROLE.on_store(cause) {
                StoreOver::Refuse => {
                    return Err(StoreError::Unreadable {
                        path: self.path.clone(),
                        cause,
                    })
                }
                StoreOver::Overwrite => false,
                StoreOver::MoveAside => true,
            },
        };

        let mut tmp = tempfile::Builder::new()
            .prefix(&format!(".{}.", S::FILE_NAME))
            .suffix(".tmp")
            .tempfile_in(dir)?;
        io::Write::write_all(&mut tmp, &bytes)?;
        tmp.as_file().sync_all()?;
        place.prepare_tmp(tmp.path())?;

        if back_up {
            self.link_to_free_backup()?;
        }

        self.fs.publish(tmp, &self.path)?;
        place
            .after_publish(&self.path)
            .map_err(StoreError::PublishedNotFinalized)?;
        place.sync_dir(dir).map_err(StoreError::PublishedNotFinalized)?;
        Ok(())
    }

    /// Removes the file, or does what `S::ROLE` says for one that cannot be
    /// read. A file whose read failed with an I/O error is removed: the read
    /// said nothing about its bytes. Takes the file's lock, like
    /// [`store`](Self::store); in a directory that does not exist there is
    /// nothing to remove and nothing is created.
    pub fn remove(&self) -> io::Result<Removal> {
        let Some(lock) = self.lock_if_dir_exists()? else {
            return Ok(Removal::Absent);
        };
        let over = match self.load().cannot_read() {
            None => RemoveOver::Remove,
            Some(cause) => S::ROLE.on_remove(cause),
        };
        match over {
            RemoveOver::Keep => Ok(Removal::Kept),
            RemoveOver::MoveAside => Ok(match self.move_aside_locked(&lock)? {
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
    /// caller has decided. `None` when there is no file. Never replaces a
    /// backup that exists, and logs the one it makes. Takes the file's lock.
    ///
    /// The move is one rename that refuses to replace, so the file backed up
    /// is the file moved even if another writer renames over it meanwhile. On
    /// a platform or filesystem without such a rename it is a hard link and
    /// then a delete, which only the lock protects.
    pub fn move_aside(&self) -> io::Result<Option<PathBuf>> {
        let Some(lock) = self.lock_if_dir_exists()? else {
            return Ok(None);
        };
        self.move_aside_locked(&lock)
    }

    fn move_aside_locked(&self, _lock: &Lock) -> io::Result<Option<PathBuf>> {
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

    fn lock_path(&self) -> PathBuf {
        self.dir().join(format!("{}.lock", S::FILE_NAME))
    }

    /// Takes the lock, creating its file when it is missing.
    fn lock(&self) -> io::Result<Lock> {
        Lock::acquire(&*self.fs, &self.lock_path())
    }

    /// `None` when the directory does not exist, so the file cannot either.
    fn lock_if_dir_exists(&self) -> io::Result<Option<Lock>> {
        match self.lock() {
            Ok(lock) => Ok(Some(lock)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
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
#[path = "store_lock_tests.rs"]
mod store_lock_tests;
