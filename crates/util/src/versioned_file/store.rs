//! Reading and writing one versioned file.

use std::io;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::loaded::{CannotRead, Loaded};
use super::{RemoveOver, StoreOver, VersionedState};

/// The file-system calls the type makes, so a test can fail or hold one
/// without touching the rest. Every method defaults to the real call.
pub(crate) trait Fs: Send + Sync {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        std::fs::read(path)
    }

    fn hard_link(&self, original: &Path, link: &Path) -> io::Result<()> {
        std::fs::hard_link(original, link)
    }

    fn publish(&self, tmp: tempfile::NamedTempFile, dest: &Path) -> io::Result<()> {
        tmp.persist(dest).map(|_| ()).map_err(|e| e.error)
    }
}

struct StdFs;

impl Fs for StdFs {}

/// What differs per file about where and how it is written, and is not the
/// type's business: directory creation and mode, the file's mode and owner.
/// Every method defaults to "chown to [`owner`](Placement::owner), nothing else".
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

    /// The temp file is complete and synced, and not yet visible under the
    /// file's name: set its mode and owner here, so the file is never
    /// published with the wrong ones.
    fn prepare_tmp(&self, tmp: &Path) -> io::Result<()> {
        crate::ownership::chown_if_some(tmp, self.owner());
        Ok(())
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

/// A directory cannot be opened for a sync through `std` on Windows; NTFS
/// makes a rename durable on its own journal.
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
    #[error("{} cannot be read ({cause}); it is left as it is", path.display())]
    Unreadable { path: PathBuf, cause: CannotRead },
    /// The value cannot be framed. The reason is a fixed label, never content.
    #[error("cannot encode the state file: {0}")]
    Encode(&'static str),
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

/// One state file, `S::FILE_NAME` in a directory.
pub struct VersionedFile<S: VersionedState> {
    path: PathBuf,
    fs: Arc<dyn Fs>,
    _schema: PhantomData<fn() -> S>,
}

impl<S: VersionedState> VersionedFile<S> {
    pub fn new(dir: &Path) -> Self {
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

    /// Writes `value`, framed with `S::VERSION`. In this order, so nothing is
    /// removed before its replacement is durable:
    ///
    /// 1. Probe the current file. Absent, older, obsolete or unreadable for an
    ///    I/O reason goes straight to 2. A newer or corrupt file is decided by
    ///    `S::ROLE`: refused (nothing touched), overwritten, or backed up in 3.
    /// 2. Write a same-directory temp file and sync it.
    /// 3. Back the old file up as `<name>.unreadable[.N].bak`, by hard link
    ///    (the same file object, so its mode and ACL stay).
    /// 4. Rename the temp over the file.
    ///
    /// A failure at 2, 3 or 4 leaves the original at its name, so a decision
    /// file is never absent between its backup and its replacement.
    ///
    /// The probe and the rename are not atomic with each other across
    /// processes: a second writer is excluded by the caller, not here.
    pub fn store(&self, value: &S, place: &dyn Placement) -> Result<(), StoreError> {
        let bytes = encode(value)?;
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

        let dir = self.dir();
        place.prepare_dir(dir)?;
        let mut tmp = tempfile::Builder::new()
            .prefix(&format!(".{}.", S::FILE_NAME))
            .suffix(".tmp")
            .tempfile_in(dir)?;
        io::Write::write_all(&mut tmp, &bytes)?;
        tmp.as_file().sync_all()?;
        place.prepare_tmp(tmp.path())?;

        if back_up {
            if let Some(backup) = self.link_to_free_backup()? {
                tracing::warn!(
                    file = S::FILE_NAME,
                    backup = %file_name(&backup),
                    "backed up an unreadable state file before replacing it"
                );
            }
        }

        self.fs.publish(tmp, &self.path)?;
        place.after_publish(&self.path)?;
        place.sync_dir(dir)?;
        Ok(())
    }

    /// Removes the file, or does what `S::ROLE` says for one that cannot be
    /// read. A file whose read failed with an I/O error is removed: the read
    /// said nothing about its bytes.
    pub fn remove(&self) -> io::Result<Removal> {
        let over = match self.load().cannot_read() {
            None => RemoveOver::Remove,
            Some(cause) => S::ROLE.on_remove(cause),
        };
        match over {
            RemoveOver::Keep => Ok(Removal::Kept),
            RemoveOver::MoveAside => Ok(match self.move_aside()? {
                Some(backup) => Removal::MovedAside(backup),
                None => Removal::Absent,
            }),
            RemoveOver::Remove => match std::fs::remove_file(&self.path) {
                Ok(()) => Ok(Removal::Removed),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Removal::Absent),
                Err(e) => Err(e),
            },
        }
    }

    /// Moves the file to the first free `<name>.unreadable[.N].bak` and
    /// returns that path, whatever the file holds and whatever the role: the
    /// caller has decided. `None` when there is no file. Never replaces a
    /// backup that exists.
    pub fn move_aside(&self) -> io::Result<Option<PathBuf>> {
        let Some(backup) = self.link_to_free_backup()? else {
            return Ok(None);
        };
        match std::fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        Ok(Some(backup))
    }

    fn dir(&self) -> &Path {
        self.path.parent().expect("a state file is always inside a directory")
    }

    /// Hard-links the file to the first free backup name. `hard_link` fails
    /// atomically on an existing name, so two writers never take the same name
    /// and no backup is ever replaced; the search ends at the first free name.
    /// `None` when the file is not there.
    fn link_to_free_backup(&self) -> io::Result<Option<PathBuf>> {
        let mut attempt = 1u64;
        loop {
            let backup = self.backup_path(attempt);
            match self.fs.hard_link(&self.path, &backup) {
                Ok(()) => return Ok(Some(backup)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => attempt += 1,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(e),
            }
        }
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

/// The value as one flat JSON object with `"version"` first.
fn encode<S: VersionedState>(value: &S) -> Result<Vec<u8>, StoreError> {
    #[derive(serde::Serialize)]
    struct Framed<'a, S> {
        version: u32,
        #[serde(flatten)]
        payload: &'a S,
    }

    const FAILED: StoreError = StoreError::Encode("the payload failed to serialize");
    let as_value = serde_json::to_value(value).map_err(|_| FAILED)?;
    let serde_json::Value::Object(fields) = &as_value else {
        return Err(StoreError::Encode("the payload is not a JSON object"));
    };
    if fields.contains_key("version") {
        return Err(StoreError::Encode(
            "the payload declares a version key, which the framing owns",
        ));
    }
    serde_json::to_vec_pretty(&Framed {
        version: S::VERSION,
        payload: value,
    })
    .map_err(|_| FAILED)
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod store_tests;

#[cfg(test)]
#[path = "store_faults_tests.rs"]
mod store_faults_tests;
