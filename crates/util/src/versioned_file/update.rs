//! The one read (`observe`), the one write path (`update`) and the atomic claim (`create_new`) of a state file.

use std::ffi::OsStr;
use std::io;
use std::path::PathBuf;

use super::generation::{self, Generation, Held};
use super::loaded::{CannotRead, Loaded, UnreadableKind};
use super::store::encode;
use super::{Placement, RemoveOver, StoreError, StoreOver, VersionedFile, VersionedState};
use crate::dir::{Dir, EntryKind, ReadDir};
use crate::error_chain::error_chain;

/// One read of the file plus the generation it was taken at.
#[derive(Debug)]
pub struct Observed<S> {
    pub loaded: Loaded<S>,
    pub generation: Generation,
}

/// What the caller of [`VersionedFile::update`] wants left at the name. What that does over a file this release
/// cannot read is the role's call, nowhere else.
#[derive(Debug)]
pub enum Change<S> {
    /// Write nothing.
    Keep,
    /// Replace the file with this value.
    Store(S),
    /// Delete the file.
    Remove,
    /// Move the file to `<name>.unreadable[.N].bak`, whatever it holds and whatever the role.
    MoveAside,
}

/// How one [`VersionedFile::update`] went for the file.
#[derive(Debug, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// The change was [`Change::Keep`].
    Unchanged,
    /// The file was replaced (a backup made first still reports this).
    Stored,
    /// The file was deleted.
    Removed,
    /// There was nothing to remove or move: no file, or no directory.
    Absent,
    /// A file the role does not remove when it cannot read it, and it could not.
    Kept,
    /// Moved to this path instead.
    MovedAside(PathBuf),
}

/// How one [`VersionedFile::create_new`] went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateOutcome {
    /// The file was made.
    Created,
    /// The name was already taken, by anything.
    Taken,
}

/// What `update` does, decided by [`step`] and nothing else.
enum Step {
    Nothing(UpdateOutcome),
    Refuse(StoreError),
    Write { back_up: bool },
    Delete,
    MoveAside,
}

/// The one place a `(Role, Change, Loaded)` becomes an action.
fn step<S: VersionedState>(change: &Change<S>, loaded: &Loaded<S>, file: &OsStr) -> Step {
    match change {
        Change::Keep => Step::Nothing(UpdateOutcome::Unchanged),
        Change::MoveAside => Step::MoveAside,
        Change::Store(_) => store_step(loaded, file),
        Change::Remove => remove_step(loaded),
    }
}

fn store_step<S: VersionedState>(loaded: &Loaded<S>, file: &OsStr) -> Step {
    let (over, refusal) = match loaded {
        Loaded::Unreadable { error, .. } => (
            S::ROLE.on_store_io_failure(),
            StoreError::ReadFailed {
                file: file.to_owned(),
                kind: error.kind(),
            },
        ),
        // Nothing a release cannot read is at the name: nothing to protect.
        Loaded::Absent => return Step::Write { back_up: false },
        // Dropped on purpose by the chain's floor.
        Loaded::Obsolete { .. } => return Step::Write { back_up: false },
        // This release reads it; the store replaces it with the newer value.
        Loaded::Current { .. } => return Step::Write { back_up: false },
        Loaded::Newer { .. } => (
            S::ROLE.on_store(CannotRead::Newer),
            StoreError::Unreadable {
                file: file.to_owned(),
                cause: CannotRead::Newer,
            },
        ),
        Loaded::Corrupt { .. } => (
            S::ROLE.on_store(CannotRead::Corrupt),
            StoreError::Unreadable {
                file: file.to_owned(),
                cause: CannotRead::Corrupt,
            },
        ),
    };
    match over {
        StoreOver::Refuse => Step::Refuse(refusal),
        StoreOver::MoveAside => Step::Write { back_up: true },
        StoreOver::Overwrite => Step::Write { back_up: false },
    }
}

fn remove_step<S: VersionedState>(loaded: &Loaded<S>) -> Step {
    let over = match loaded {
        Loaded::Unreadable { .. } => S::ROLE.on_remove_io_failure(),
        // Removing nothing is still the decision to remove.
        Loaded::Absent => RemoveOver::Remove,
        // Dropped on purpose by the chain's floor.
        Loaded::Obsolete { .. } => RemoveOver::Remove,
        // This release reads it and asked for it gone.
        Loaded::Current { .. } => RemoveOver::Remove,
        Loaded::Newer { .. } => S::ROLE.on_remove(CannotRead::Newer),
        Loaded::Corrupt { .. } => S::ROLE.on_remove(CannotRead::Corrupt),
    };
    match over {
        RemoveOver::Keep => Step::Nothing(UpdateOutcome::Kept),
        RemoveOver::MoveAside => Step::MoveAside,
        RemoveOver::Remove => Step::Delete,
    }
}

impl<S: VersionedState> VersionedFile<S> {
    /// Reads the file without writing, under this file's lock (it waits only for a write in flight), so the
    /// generation is the one that goes with the bytes: a read outside the lock could pair old bytes with a generation
    /// bumped for a write not yet published.
    ///
    /// A file the folder's owner cannot vouch for (a second name a user planted) is `Unreadable`. A directory that is
    /// not there is an absent file; one that cannot be opened (a link in its path that [`Dir`] does not follow) is a
    /// read that failed, as is a name that holds anything but a regular file.
    pub fn observe(&self) -> Observed<S> {
        let held = generation::lock(&self.path);
        let loaded = match ReadDir::open(&self.dir) {
            Ok(dir) => self.read_through(&dir),
            Err(err) => Loaded::from_read(Err(err), || Some(UnreadableKind::Directory)),
        };
        Observed {
            loaded,
            generation: held.generation(),
        }
    }

    /// One read through `dir`. When it fails, the one look at the name says whether it holds a regular file, nothing
    /// (the file is [`Loaded::Absent`]), or could not be examined.
    fn read_through(&self, dir: &ReadDir) -> Loaded<S> {
        let name = self.file_name();
        Loaded::from_read(self.fs.read(dir, name), || match self.fs.kind_of(dir, name) {
            Ok(Some(EntryKind::Symlink | EntryKind::Directory | EntryKind::Other)) => Some(UnreadableKind::NotAFile),
            Ok(Some(EntryKind::File)) => Some(UnreadableKind::File),
            // The name is gone: the read failed on a file that was removed meanwhile.
            Ok(None) => None,
            Err(err) => {
                tracing::debug!(file = %name.to_string_lossy(), kind = ?err.kind(), "the name of a state file that failed to read could not be examined");
                Some(UnreadableKind::Unprobed)
            }
        })
    }

    /// Under this file's lock: read it, let `decide` choose, apply the choice, and say what happened to the file.
    /// `decide` runs under the lock and does no I/O; the lock is a leaf (nothing is acquired inside it).
    ///
    /// In this order, so nothing is removed before its replacement is durable:
    ///
    /// 1. Open the directory without creating it (a missing one is an absent file) and read through that handle.
    /// 2. `decide`. A [`Change::Store`] value is encoded now; one that would not read back is
    ///    [`StoreError::Encode`] and nothing is touched.
    /// 3. [`step`] turns the change and what was read into an action. A refusal touches nothing.
    /// 4. The generation moves, then the action runs. A failure before the rename leaves the original at its name;
    ///    once the rename has happened the result is `Ok`, and a failed `after_publish` or directory flush is logged
    ///    at warn.
    ///
    /// The directory is opened once without following a symlink and every step names a file inside that handle.
    ///
    /// On Windows the replace and its failure modes are described in the module doc. A non-finite `Option<f64>` is
    /// stored, and read back, as `None`; a plain float is refused with [`StoreError::Encode`].
    ///
    /// Blocks the calling thread on file I/O: from async code call it where blocking is allowed.
    pub fn update<R>(
        &self,
        place: &dyn Placement,
        decide: impl FnOnce(&Observed<S>) -> (Change<S>, R),
    ) -> Result<(R, UpdateOutcome), StoreError> {
        let mut held = generation::lock(&self.path);
        let dir = match self.open_dir(place, false) {
            Ok(dir) => Some(dir),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        let loaded = match &dir {
            None => Loaded::Absent,
            Some(dir) => match dir.reader() {
                Ok(reader) => self.read_through(&reader),
                Err(err) => Loaded::from_read(Err(err), || Some(UnreadableKind::Directory)),
            },
        };
        let observed = Observed {
            loaded,
            generation: held.generation(),
        };

        let (change, result) = decide(&observed);
        let bytes = match &change {
            Change::Store(value) => Some(encode(value)?),
            Change::Keep | Change::Remove | Change::MoveAside => None,
        };
        let outcome = match step(&change, &observed.loaded, self.file_name()) {
            Step::Nothing(outcome) => outcome,
            Step::Refuse(refusal) => return Err(refusal),
            Step::Write { back_up } => {
                let bytes = bytes.expect("a write step comes from a Store");
                self.write(&mut held, place, dir, &bytes, back_up)?;
                UpdateOutcome::Stored
            }
            Step::Delete => match dir {
                None => UpdateOutcome::Absent,
                Some(dir) => {
                    held.bump();
                    match self.fs.remove_file(&dir, self.file_name()) {
                        Ok(()) => UpdateOutcome::Removed,
                        Err(e) if e.kind() == io::ErrorKind::NotFound => UpdateOutcome::Absent,
                        Err(e) => return Err(e.into()),
                    }
                }
            },
            Step::MoveAside => match dir {
                None => UpdateOutcome::Absent,
                Some(dir) => {
                    held.bump();
                    match self.move_aside_in(&dir)? {
                        Some(backup) => UpdateOutcome::MovedAside(backup),
                        None => UpdateOutcome::Absent,
                    }
                }
            },
        };
        Ok((result, outcome))
    }

    fn write(
        &self,
        held: &mut Held,
        place: &dyn Placement,
        dir: Option<Dir>,
        bytes: &[u8],
        back_up: bool,
    ) -> Result<(), StoreError> {
        held.bump();
        let dir = match dir {
            Some(dir) => dir,
            None => self.open_dir(place, true)?,
        };
        place.prepare_dir(&dir)?;
        let staged = dir.stage(self.file_name(), bytes, place.owner(), |tmp| place.prepare_tmp(tmp))?;
        if back_up {
            self.link_to_free_backup(&dir)?;
        }
        self.fs.publish(staged)?;
        self.finalize(place, &dir);
        Ok(())
    }

    /// What follows a publish. The file is already at its name, so nothing here can fail the write: the caller acts
    /// on what is on disk, and the only thing a failed flush costs is durability across a power loss, which the
    /// caller could do nothing about. The directory is flushed even when `after_publish` failed.
    fn finalize(&self, place: &dyn Placement, dir: &Dir) {
        if let Err(e) = place.after_publish(dir, self.file_name()) {
            tracing::warn!(file = S::FILE_NAME, error = %error_chain(&e), "a state file was published, but its after-publish step failed");
        }
        if let Err(e) = place.sync_dir(dir) {
            tracing::warn!(file = S::FILE_NAME, error = %error_chain(&e), "a state file was published, but its directory could not be flushed");
        }
    }

    /// Publishes `value` as a new file only if the name is free, whatever else is there: a file this release cannot
    /// read is `Taken` too. A rename that refuses to replace is what makes it atomic, across processes and without
    /// a lock, a reader never sees a partial file, and the file never has a second name. (Where the filesystem has
    /// no such rename the claim is a hard link, and the file has two names until the temp name is removed; see
    /// [`crate::dir::Staged::claim`].) Does not move the generation.
    pub fn create_new(&self, value: &S, place: &dyn Placement) -> Result<CreateOutcome, StoreError> {
        let bytes = encode(value)?;
        let dir = self.open_dir(place, true)?;
        place.prepare_dir(&dir)?;
        let staged = dir.stage(self.file_name(), &bytes, place.owner(), |tmp| place.prepare_tmp(tmp))?;
        match staged.claim() {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Ok(CreateOutcome::Taken),
            Err(e) => return Err(e.into()),
        }
        self.finalize(place, &dir);
        Ok(CreateOutcome::Created)
    }

    /// The directory, opened for what `place` asks of it.
    fn open_dir(&self, place: &dyn Placement, create: bool) -> io::Result<Dir> {
        #[cfg(windows)]
        if place.open_for_acl() {
            return Dir::open_for_acl(&self.dir, create);
        }
        Dir::open(&self.dir, create, place.owner())
    }
}

#[cfg(test)]
#[path = "update_tests.rs"]
mod update_tests;

#[cfg(test)]
#[path = "update_matrix_tests.rs"]
mod update_matrix_tests;
