//! Load-time quarantine and gated saving for the GUI config file (#467).
//!
//! `AppConfig::load` used to map a missing file to defaults and anything else
//! to an error — which the GUI discarded (`unwrap_or_default`), so the next
//! save overwrote the corrupt file, destroying the user's servers and
//! passwords. `ConfigStore` makes that impossible: a corrupt/unreadable
//! `config.json` is moved aside to `config.json.unreadable[.N].bak` before
//! defaults are used, and if that fails, saving is blocked for the session. A
//! file from a newer release (#1096) is left where it is and saving is blocked:
//! this release cannot write it without dropping what it does not know. So is a
//! file whose read is *refused* ([`ConfigRecovery::Refused`]): a refusal says this process may not read it, not that
//! it is damaged, so it is neither moved aside nor overwritten. And so is a folder that does not open
//! ([`ConfigRecovery::FolderNotOpened`]): nothing was read and nothing can be moved.
//!
//! The file is a [`VersionedFile`] of role `Role::Config`: the user's own file, handled as the process that loads it
//! is. An unprivileged process in its own folder follows every link the OS would and reads what it finds. A
//! privileged one (a GUI run under `sudo`) walks the folder and reads the file as the system does, so a link at the
//! name, a file another account owns or anything that is not a regular file is refused, and the file is left in place
//! with defaults in memory and saving blocked. The load is one [`VersionedFile::update`] that reads the file and,
//! when it is corrupt or fails to read, moves it aside.

use crate::config::{AppConfig, ConfigError};
use std::io;
use std::path::{Path, PathBuf};
use tracing::{error, warn};
use util::dir::{Dir, Principal, Refusal};
use util::parse_error::ParseFailure;
use util::versioned_file::{Change, Loaded, Observed, Placement, Schema, StoreError, UpdateOutcome, VersionedFile};

/// What happened when the config file could not be loaded, and what became of it.
#[derive(Debug)]
pub enum ConfigRecovery {
    /// Corrupt or unreadable; moved aside to `backup`, and saving works.
    Quarantined {
        path: PathBuf,
        error: ConfigError,
        backup: PathBuf,
    },
    /// Corrupt or unreadable, and could not be moved aside: saving is blocked so the file is never overwritten.
    QuarantineFailed {
        path: PathBuf,
        error: ConfigError,
        failure: io::Error,
    },
    /// The folder of `path` could not be opened (a file in its place, a link the walk refuses, no right to it), so
    /// nothing was read and nothing can be moved: defaults, and saving is blocked.
    FolderNotOpened { path: PathBuf, failure: io::Error },
    /// The read was refused (a link at the name, a file another account owns, not a regular file): nothing was read and
    /// nothing is moved, so the file is exactly where it was; defaults, and saving is blocked.
    Refused { path: PathBuf, refusal: Refusal },
    /// From a newer release (`found` is `None` for a version too large for a `u32`): left where it is, and saving is
    /// blocked.
    LeftInPlace { path: PathBuf, found: Option<u32> },
}

impl ConfigRecovery {
    /// The config file that failed to load.
    pub fn path(&self) -> &Path {
        match self {
            ConfigRecovery::Quarantined { path, .. } => path,
            ConfigRecovery::QuarantineFailed { path, .. } => path,
            ConfigRecovery::FolderNotOpened { path, .. } => path,
            ConfigRecovery::Refused { path, .. } => path,
            ConfigRecovery::LeftInPlace { path, .. } => path,
        }
    }

    /// Whether saving is blocked for the session: the file is still at its name and a write would destroy it.
    fn blocks_saving(&self) -> bool {
        match self {
            ConfigRecovery::Quarantined { .. } => false,
            ConfigRecovery::QuarantineFailed { .. } => true,
            ConfigRecovery::FolderNotOpened { .. } => true,
            ConfigRecovery::Refused { .. } => true,
            ConfigRecovery::LeftInPlace { .. } => true,
        }
    }

    fn log(&self) {
        match self {
            ConfigRecovery::Quarantined { path, error, backup } => error!(
                path = %path.display(), error = error as &dyn std::error::Error, backup = %backup.display(),
                "config file unreadable; quarantined to backup, starting with defaults"
            ),
            ConfigRecovery::QuarantineFailed { path, error, failure } => error!(
                path = %path.display(), error = error as &dyn std::error::Error, backup_error = failure as &dyn std::error::Error,
                "config file unreadable and backup failed; saving disabled for this session"
            ),
            ConfigRecovery::FolderNotOpened { path, failure } => error!(
                path = %path.display(), error = failure as &dyn std::error::Error,
                "config folder could not be opened; starting with defaults, saving disabled for this session"
            ),
            ConfigRecovery::Refused { path, refusal } => error!(
                path = %path.display(), error = refusal as &dyn std::error::Error,
                "config file refused; left untouched, starting with defaults, saving disabled for this session"
            ),
            ConfigRecovery::LeftInPlace { path, found } => error!(
                path = %path.display(),
                error = &ConfigError::NewerVersion { found: *found, supported: AppConfig::VERSION } as &dyn std::error::Error,
                "config file is from a newer release; left untouched, starting with defaults, saving disabled for this session"
            ),
        }
    }
}

/// What one read of `config.json` found, taken inside the update that moves a file this release cannot read aside.
enum Found {
    Config(AppConfig),
    Absent,
    Newer(Option<u32>),
    Refused(Refusal),
    Corrupt(ParseFailure),
    Unreadable(io::Error),
}

impl Found {
    /// What to do with the file now, and what was found.
    fn of(observed: &Observed<AppConfig>) -> (Change<AppConfig>, Found) {
        match &observed.loaded {
            Loaded::Current { value, .. } => (Change::Keep, Found::Config(value.clone())),
            Loaded::Absent => (Change::Keep, Found::Absent),
            // `AppConfig`'s chain floors at version 0, which is not a version: nothing decodes as obsolete.
            Loaded::Obsolete { found, .. } => unreachable!("config.json read as obsolete version {found}"),
            Loaded::Newer { found, .. } => (Change::Keep, Found::Newer(*found)),
            // `ParseFailure` is category and position only: never the serde error, whose Display echoes content.
            Loaded::Corrupt { failure, .. } => (Change::MoveAside, Found::Corrupt(*failure)),
            // A refusal says this process may not read the file, not that it is damaged: it stays where it is.
            Loaded::Unreadable { error, .. } => match Refusal::from_error(error) {
                Some(refusal) => (Change::Keep, Found::Refused(*refusal)),
                None => (Change::MoveAside, Found::Unreadable(copy_of(error))),
            },
        }
    }
}

/// A copy of `error`, which `Loaded` lends and `ConfigError::Read` owns: the OS code (which may sit inside a wrapper
/// that names the NTSTATUS), else the kind. An `io::Error` cannot be cloned, and any other payload is not a type this
/// can rebuild. Never a refusal: [`Found::of`] leaves the file of one where it is.
fn copy_of(error: &io::Error) -> io::Error {
    debug_assert!(Refusal::from_error(error).is_none(), "a refusal is not copied");
    match util::error::raw_os_error(error) {
        Some(code) => io::Error::from_raw_os_error(code),
        None => io::Error::from(error.kind()),
    }
}

/// Owns the config file and the load-time recovery state. All GUI saves go
/// through [`ConfigStore::save`] so a file that could not be preserved blocks
/// destructive writes for the whole session.
pub struct ConfigStore {
    file: VersionedFile<AppConfig>,
    /// Set when the file is, or may be, still at its name (it could not be moved aside, it is from a newer release,
    /// its read was refused, or its folder did not open): writing would destroy it. See
    /// [`ConfigRecovery::blocks_saving`].
    save_blocked: bool,
}

impl ConfigStore {
    /// Load `config.json` from `dir`, moving a corrupt/unreadable file aside to a `.bak`.
    ///
    /// Missing file → defaults, no recovery (first launch). A file from a newer
    /// release, a read the process was refused, or a folder that does not open → defaults, nothing moved, saving
    /// blocked.
    pub fn load(dir: &Path, principal: Principal) -> (Self, AppConfig, Option<ConfigRecovery>) {
        let file = VersionedFile::<AppConfig>::for_process(dir, principal);
        let path = file.path().to_path_buf();
        let mut found = None;
        let outcome = file.update(&ConfigPlacement, |observed| {
            let (change, what) = Found::of(observed);
            found = Some(what);
            (change, ())
        });
        let (config, recovery) = match (found, outcome) {
            (Some(Found::Config(config)), _) => (config, None),
            (Some(Found::Absent), _) => (AppConfig::default(), None),
            (Some(Found::Newer(found)), _) => (AppConfig::default(), Some(ConfigRecovery::LeftInPlace { path, found })),
            (Some(Found::Refused(refusal)), _) => {
                (AppConfig::default(), Some(ConfigRecovery::Refused { path, refusal }))
            }
            (Some(Found::Corrupt(failure)), moved) => {
                let error = ConfigError::Parse { failure };
                (AppConfig::default(), moved_aside(path, error, moved))
            }
            (Some(Found::Unreadable(source)), moved) => {
                let error = ConfigError::Read { source };
                (AppConfig::default(), moved_aside(path, error, moved))
            }
            // The folder did not open, so nothing was read.
            (None, Err(failure)) => {
                let recovery = ConfigRecovery::FolderNotOpened {
                    path,
                    failure: io_of(failure),
                };
                (AppConfig::default(), Some(recovery))
            }
            (None, Ok(_)) => unreachable!("an update that read nothing succeeded"),
        };

        if let Some(r) = &recovery {
            r.log();
        }

        // Config load is the first site in any process that holds a server
        // address, so arming here precedes every log line that could carry
        // one — including the recovery `error!` above's successors.
        crate::logging::redact_arm::arm_config(&config);

        let save_blocked = recovery.as_ref().is_some_and(ConfigRecovery::blocks_saving);
        (Self { file, save_blocked }, config, recovery)
    }

    pub fn path(&self) -> &Path {
        self.file.path()
    }

    /// Save `config`, unless a file that could not be preserved (or read, or reached) blocked saving.
    ///
    /// Not a synchronization point beyond the file's own lock: concurrent saves
    /// are serialized by the caller — every GUI site holds the
    /// `AppState::config` mutex across this call.
    pub fn save(&self, config: &AppConfig) -> Result<(), ConfigError> {
        if self.save_blocked {
            return Err(ConfigError::SaveBlocked);
        }
        self.file
            .update(&ConfigPlacement, |_| (Change::Store(config.clone()), ()))
            .map(|((), _)| ())
            .map_err(|source| ConfigError::Write { source })
    }
}

/// What the move aside of a corrupt or unreadable file came to.
fn moved_aside(
    path: PathBuf,
    error: ConfigError,
    moved: Result<((), UpdateOutcome), StoreError>,
) -> Option<ConfigRecovery> {
    match moved {
        Ok(((), UpdateOutcome::MovedAside(backup))) => Some(ConfigRecovery::Quarantined { path, error, backup }),
        // The file was gone by the time it was moved: nothing is at the name, nothing was lost.
        Ok(((), UpdateOutcome::Absent)) => None,
        Ok(((), other)) => unreachable!("a move aside came to {other:?}"),
        Err(failure) => Some(ConfigRecovery::QuarantineFailed {
            path,
            error,
            failure: io_of(failure),
        }),
    }
}

/// The I/O error of a [`StoreError`] that a move aside or an open of the folder returns: neither stores, so neither
/// refuses a store or fails to encode.
fn io_of(error: StoreError) -> io::Error {
    match error {
        StoreError::Io(source) => source,
        other => unreachable!("a move aside or an open of the folder failed with {other:?}"),
    }
}

/// Where `config.json` is written: a folder of the user's own, private because the file holds plaintext passwords.
struct ConfigPlacement;

impl Placement for ConfigPlacement {
    // The staged file is sealed `0600` (unix), and that is the load-bearing protection: a folder this process does not
    // own cannot be chmod'd, and that must not fail the save.
    fn prepare_dir(&self, dir: &Dir) -> io::Result<()> {
        if let Err(source) = dir.secure(None, Some(0o700)) {
            warn!(
                error = &source as &dyn std::error::Error,
                "could not tighten config directory permissions; continuing"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "config_store_tests.rs"]
mod config_store_tests;
