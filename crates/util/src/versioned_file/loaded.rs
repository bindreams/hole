//! The outcome of reading a versioned file.

use super::{frame, Chain, ChainError, VersionedState};
use crate::parse_error::ParseFailure;

/// The bytes of a file that was not interpreted, kept so a caller can still
/// salvage something from them (a token, for one). `Debug` prints the length
/// only: these bytes may hold an address or a password.
pub struct Raw(Vec<u8>);

impl Raw {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Raw {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Raw(<{} bytes>)", self.0.len())
    }
}

/// What reading a file found. Never rewrites: a migrated value reaches disk at
/// the next `store`.
#[derive(Debug)]
pub enum Loaded<S> {
    /// No file (`ErrorKind::NotFound` only).
    Absent,
    /// The read failed with an I/O error. Says nothing about the bytes, so it
    /// is not [`CannotRead`]: no rule that moves or refuses a file by what it
    /// holds may fire on it. `store` and `remove` give it a cell of its own
    /// per role (`Role::on_store_io_failure`, `Role::on_remove_io_failure`),
    /// and none of them destroys the file.
    Unreadable(std::io::Error),
    /// Not JSON, a bad `version`, or the wrong shape for that version.
    Corrupt { failure: ParseFailure, raw: Raw },
    /// At or below the chain's floor: dropped on purpose.
    Obsolete { found: u32, raw: Raw },
    /// Above this release's version: never interpreted. `found` is `None` for
    /// a version too large for a `u32`.
    Newer { found: Option<u32>, raw: Raw },
    /// Read into the current schema; `found < S::VERSION` means it was
    /// migrated in memory.
    Current { value: S, found: u32 },
}

/// The owner's two causes for a file a release cannot read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CannotRead {
    Newer,
    Corrupt,
}

impl std::fmt::Display for CannotRead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CannotRead::Newer => f.write_str("it is from a newer release"),
            CannotRead::Corrupt => f.write_str("it is corrupt"),
        }
    }
}

impl<S> Loaded<S> {
    /// `Some` for exactly `Newer` and `Corrupt`.
    pub fn cannot_read(&self) -> Option<CannotRead> {
        match self {
            Loaded::Newer { .. } => Some(CannotRead::Newer),
            Loaded::Corrupt { .. } => Some(CannotRead::Corrupt),
            Loaded::Absent | Loaded::Unreadable(_) | Loaded::Obsolete { .. } | Loaded::Current { .. } => None,
        }
    }
}

impl<S: VersionedState> Loaded<S> {
    /// Classifies one read of `S`'s file. Logs a `warn!` for each unusual
    /// outcome and a `debug!` for a migrated one: name, versions and cause,
    /// never a value.
    pub(crate) fn from_read(read: std::io::Result<Vec<u8>>) -> Self {
        let file = S::FILE_NAME;
        let bytes = match read {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Loaded::Absent,
            Err(e) => {
                tracing::warn!(file, kind = ?e.kind(), "state file could not be read");
                return Loaded::Unreadable(e);
            }
        };
        let version = match frame::read_version(&bytes, S::UNVERSIONED_AS) {
            Ok(version) => version,
            Err(failure) => {
                tracing::warn!(file, %failure, "state file is corrupt");
                return Loaded::Corrupt {
                    failure,
                    raw: Raw::new(bytes),
                };
            }
        };
        let found = match version.within(S::VERSION) {
            Ok(found) => found,
            Err(found) => {
                tracing::warn!(
                    file,
                    found = found.map_or_else(|| "beyond u32".to_owned(), |v| v.to_string()),
                    supported = S::VERSION,
                    "state file is from a newer release"
                );
                return Loaded::Newer {
                    found,
                    raw: Raw::new(bytes),
                };
            }
        };
        match <S as Chain>::decode(found, &bytes) {
            Ok(value) => {
                if found < S::VERSION {
                    tracing::debug!(file, found, supported = S::VERSION, "state file migrated in memory");
                }
                Loaded::Current { value, found }
            }
            Err(ChainError::Obsolete) => {
                tracing::warn!(
                    file,
                    found,
                    supported = S::VERSION,
                    "state file version is no longer supported"
                );
                Loaded::Obsolete {
                    found,
                    raw: Raw::new(bytes),
                }
            }
            Err(ChainError::Shape(failure)) => {
                tracing::warn!(file, found, %failure, "state file is corrupt");
                Loaded::Corrupt {
                    failure,
                    raw: Raw::new(bytes),
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "loaded_tests.rs"]
mod loaded_tests;
