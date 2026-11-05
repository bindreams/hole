//! Persisted plugin process identities for crash recovery.
//!
//! The bridge writes each plugin child's `ProcessIdRecord` to a JSON file when
//! a plugin chain starts and reads it back on startup to reap processes leaked
//! by a previous crashed run. Mirrors the `routing::state` crash-recovery
//! pattern. `plugin_recovery` owns the reap and is the only component allowed
//! to remove records from the file.
//!
//! A record pairs the pid with the kernel's own start token, so a recycled pid
//! never restores to the recorded process — see `cosca::identity`.

use serde::{Deserialize, Serialize};
use std::path::Path;
use util::versioned_file::{
    Change, DefaultPlacement, KeepOwner, Loaded, Obsolete, Role, Schema, StoreError, UpdateOutcome, VersionedFile,
    VersionedState,
};

// Types ===============================================================================================================

/// Filename of the persisted state file under `state_dir`. Exported so
/// external tooling can reference the single source of truth.
pub const STATE_FILE_NAME: &str = "bridge-plugins.json";

/// The plugin children a run started and has not yet reaped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginState {
    pub plugins: Vec<cosca::identity::ProcessIdRecord>,
}

/// Schema 2. Version 1 held `{pid, start_time_unix_ms}` records, which cannot name a process.
impl Schema for PluginState {
    const VERSION: u32 = 2;
    type Prev = Obsolete<1>;

    fn upgrade(prev: Obsolete<1>) -> Self {
        match prev {}
    }
}

/// An OS record: it may name plugins that are still running, so one this release cannot read is never replaced or
/// removed.
impl VersionedState for PluginState {
    const FILE_NAME: &'static str = STATE_FILE_NAME;
    const ROLE: Role = Role::OsRecord;
}

util::assert_contiguous!(PluginState);

// I/O =================================================================================================================

/// The plugin record's file. Every read and write of it goes through this type.
pub type PluginFile = VersionedFile<PluginState>;

pub fn file(state_dir: &Path) -> PluginFile {
    VersionedFile::new(state_dir)
}

/// Appends a single record, creating the file if missing. A newer, corrupt or unreadable record is refused
/// ([`StoreError`]) and left as it is: rewriting it with one record would drop the plugins it tracks. An obsolete
/// one is replaced without a backup.
pub fn append_record(
    state_dir: &Path,
    record: cosca::identity::ProcessIdRecord,
    owner: Option<(u32, u32)>,
) -> Result<(), StoreError> {
    file(state_dir)
        .update(&DefaultPlacement { owner }, |observed| {
            let mut state = match &observed.loaded {
                Loaded::Current { value, .. } => value.clone(),
                // Nothing to extend. The role refuses a store over a newer, corrupt or unreadable record; an obsolete
                // one is replaced without a backup, by design.
                Loaded::Absent
                | Loaded::Obsolete { .. }
                | Loaded::Newer { .. }
                | Loaded::Corrupt { .. }
                | Loaded::Unreadable { .. } => PluginState { plugins: Vec::new() },
            };
            state.plugins.push(record);
            (Change::Store(state), ())
        })
        .map(|_| ())
}

/// Reads the record. A failed read, a newer or a corrupt record is for the caller to act on; the schema/JSON detail
/// is logged where it is detected.
pub fn load(state_dir: &Path) -> Loaded<PluginState> {
    file(state_dir).observe().loaded
}

/// Removes exactly the `accounted` records, and the file when none remain.
///
/// The caller loaded the file earlier and settled those records (killed, gone, or unrestorable here); the file may
/// have grown since, and what grew is not the caller's to touch. The rewrite keeps the file's owner and never
/// chowns the directory. A file this release cannot read, or that is missing, has no record of the caller's to edit:
/// nothing is written and the outcome is [`UpdateOutcome::Unchanged`]. A file that cannot be read is named in a warning.
pub(crate) fn remove_accounted(
    state_dir: &Path,
    accounted: &[cosca::identity::ProcessIdRecord],
) -> Result<UpdateOutcome, StoreError> {
    file(state_dir)
        .update(&KeepOwner, |observed| match &observed.loaded {
            Loaded::Current { value, .. } => {
                let mut state = value.clone();
                state.plugins.retain(|r| !accounted.contains(r));
                if state.plugins.is_empty() {
                    (Change::Remove, ())
                } else if state.plugins.len() == value.plugins.len() {
                    (Change::Keep, ())
                } else {
                    (Change::Store(state), ())
                }
            }
            Loaded::Absent => {
                tracing::debug!("no plugin state file: nothing to remove");
                (Change::Keep, ())
            }
            Loaded::Newer { .. } => {
                tracing::warn!("the plugin state file is newer than this release reads: kept, nothing to remove");
                (Change::Keep, ())
            }
            Loaded::Corrupt { .. } => {
                tracing::warn!("the plugin state file is corrupt: kept, nothing to remove");
                (Change::Keep, ())
            }
            Loaded::Unreadable { .. } => {
                tracing::warn!("the plugin state file is unreadable: kept, nothing to remove");
                (Change::Keep, ())
            }
            // Names no process at all, so no record of the caller's is in it.
            Loaded::Obsolete { .. } => (Change::Keep, ()),
        })
        .map(|((), outcome)| outcome)
}

/// Deletes the record iff it is still obsolete. The caller classified it earlier; an append may have rewritten it
/// with live records since, and one this release cannot read is left alone.
pub(crate) fn clear_obsolete(state_dir: &Path) -> Result<UpdateOutcome, StoreError> {
    file(state_dir)
        .update(&DefaultPlacement::default(), |observed| match &observed.loaded {
            Loaded::Obsolete { .. } => (Change::Remove, ()),
            Loaded::Unreadable { .. } => {
                tracing::warn!("the plugin state file could not be read, so it is kept rather than discarded");
                (Change::Keep, ())
            }
            Loaded::Absent | Loaded::Current { .. } | Loaded::Newer { .. } | Loaded::Corrupt { .. } => {
                (Change::Keep, ())
            }
        })
        .map(|((), outcome)| outcome)
}

#[cfg(test)]
#[path = "plugin_state_tests.rs"]
mod plugin_state_tests;
