//! Persisted plugin process identities for crash recovery.
//!
//! The bridge writes each plugin child's `ProcessIdRecord` to a JSON file when
//! a plugin chain starts and reads it back on startup to reap processes leaked
//! by a previous crashed run. Mirrors the `routing::state` crash-recovery
//! pattern. `plugin_recovery` owns the reap and is the only component allowed
//! to delete the file.
//!
//! A record pairs the pid with the kernel's own start token, so a recycled pid
//! never restores to the recorded process — see `cosca::identity`.

use serde::{Deserialize, Serialize};
use std::path::Path;
use util::versioned_file::{
    Change, DefaultPlacement, Loaded, Obsolete, Role, Schema, StoreError, UpdateOutcome, VersionedFile, VersionedState,
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

/// Deletes the record. One this release cannot read is kept ([`UpdateOutcome::Kept`]).
pub fn clear(state_dir: &Path) -> Result<UpdateOutcome, StoreError> {
    file(state_dir)
        .update(&DefaultPlacement::default(), |_| (Change::Remove, ()))
        .map(|((), outcome)| outcome)
}

#[cfg(test)]
#[path = "plugin_state_tests.rs"]
mod plugin_state_tests;
