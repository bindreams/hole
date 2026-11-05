//! Persist the target and the startup preference as a test's starting state, through the same writers production uses.

use std::path::Path;

use util::versioned_file::StoreError;

use crate::target::{self, StartupPreference, Target};

/// Persist `target` without a decision in front of it. `Target::Unreadable` has no on-disk form and is left unwritten.
pub(crate) fn save(state_dir: &Path, target: &Target, owner: Option<(u32, u32)>) -> Result<(), StoreError> {
    target::apply(state_dir, owner, |_| target.clone()).map(|_| ())
}

/// Persist `pref` over whatever the file holds.
pub(crate) fn save_startup_preference(
    state_dir: &Path,
    pref: &StartupPreference,
    owner: Option<(u32, u32)>,
) -> Result<(), StoreError> {
    target::apply_startup_preference(state_dir, owner, |current| *current = pref.clone())
}
