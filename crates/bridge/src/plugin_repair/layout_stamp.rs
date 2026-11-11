//! The layout stamp of the plugin folder: a versioned file, `layout.json`, saying which layout the folder holds.
//!
//! An OS record in `util::versioned_file`'s terms, so one this release cannot read (newer, corrupt, unreadable) is
//! never replaced or removed. Repair leaves such a folder alone and connects refuse to run plugins from it.

use std::path::Path;

use serde::{Deserialize, Serialize};
use util::versioned_file::{Obsolete, Role, Schema, VersionedFile, VersionedState, WhyUnreadable};

/// The stamp's file name inside the plugin folder.
pub const STAMP_FILE_NAME: &str = "layout.json";

/// Layout 1: the folder holds the plugins `hole` carries, and this file. The version is the layout number, so the
/// payload has no field that could restate it.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct PluginLayout {}

impl Schema for PluginLayout {
    const VERSION: u32 = 1;
    type Prev = Obsolete<0>;

    fn upgrade(prev: Obsolete<0>) -> Self {
        match prev {}
    }
}

impl VersionedState for PluginLayout {
    const FILE_NAME: &'static str = STAMP_FILE_NAME;
    const ROLE: Role = Role::OsRecord;
}

util::assert_contiguous!(PluginLayout);

/// What a plugin folder's stamp says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StampState {
    /// The stamp is this release's layout.
    Current,
    /// No stamp, or one at or below the floor, dropped on purpose: a folder of no layout this release knows.
    Nothing,
    /// A stamp that exists and is not one to act on.
    Unreadable(WhyUnreadable),
}

/// The stamp of the folder at `dir`. For the service's own folder, the caller has judged it sound first: whoever could
/// write the folder could write the stamp. For an admin's `--plugin-dir` the stamp only tells a Hole plugin folder from
/// a wrong one; it says nothing of who wrote it. The read follows the bridge's vouched-read rules, so a user's link to
/// a folder somebody else owns, or a stamp another user owns, is `Unreadable`.
pub fn state(dir: &Path) -> StampState {
    match VersionedFile::<PluginLayout>::new(dir)
        .observe()
        .loaded
        .into_actionable()
    {
        Ok(Some(_)) => StampState::Current,
        Ok(None) => StampState::Nothing,
        Err(why) => StampState::Unreadable(why),
    }
}

/// Stores the current stamp in the folder, owned by the layout's owner. A stamp this release cannot read is refused
/// and left as it is.
#[cfg(unix)]
pub fn store(layout: &super::PluginDirLayout) -> Result<(), util::versioned_file::StoreError> {
    use util::versioned_file::{Change, DefaultPlacement};
    VersionedFile::<PluginLayout>::new(&layout.dir)
        .update(
            &DefaultPlacement {
                owner: Some(layout.owner),
            },
            |_| (Change::Store(PluginLayout {}), ()),
        )
        .map(|((), _)| ())
}

#[cfg(test)]
#[path = "layout_stamp_tests.rs"]
mod layout_stamp_tests;
