//! The covers Hole holds, read back from the OS, for the privileged lanes' egress waits.

use std::path::Path;

/// A description of every cover (standing lockdown and transient) the OS reports, or `None` when it
/// reports none. `state_dir` is the directory the test engaged its covers with; a cover engaged under
/// any other directory, or whose record is gone, is reported all the same.
///
/// Anything but a confirmed absence counts as held (`CoverPresence::is_present`): a firewall that could
/// not be asked has not shown the cover gone.
pub fn held_covers(state_dir: &Path) -> Option<String> {
    crate::routing::failclosed::cover_oracle::held_covers(state_dir)
}
