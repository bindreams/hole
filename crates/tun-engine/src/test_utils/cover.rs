//! The covers Hole holds, read back from the OS, for the privileged lanes' egress waits.

use std::path::Path;

/// See `routing::failclosed::cover_oracle::held_covers`.
pub fn held_covers(state_dir: &Path) -> Option<String> {
    crate::routing::failclosed::cover_oracle::held_covers(state_dir)
}
