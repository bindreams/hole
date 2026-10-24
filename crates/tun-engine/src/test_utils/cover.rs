//! The standing lockdown cover, read back from the OS, for the privileged lanes' egress waits.

use std::path::Path;

/// A description of the standing lockdown cover the OS reports, or `None` when it reports none.
///
/// Anything but a confirmed absence counts as held (`CoverPresence::is_present`): a firewall that could
/// not be asked has not shown the cover gone. The read is the one the production sweep makes.
pub fn held_lockdown(state_dir: &Path) -> Option<String> {
    let presence = crate::routing::failclosed::lockdown_cover_presence(state_dir);
    presence
        .is_present()
        .then(|| format!("a standing lockdown cover (OS says {presence:?})"))
}
