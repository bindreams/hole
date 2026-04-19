//! DNS crash recovery.
//!
//! Called at bridge startup *after* the IPC socket bind succeeds — matches
//! the existing convention in [`crate::plugin_recovery`] /
//! [`tun_engine::routing::recover_routes`]. Reads `bridge-dns.json`,
//! restores each adapter's prior DNS, deletes the file.
//!
//! **Order in the startup cascade:** this runs *before*
//! `routing::recover_routes` (plan §Components / §Lifecycle). If the
//! process is killed mid-recovery, the user is more likely left with
//! functional DNS + broken routes (fixable via `route delete`) than
//! broken DNS + functional routes (much harder for the user to diagnose).
//! DNS restore is also cheaper (2–4 `netsh`/`networksetup` calls per
//! adapter) than route recovery, so this front-loads the cheap cleanup.

use std::path::Path;

use crate::dns::system;
use crate::dns_state;

/// Clean up system DNS settings left behind by a previous bridge run.
/// Best-effort — errors logged at `warn`, returns `()`.
pub fn recover_dns_config(state_dir: &Path) {
    let Some(state) = dns_state::load(state_dir) else {
        return;
    };

    tracing::info!(
        loopback = %state.chosen_loopback,
        adapter_count = state.adapters.len(),
        "dns_recovery: restoring prior DNS for leaked state"
    );

    let errors = system::restore_all(&state.adapters);
    if !errors.is_empty() {
        tracing::warn!(
            count = errors.len(),
            "dns_recovery: {} adapter restores failed (see prior WARNs)",
            errors.len()
        );
    }

    if let Err(e) = dns_state::clear(state_dir) {
        tracing::warn!(error = %e, "failed to clear DNS state file after recovery");
    }
}

#[cfg(test)]
#[path = "recovery_tests.rs"]
mod recovery_tests;
