//! Fail-closed network cover: block all egress except loopback and the SS
//! server IP, as an RAII guard. Used by the update cutover (PR3) to keep the
//! tunnel leak-free during the brief bridge restart. OS specifics live in the
//! platform submodules; this facade is `#[cfg]`-free for callers.

use std::net::IpAddr;
use std::path::Path;

use crate::error::RoutingError;

// macOS persists its pf enable token; Windows recovers WFP filters by fixed
// GUID and needs no state.
#[cfg(target_os = "macos")]
pub mod failclosed_state;

#[cfg(target_os = "windows")]
#[path = "failclosed/windows.rs"]
mod platform;

#[cfg(target_os = "macos")]
#[path = "failclosed/macos.rs"]
mod platform;

/// RAII guard for an engaged fail-closed cover. Dropping it disengages the
/// cover (Windows: delete the WFP filters by GUID; macOS: restore
/// `/etc/pf.conf` and drop the pf enable refcount). `Send` so the PR3 cutover
/// coordinator can hold it across `.await`.
//
// `platform::Cover` carries its own `Drop`; the field-drop runs it. No
// explicit `Drop for Cover` needed.
pub struct Cover {
    #[allow(dead_code)] // engaged only by PR3's cutover; PR2 has no production caller
    inner: platform::Cover,
}

/// Engage the cover blocking all egress except loopback and `server_ip`.
/// `state_dir` is where macOS persists its enable token for crash recovery
/// (unused on Windows). On failure the host is left uncovered.
pub fn engage(server_ip: IpAddr, state_dir: &Path) -> Result<Cover, RoutingError> {
    Ok(Cover {
        inner: platform::engage(server_ip, state_dir)?,
    })
}

/// Sweep a cover left behind by a crashed run. Idempotent — a no-op when no
/// cover is present. Called from `routing::recover_routes` at bridge startup.
pub fn recover_cover(state_dir: &Path) {
    platform::recover_cover(state_dir);
}

/// Engage the standing lockdown cover: block all egress except loopback, the
/// `tun_luid` interface (Windows) so app traffic flows, the `app_ids` binaries,
/// and `server_ip`. `state_dir` is where macOS persists its recovery state.
/// On failure the host is left uncovered (the caller decides fail-FATAL).
#[cfg(target_os = "windows")]
pub fn engage_lockdown(
    server_ip: IpAddr,
    tun_luid: u64,
    app_ids: &[std::path::PathBuf],
    state_dir: &Path,
) -> Result<Cover, RoutingError> {
    Ok(Cover {
        inner: platform::engage_lockdown(server_ip, tun_luid, app_ids, state_dir)?,
    })
}
