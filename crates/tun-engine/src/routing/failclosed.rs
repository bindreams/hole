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

#[cfg(target_os = "macos")]
pub mod lockdown_pf_state;

pub mod luid;
pub use luid::{LuidResolver, SystemLuidResolver};

pub mod lockdown_state;

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
///
/// Opaque wrapper over the private `platform::Cover` (the platform module can't
/// be named by `#[cfg]`-free callers). `_inner` is held only for its `Drop`,
/// which does the disengage — no explicit `Drop for Cover` needed.
pub struct Cover {
    _inner: platform::Cover,
}

impl crate::routing::CoverGuard for Cover {
    /// Persist the underlying filters without disengaging: consumes the guard so
    /// its `Drop` does not run. The filters are persistent-by-design, so leaving
    /// them in force across a cutover restart is exactly correct — the new
    /// bridge re-adopts them. Forgetting the inner guard also skips its other
    /// teardown (the Windows WFP engine handle close), so call only immediately
    /// before process exit (see [`CoverGuard::disarm`]).
    fn disarm(self) {
        std::mem::forget(self._inner);
    }
}

/// Engage the cover blocking all egress except loopback and `server_ip`.
/// `state_dir` is where macOS persists its enable token for crash recovery
/// (unused on Windows). On failure the host is left uncovered.
pub fn engage(server_ip: IpAddr, state_dir: &Path) -> Result<Cover, RoutingError> {
    Ok(Cover {
        _inner: platform::engage(server_ip, state_dir)?,
    })
}

/// Sweep a transient cover left behind by a crashed run. Idempotent — a no-op
/// when no cover is present. Called from `routing::recover_routes` at bridge
/// startup. When `adopting` is true a standing lockdown cover is being adopted,
/// so the transient restore must leave the lockdown ruleset in force (macOS
/// skips the `/etc/pf.conf` reload).
pub fn recover_cover(state_dir: &Path, adopting: bool) {
    platform::recover_cover(state_dir, adopting);
}

/// Engage the standing lockdown cover (loopback + TUN + onward-server + —on
/// Windows— plugin/bridge App-IDs permitted, all else blocked). Returns the
/// SAME [`Cover`] wrapper the transient `engage` returns — the platform guard
/// is kind-aware, so dropping it disengages the lockdown cover specifically.
/// On Windows the LUID is re-resolved here every engage (never persisted). On
/// failure the host is left uncovered; the bridge's fail-FATAL caller aborts
/// the start. `app_ids` is empty on macOS (pf has no per-process matching).
pub fn engage_lockdown(
    server_ip: IpAddr,
    tun_name: &str,
    resolver: &dyn LuidResolver,
    app_ids: &[std::path::PathBuf],
    state_dir: &Path,
) -> Result<Cover, RoutingError> {
    #[cfg(target_os = "windows")]
    {
        let luid = resolver.resolve(tun_name)?;
        Ok(Cover {
            _inner: platform::engage_lockdown(server_ip, luid, app_ids, state_dir)?,
        })
    }
    #[cfg(target_os = "macos")]
    {
        let _ = (resolver, app_ids);
        Ok(Cover {
            _inner: platform::engage_lockdown(server_ip, tun_name, state_dir)?,
        })
    }
}

/// Act on a [`CoverRecovery`] decision for the standing lockdown cover at
/// startup. Dispatches to the platform reconciler: `Adopt` keeps the host
/// fail-closed, refreshing the volatile TUN + server permits; `Sweep` fully
/// disengages; `Noop` does nothing. cfg-free for `routing::recover_routes`.
/// Best-effort: a `Sweep` that cannot disengage is logged, not propagated —
/// startup recovery has no caller to act on it.
pub fn recover_lockdown(decision: crate::routing::CoverRecovery, state_dir: &Path) {
    use crate::routing::CoverRecovery::*;
    match decision {
        Noop | Adopt => platform::recover_lockdown(decision, state_dir),
        Sweep => {
            if let Err(e) = disengage_lockdown(state_dir) {
                tracing::warn!(error = %e, "lockdown sweep could not disengage the cover");
            }
        }
    }
}

/// Fail-loud disengage of a standing lockdown cover, with no running bridge.
/// Unlike [`recover_lockdown`]'s best-effort `Sweep`, this PROPAGATES failure so
/// the `bridge unlock` escape hatch can refuse to claim success (and refuse to
/// flip the intent off) while the cover is still engaged. An absent cover is
/// `Ok` (nothing to disengage); a real failure (not elevated / engine open /
/// pfctl) is `Err`.
pub fn disengage_lockdown(state_dir: &Path) -> Result<(), RoutingError> {
    platform::disengage_lockdown(state_dir)
}

/// Whether a standing lockdown cover from a prior run is present — the recovery
/// decision's `prior_present` signal, keyed on the cover's OWN evidence (NOT
/// `bridge-routes.json`). macOS: the `bridge-lockdown-pf.json` state file
/// exists. Windows: always `true` — delete-by-GUID reconciliation is idempotent
/// (a no-op when no filters exist), so probing would only add a redundant WFP
/// enumeration; a `Sweep`/`Adopt` on a clean host does nothing.
pub fn lockdown_cover_present(state_dir: &Path) -> bool {
    #[cfg(target_os = "macos")]
    {
        lockdown_pf_state::load(state_dir).is_some()
    }
    #[cfg(target_os = "windows")]
    {
        let _ = state_dir;
        true
    }
}

/// Windows-only test helper: resolve the LUID then build the spec, exercising
/// the exact resolve-then-build ordering `engage_lockdown` uses, without FWPM.
#[cfg(all(test, target_os = "windows"))]
pub(crate) fn build_lockdown_spec_for_test(
    resolver: &dyn LuidResolver,
    tun_name: &str,
    server_ip: IpAddr,
    app_ids: &[std::path::PathBuf],
) -> platform::CoverSpec {
    let luid = resolver.resolve(tun_name).expect("mock resolver");
    platform::build_lockdown_spec(server_ip, luid, app_ids)
}

// Windows-only: pins the resolve-then-build LUID ordering. macOS keys pf on the
// interface name, so there is no LUID to re-resolve.
#[cfg(all(test, target_os = "windows"))]
#[path = "failclosed/facade_tests.rs"]
mod facade_tests;

// Privileged-lane real-engage verification (#527): engages the REAL OS cover and
// asserts it blocks egress. Gated to the elevated `hole-tests` TUN lane by the
// `TUN` label (see the module docs); excluded from the unprivileged pass.
#[cfg(test)]
#[path = "failclosed/lockdown_privileged_tests.rs"]
mod lockdown_privileged_tests;
