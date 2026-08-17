//! Fail-closed network cover: block all egress except loopback, the SS server
//! IP, and (when a plugin needs it) the ECH-config DoH resolver, as an RAII
//! guard held across a connect attempt so a failed connect leaves the host
//! blocked, not leaked. OS specifics live in the platform submodules; this
//! facade is `#[cfg]`-free for callers.

use std::net::IpAddr;
use std::path::Path;

use crate::error::RoutingError;

/// The one port the resolver permit ever needs: `doh_url_for_ip` in
/// `hole_bridge::dns::ech` never constructs a URL with any other port
/// (its bare `https://` scheme implies this one — see that crate's
/// `DOH_PORT` and its executable pin,
/// `doh_url_for_ip_ports_to_the_https_default`), so this is structurally the
/// sole value the ECH-config fetch can dial. A separate declaration, not an
/// import: this crate sits BELOW `hole-bridge` in the dependency graph and
/// cannot import from it, so the reverse link is what's enforced instead —
/// `pub` (not `pub(crate)`) so `hole-bridge` CAN import and pin it against
/// its own `DOH_PORT` (see `crates/bridge/src/dns/ech_tests.rs`,
/// `resolver_permit_port_matches_doh_port`). Shared by both platform
/// modules here so the port is named in exactly one place on this side of
/// the boundary too.
pub const RESOLVER_PERMIT_PORT: u16 = 443;

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

/// Engage the cover blocking all egress except loopback, `server_ip`, and
/// (when `Some`) `resolver_ip` — see [`crate::routing::Routing::install_failclosed_cover`]
/// for what a caller must already have demonstrated to pass `Some` here.
/// `state_dir` is where macOS persists its enable token for crash recovery
/// (unused on Windows). On failure the host is left uncovered.
pub fn engage(
    server_ip: IpAddr,
    resolver_ip: Option<IpAddr>,
    state_dir: &Path,
    owner: Option<(u32, u32)>,
) -> Result<Cover, RoutingError> {
    Ok(Cover {
        _inner: platform::engage(server_ip, resolver_ip, state_dir, owner)?,
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

/// Fail-loud transient sweep: clears a block-until-connected cover a crash left
/// behind and PROPAGATES failure, so a caller cannot report success over a host
/// it did not open. Verified by re-probing, like the standing disengage — the
/// point is the outcome, not that the calls returned. [`recover_cover`] stays
/// best-effort: startup recovery has no caller to act on an error.
pub fn sweep_transient_verified(state_dir: &Path) -> Result<(), RoutingError> {
    platform::sweep_transient_verified(state_dir)
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
    owner: Option<(u32, u32)>,
) -> Result<Cover, RoutingError> {
    #[cfg(target_os = "windows")]
    {
        let _ = owner;
        let luid = resolver.resolve(tun_name)?;
        Ok(Cover {
            _inner: platform::engage_lockdown(server_ip, luid, app_ids, state_dir)?,
        })
    }
    #[cfg(target_os = "macos")]
    {
        let _ = (resolver, app_ids);
        Ok(Cover {
            _inner: platform::engage_lockdown(server_ip, tun_name, state_dir, owner)?,
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

/// What a probe of the standing lockdown cover found. Three states, not a bool:
/// a probe that cannot reach the OS knows nothing, and folding that into "no
/// cover" would report an all-clear over a host our own filters are still
/// holding closed — and hide the escape, which keys on the same signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverState {
    /// Our lockdown cover is in force: the host has no egress but the permits.
    Engaged,
    /// Confirmed absent — no cover of ours is holding the host.
    Absent,
    /// The probe could not answer (WFP engine open failed, `pfctl` unreadable).
    Unknown,
}

impl CoverState {
    /// Whether anything but a CONFIRMED absence was observed — the single
    /// question both consumers ask, deliberately one method rather than two
    /// synonyms: recovery must reconcile a cover it cannot rule out (`Adopt` and
    /// `Sweep` are idempotent, so acting on a phantom is free while skipping a
    /// real one strands it), and the status surface must offer the way out for
    /// the same reason. Splitting them would let a change to what `Unknown`
    /// means for one silently change it for the other.
    pub fn is_present(self) -> bool {
        !matches!(self, CoverState::Absent)
    }
}

/// Gate a disengage on a post-disengage probe. `Ok` means the OS confirms the
/// cover is gone — not that a call returned. Shared by both platforms so
/// `disengage_lockdown`'s fail-loud contract is one rule, not two.
pub(crate) fn verify_disengaged(state: CoverState) -> Result<(), RoutingError> {
    match state {
        CoverState::Absent => Ok(()),
        CoverState::Engaged => Err(RoutingError::RouteSetup(
            "the lockdown cover is still engaged after disengaging; the host remains blocked".into(),
        )),
        CoverState::Unknown => Err(RoutingError::RouteSetup(
            "could not confirm the lockdown cover was disengaged; the host may remain blocked".into(),
        )),
    }
}

/// Whether our STANDING lockdown cover is holding the host closed RIGHT NOW.
/// Distinct from [`lockdown_cover_present`], which asks the reconciliation
/// question ("is there prior-run state to act on?") and is deliberately more
/// lenient on macOS. The two coincide on Windows: its filters are persistent, so
/// anything present is in force.
pub fn lockdown_cover_state(state_dir: &Path) -> CoverState {
    platform::lockdown_cover_state(state_dir)
}

/// Whether the TRANSIENT block-until-connected cover is holding the host closed.
///
/// Probed for the same reason as the standing one: its filters are persistent
/// too, so a crash mid-connect leaves them blocking with no guard anywhere in the
/// next process. Without this, a host held closed by a stranded transient cover
/// reports as plain "Disconnected" with no action offered — the same lockout the
/// standing probe exists to end, one key set over.
pub fn transient_cover_state(state_dir: &Path) -> CoverState {
    platform::transient_cover_state(state_dir)
}

/// The strongest claim about whether HOLE is holding the host closed, from either
/// cover. `Engaged` if either is; otherwise `Unknown` if either is; else `Absent`.
pub fn any_cover_state(state_dir: &Path) -> CoverState {
    match (lockdown_cover_state(state_dir), transient_cover_state(state_dir)) {
        (CoverState::Engaged, _) | (_, CoverState::Engaged) => CoverState::Engaged,
        (CoverState::Unknown, _) | (_, CoverState::Unknown) => CoverState::Unknown,
        _ => CoverState::Absent,
    }
}

/// Whether a standing lockdown cover from a prior run is present — the recovery
/// decision's `prior_present` signal, keyed on the cover's OWN evidence (NOT
/// `bridge-routes.json`).
///
/// macOS stays lenient: the `bridge-lockdown-pf.json` state file existing is
/// enough. pf is disabled and its ruleset flushed across a reboot while that
/// file survives, so a stricter test would make `Sweep` skip the very file it
/// exists to clear. Windows probes for real — [`CoverState::is_present`] treats
/// an unanswerable probe as present so reconciliation still runs.
pub fn lockdown_cover_present(state_dir: &Path) -> bool {
    #[cfg(target_os = "macos")]
    {
        lockdown_pf_state::load(state_dir).is_some()
    }
    #[cfg(target_os = "windows")]
    {
        platform::lockdown_cover_state(state_dir).is_present()
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

#[cfg(test)]
#[path = "failclosed/cover_state_tests.rs"]
mod cover_state_tests;

// Privileged-lane real-engage verification (#527): engages the REAL OS cover and
// asserts it blocks egress. Gated to the elevated `hole-tests` TUN lane by the
// `TUN` label (see the module docs); excluded from the unprivileged pass.
#[cfg(test)]
#[path = "failclosed/lockdown_privileged_tests.rs"]
mod lockdown_privileged_tests;
