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

/// A cover's on-disk state-file read, distinguishing "never engaged" from "the
/// evidence exists but cannot be read". Collapsing the latter into the former
/// would make [`release_all`] treat a corrupt or version-skewed file as
/// nothing to clear over a host its cover may still be holding closed — see
/// `release_all`'s doc for why that distinction is load-bearing. Generic and
/// declared here (not per-platform) so both macOS state modules share one
/// reader shape.
#[derive(Debug)]
pub enum StateFile<T> {
    /// No file — no cover of this kind was ever engaged (or a prior release
    /// already cleared it).
    Absent,
    /// A file exists but could not be read, parsed, or matched the expected
    /// schema version. Treated as a cover to clear, never as absence.
    Unusable,
    /// A file exists and parsed at the current schema version.
    Present(T),
}

// macOS persists its pf enable token; Windows recovers WFP filters by fixed
// GUID and needs no state.
#[cfg(target_os = "macos")]
pub mod failclosed_state;

#[cfg(target_os = "macos")]
pub mod lockdown_pf_state;

pub mod luid;
pub use luid::{LuidResolver, SystemLuidResolver};

pub mod lockdown_state;

// `pub(crate)` (not the default private) ONLY on the Windows arm: #846's
// `dns_confine::spec` — a sibling module outside this file's own subtree —
// needs `platform::{FILTER_GUIDS, LOCKDOWN_FILTER_GUIDS}` to prove its own
// WFP GUIDs are disjoint from the cover's, so a copy-paste collision can
// never let one's fixed-GUID sweep delete the other's filters. The macOS arm
// is untouched: nothing outside this file needs it.
#[cfg(target_os = "windows")]
#[path = "failclosed/windows.rs"]
pub(crate) mod platform;

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

/// Whether startup recovery disengages the standing cover for a given
/// decision. There are only two answers, and only one of them opens the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoveryDispatch {
    /// The standing cover's own live/dead disposition is untouched. `Adopt`
    /// additionally runs [`reclaim_stale_tun_permit`] (see `recover_lockdown`)
    /// — narrow and provably unable to open a live cover, so it does not
    /// change this classification.
    Inert,
    /// Disengage the standing cover.
    Disengage,
}

/// Classify a [`CoverRecovery`] into whether it disengages the standing cover.
/// Pure, exhaustive, and platform-free, so "`Adopt` never disengages the
/// cover, on either platform" is a testable statement rather than a claim
/// about two bodies of code.
///
/// `Adopt` never disengages because the volatile-permit refresh it used to
/// perform for the SERVER-IP permit moved into `engage_lockdown`: a
/// recovery-time delete would drop a RUNNING first bridge's server permit
/// whenever a second bridge with a fresh state dir adopted the cover,
/// hard-blocking a host whose GUI still said Connected. `Noop` never
/// disengages by definition. Only an explicit recorded-off `Sweep` reaches the
/// firewall to remove protection.
pub(crate) fn recovery_dispatch(decision: crate::routing::CoverRecovery) -> RecoveryDispatch {
    use crate::routing::CoverRecovery::*;
    match decision {
        Noop | Adopt => RecoveryDispatch::Inert,
        Sweep => RecoveryDispatch::Disengage,
    }
}

/// Act on a [`CoverRecovery`] decision for the standing lockdown cover at
/// startup. cfg-free for `routing::recover_routes`. Best-effort: a `Sweep` that
/// cannot disengage is logged, not propagated — startup recovery has no caller
/// to act on it.
///
/// `tun_name` is THIS bridge's own TUN device: its own last-known name from
/// `bridge-routes.json` when that file had something to recover, else the
/// caller's own configured device name (see `routing::recover_routes_with`'s
/// doc — the file's absence is not evidence the reclaim is unneeded). On
/// `Adopt` it gates a narrow reclaim (see [`reclaim_stale_tun_permit`]); the
/// rest of the decision's OS behaviour is unaffected by it.
pub fn recover_lockdown(decision: crate::routing::CoverRecovery, state_dir: &Path, tun_name: Option<&str>) {
    match recovery_dispatch(decision) {
        RecoveryDispatch::Inert => {
            // The standing cover itself is untouched: it must survive the
            // restart (this IS the crash-leak fix), and it may not even be
            // ours. On macOS the dead utun name in the `pass out quick on
            // <tun>` line is harmless (it matches no live interface); pf rules
            // and enable state do not survive a reboot, but the state file
            // does, so the next connect's `engage_lockdown` re-enables pf and
            // reloads a live ruleset. Residual: the boot->first-connect
            // interval is unprotected until that first reconnect re-arms the
            // host.
            if decision == crate::routing::CoverRecovery::Adopt {
                if let Some(tun_name) = tun_name {
                    reclaim_stale_tun_permit(tun_name);
                }
            }
            tracing::info!(
                ?decision,
                "lockdown recovery: no OS action beyond the TUN-permit reclaim"
            );
        }
        RecoveryDispatch::Disengage => {
            tracing::info!("lockdown recovery: sweeping leftover cover (intent off)");
            if let Err(e) = disengage_lockdown(state_dir) {
                tracing::warn!(error = %e, "lockdown sweep could not disengage the cover");
            }
        }
    }
}

/// Windows only: delete the volatile TUN-interface permit pair when
/// `tun_name` no longer resolves to a live `NET_LUID` — i.e. this permit's
/// target adapter is provably gone. Called from [`recover_lockdown`] only on
/// `Adopt`.
///
/// A `NET_LUID` is `IfType<<48 | NetLuidIndex<<24`, and NDIS reassigns a freed
/// `NetLuidIndex` to the next adapter of the same type. Without this, an
/// adopted cover's stale TUN permit — a persistent WFP filter that survives a
/// crash — can silently authorize a LATER, unrelated wintun-based adapter that
/// happens to inherit the freed index, while Hole still reports the kill
/// switch armed.
///
/// Unlike the server-IP permit (whose recovery-time deletion is exactly what
/// moved BOTH volatile deletes into `engage_lockdown`'s own transaction — see
/// [`crate::routing::CoverRecovery::Adopt`]'s doc), a genuinely running
/// bridge's own `hole-tun` resolves here successfully, so this can never
/// delete a permit a live bridge relies on: it only fires when the name is
/// provably unresolvable.
///
/// macOS's lockdown ruleset matches the TUN by literal interface name (`pass
/// out quick on hole-tun`), not a numeric index the OS can silently reassign
/// to an unrelated adapter, so there is no macOS analogue and this is a no-op
/// there.
pub fn reclaim_stale_tun_permit(tun_name: &str) {
    #[cfg(target_os = "windows")]
    platform::reclaim_stale_tun_permit(&luid::SystemLuidResolver, tun_name);
    #[cfg(not(target_os = "windows"))]
    let _ = tun_name;
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

/// Ask the OS whether a standing lockdown cover from a prior run is present,
/// keyed on the cover's OWN evidence (NOT `bridge-routes.json` — the cover's
/// lifetime is independent of routes).
///
/// - **Windows**: query every lockdown filter GUID with `FwpmFilterGetByKey0`.
/// - **macOS**: read our own ruleset label back from `pfctl -s labels`, falling back to `bridge-lockdown-pf.json`.
///
/// [`CoverPresence::Indeterminate`](crate::routing::CoverPresence::Indeterminate)
/// means the OS was asked and its answer was unusable;
/// [`CoverPresence::Unreachable`](crate::routing::CoverPresence::Unreachable)
/// means it could not be asked at all. Neither ever authorises removing
/// protection on its own — see [`crate::routing::decide_cover_recovery`].
pub fn lockdown_cover_presence(state_dir: &Path) -> crate::routing::CoverPresence {
    platform::lockdown_cover_presence(state_dir)
}

/// Clear every fail-closed cover this platform can install — both the
/// transient block-until-connected cover and the standing lockdown cover —
/// without ever asking whether either is present. This is the escape from a
/// stranded cover: the tray's Unblock item and turning the kill switch off
/// both reach the host through this one function, and nothing else in this
/// crate clears a cover conditionally on its presence.
///
/// Contract, load-bearing for every caller:
///
/// 1. **Unconditional.** Never probes the LIVE cover (the WFP/pf objects
///    themselves) to decide whether to act. Idempotent — a clean host
///    returns `Ok`. On macOS, "clean host" is read from Hole's own state
///    file — `StateFile::Absent` — because pf has no query for "who is
///    holding this ruleset"; the file is the only record. A state file lost
///    out from under a genuinely live cover (not corrupt — entirely absent,
///    e.g. an external wipe of `state_dir`) is therefore indistinguishable
///    from a clean host and `release_all` reports `Ok` without touching pf.
///    See CONTRIBUTING.md's disclosed residuals.
/// 2. **Total.** Clears BOTH cover kinds. Clearing only one would leave a
///    user with no way out at all.
/// 3. **No short-circuit.** Every clear is attempted before any failure is
///    examined. The only early return is a Windows engine-open failure, where
///    nothing could have been issued in the first place.
/// 4. **Never a false success from anything `release_all` can observe.** `Ok`
///    means every cover this call could detect is cleared. The converse does
///    not hold — the function may report `Err` over a host that is in fact
///    open. That asymmetry is deliberate: a false `Err` keeps the escape on
///    the tray menu and the intent armed, while a false `Ok` over a
///    *detected* cover is the lockout this function exists to remove. Item 1
///    is the one case where `Ok` can be reported over a still-blocked host —
///    it is not a violation of this clause, since the cover left no evidence
///    to detect.
/// 5. **Bookkeeping is best-effort, except the state-file clear.** The macOS
///    `pfctl -X` refcount drop and the Windows sublayer/provider delete log a
///    warning on failure and do not fail the call. A cover's state-file clear
///    is different: it is *skipped* whenever that cover's replacement ruleset
///    did not confirm, because the file is the cover's only record — clearing
///    it after an unconfirmed restore would make the next call read a clean
///    host while the block persists (a manufactured, permanent lockout).
///
/// Windows keeps no cover state file at all: the filter set is compiled-in
/// fixed GUIDs, so there is no bookkeeping that can be corrupt or
/// version-skewed and nothing to erase — only GUID sweeps run there.
pub fn release_all(state_dir: &Path) -> Result<(), RoutingError> {
    platform::release_all(state_dir)
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

// Privileged-lane real-firewall proof that `release_all` really clears both
// cover kinds and never a clean host's live ruleset. Gated identically to
// `lockdown_privileged_tests` above — see that module's doc.
#[cfg(test)]
#[path = "failclosed/release_privileged_tests.rs"]
mod release_privileged_tests;

// Privileged-lane falsification: engages the REAL standing lockdown
// cover against two REAL, live TUN devices and proves the tunnel-permit rule
// is sensitive to the interface it names, not merely present. Gated
// identically to `lockdown_privileged_tests` above — see that module's doc.
#[cfg(test)]
#[path = "failclosed/live_tun_permit_privileged_tests.rs"]
mod live_tun_permit_privileged_tests;
