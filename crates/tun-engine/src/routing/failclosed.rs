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

pub mod boottime_witness;

// Compiled out of a macOS PRODUCTION build — Windows' boot-time twin read-back
// is its only caller — but kept for every lane's TESTS, because the rule it
// encodes is platform-free and a rule proved only where the hazard lives is
// proved nowhere else.
#[cfg(any(target_os = "windows", test))]
pub(crate) mod readback;

// `pub(crate)` (not the default private) ONLY on the Windows arm:
// `dns_confine::spec` — a sibling module outside this file's own subtree —
// needs `platform::{FILTER_GUIDS, LOCKDOWN_FILTER_GUIDS, PROVIDER_GUID,
// SUBLAYER_GUID}` to prove its own WFP GUIDs are disjoint from the cover's,
// so a copy-paste collision can never let one's fixed-GUID sweep delete the
// other's filters (or a collision fail `FwpmProviderAdd0`/`FwpmSubLayerAdd0`
// at runtime). The macOS arm is untouched: nothing outside this file needs
// it.
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
    /// bridge re-adopts them.
    ///
    /// Delegates to the platform guard's own `detach`, which releases whatever
    /// this process still holds, rather than `std::mem::forget` — that skipped
    /// the Windows FWPM engine handle close too, leaking one handle per call
    /// for any caller that keeps running (see [`CoverGuard::disarm`]).
    fn disarm(self) {
        self._inner.detach();
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
///
/// On a platform whose standing cover arms boot-time keys
/// (`platform::STANDING_COVER_ARMS_BOOT_TIME`) the engage also records the
/// [`boottime_witness`], covering the host whose sibling is removed by
/// something that is not a sweep at all (an external FWPM delete, a firewall
/// reset), where no sweep ever had the evidence to copy.
///
/// That write does NOT live here, and bindreams/hole#1010's F3 is why: the
/// moment the fact becomes true is the moment the transaction commits, and
/// `platform::engage_lockdown` has post-commit work after it whose failure
/// leaves the cover standing. A `?` at this level skipped the record for
/// exactly the host class it exists to cover. The record is written inside
/// the platform engage, bound to the commit — see `windows.rs`'s
/// `commit_and_record`.
pub fn engage_lockdown(
    server_ip: IpAddr,
    tun_name: &str,
    resolver: &dyn LuidResolver,
    app_ids: &[std::path::PathBuf],
    state_dir: &Path,
    owner: Option<(u32, u32)>,
) -> Result<Cover, RoutingError> {
    #[cfg(target_os = "windows")]
    let inner = {
        let luid = resolver.resolve(tun_name)?;
        platform::engage_lockdown(server_ip, luid, app_ids, state_dir, owner)?
    };
    #[cfg(target_os = "macos")]
    let inner = {
        let _ = (resolver, app_ids);
        platform::engage_lockdown(server_ip, tun_name, state_dir, owner)?
    };
    Ok(Cover { _inner: inner })
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
            // Named discard: startup recovery has no operator to report a
            // qualification to. What it must NOT discard is the evidence — and
            // it does not, because `disengage_lockdown` persists the
            // [`boottime_witness`] before returning. This is the one sweep in
            // the whole lifecycle that can still see a standing cover's
            // `PERSISTENT` sibling on a host whose kill switch was armed in an
            // earlier boot and recorded off in this one; the sweep itself then
            // deletes that sibling, so no later sweep can re-derive it. "The
            // next start sweeps again" — the justification this discard used
            // to carry — is false for exactly that reason.
            match disengage_lockdown(state_dir) {
                Ok(_clearance_is_persisted_not_reported_at_startup) => {}
                Err(e) => tracing::warn!(error = %e, "lockdown sweep could not disengage the cover"),
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
/// out quick on utunN` — the kernel-assigned name `TunIdentity::alias` reads
/// back, not the fixed `hole-tun` Windows requests), not
/// a numeric index the OS can silently reassign to an unrelated adapter, so
/// there is no macOS analogue and this is a no-op there.
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
///
/// `Ok` carries a [`Clearance`] for the same reason [`release_all`]'s does,
/// and this is the path where it matters most. `bridge unlock` writes the
/// kill-switch intent OFF right after this returns, so — unlike every other
/// disengage — there is no next engage to re-arm or re-delete a boot-time key,
/// and this is the last moment anything will look at one. macOS answers
/// [`Clearance::proven`]: pf has no boot-time analogue, a ruleset does not
/// survive a reboot at all, so a macOS disengage has nothing to leave unproven.
pub fn disengage_lockdown(state_dir: &Path) -> Result<Clearance, RoutingError> {
    sweep_with_witness(state_dir, None, |witness| {
        platform::disengage_lockdown(state_dir, witness)
    })
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
///
///    **`Ok` is therefore qualified, not absolute**, and [`Clearance`] — the
///    `Ok` payload — carries the qualification. `Ok` says every delete this
///    call issued either removed an object or came back empty;
///    [`Clearance::is_proven`] is the narrower claim that what a key answered
///    *proved* it carries nothing. The two differ for exactly one
///    key-and-answer pair: a [`KeyLifetime::BootTime`] key that came back
///    [`KeyOutcome::NotFound`], where the delete issued and answered and the
///    answer proves nothing. The uninstall gate is the caller that must read
///    the narrower one: it is about to delete the only binary that could act on
///    the difference.
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
pub fn release_all(state_dir: &Path) -> Result<Clearance, RoutingError> {
    sweep_with_witness(state_dir, None, |witness| platform::release_all(state_dir, witness))
}

// Release clearance ===================================================================================================

/// Which record backs a fail-closed filter key, and therefore what a
/// delete-by-key that finds nothing PROVES about it.
///
/// This is the whole reason [`Clearance`] exists. A delete-by-key reports one
/// of three things — removed, not-found, or a genuine failure — and the
/// release path has always treated not-found as benign. For one key class
/// that reading is sound; for the other it is an assumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyLifetime {
    /// The record a by-key delete addresses is the key's ONLY record.
    ///
    /// Windows `FWPM_FILTER_FLAG_PERSISTENT`: BFE's store is the record, BFE
    /// re-adds the runtime object from it every boot, and the delete removes
    /// the store entry. macOS pf: the ruleset does not survive a reboot at
    /// all. Either way "not found" proves the key carries nothing.
    Persistent,
    /// The record a by-key delete addresses may not be the key's only record.
    ///
    /// Windows `FWPM_FILTER_FLAG_BOOTTIME`: the runtime object exists only
    /// between kernel start and Base Filtering Engine start, so on any boot
    /// where it is not live the key answers "not found" **whether or not a
    /// boot-time policy record is still provisioned behind it**. That is the
    /// cell that makes this lifetime a separate variant, and no assumption
    /// softens it: an empty answer is what the key gives on a host that armed
    /// the kill switch years ago AND on one that never armed it at all.
    ///
    /// **A watched removal is treated as proof** ([`KeyOutcome::Removed`] →
    /// [`KeyObservation::proves_empty`]), on an ASSUMPTION rather than a
    /// measurement: that `FwpmFilterDeleteByKey0` purges the boot-time policy
    /// record along with the runtime object it demonstrably removes. Nothing
    /// here can check it — every read this crate can take (the delete's code, a
    /// `BOOTTIME_ONLY` enumeration, `netsh wfp show boottimepolicy`) goes
    /// through the Base Filtering Engine, and the record in question is by
    /// definition what applies BEFORE BFE starts at the next boot, so only a
    /// reboot separates "purged" from "provisioned and invisible". The
    /// assumption is the repo owner's, and verifying it on real hardware is
    /// tracked as **bindreams/hole#1043**; if it is wrong, a host that watched
    /// its twins go is silent over a stranded pre-BFE block-all.
    ///
    /// Read the assumption as "the record UNDER THAT KEY" — a filter key is
    /// unique in FWPM, so a delete that removes the object standing under it
    /// leaves no second record there for an earlier boot to have staged. That
    /// is a reading of the assumption, not a separate measurement, and it is
    /// what makes the delete on boot N+1 speak for boot N's provisioning too.
    /// See CONTRIBUTING.md's fail-closed residuals.
    ///
    /// The harm is bounded: BFE's start is what takes a boot-time filter out
    /// of effect, so a stranded record blocks egress across the boot→BFE
    /// window only. How long that window is has not been measured here — the
    /// claim is that it is bounded and ends before the network stack is
    /// generally usable, not any particular duration. It is not permanent
    /// network loss, which is why an unproven key does not fail a release —
    /// but conditionally: the Windows impl's "Boot-time coverage" module doc
    /// (`failclosed/windows.rs`) declines to assert that bound for a host
    /// whose boot itself needs egress (PXE or iSCSI boot, volume unlock
    /// against a network key server), where a block in that window can stop
    /// the boot from ever reaching the BFE start that would lift it. What it
    /// must not do is read as proof.
    BootTime,
}

/// What one delete-by-key observed about its key, keyed on the CAUSE it
/// reported rather than on which consequence the caller happens to share.
///
/// Three return codes, three variants. Deriving one of them from the absence
/// of another — "not `NotFound`, therefore `Removed`" — folds an access
/// denial, a transient RPC failure and a genuine removal into a single
/// verdict, and that verdict is what the MSI deletes `hole.exe` on the
/// strength of. See CLAUDE.md's "per-variant policy lives on the type".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyOutcome {
    /// The delete removed a live object (`ERROR_SUCCESS`). Proof of removal
    /// for ANY lifetime — directly for [`KeyLifetime::Persistent`], whose
    /// runtime object and record are the same thing, and for
    /// [`KeyLifetime::BootTime`] under the purge assumption that variant's doc
    /// states (bindreams/hole#1043). What the privileged lane measured is the
    /// runtime half: the filter leaves the `BOOTTIME_ONLY` view.
    Removed,
    /// The delete found nothing on the key (`FWP_E_FILTER_NOT_FOUND`). Proof
    /// of absence only for [`KeyLifetime::Persistent`].
    NotFound,
    /// The delete neither removed an object nor found the key empty: the OS
    /// refused or failed (not elevated, engine error, RPC failure). Proof of
    /// NOTHING, for any lifetime.
    ///
    /// Such a code also fails the release outright — but it reaches the
    /// clearance fold all the same, because a Windows sweep issues every
    /// delete before reading any code and hands back both halves
    /// ([`SweepOutcome`]). So a refused delete shows up in
    /// [`Clearance::unproven_keys`] beside the failure, and an operator is
    /// told which key the sweep could not settle rather than only that one
    /// could not be.
    Failed,
}

/// What a key's outcome is allowed to say about OTHER keys in the same sweep.
///
/// [`KeyOutcome`] answers "what happened to THIS key". That is the whole
/// answer for a [`KeyLifetime::Persistent`] key, and for a
/// [`KeyLifetime::BootTime`] one only when its object was live enough to be
/// REMOVED. On every other boot a boot-time key cannot report on itself: its
/// runtime object is not live, so it answers [`KeyOutcome::NotFound`] on a host
/// that armed the kill switch years ago and on a host that never armed it at
/// all. Some OTHER key has to separate those, and exactly one can.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRole {
    /// Speaks only for itself. Every key whose own outcome is the whole
    /// answer about it.
    Plain,
    /// The `FWPM_FILTER_FLAG_PERSISTENT` half of the rule a
    /// [`KeyLifetime::BootTime`] twin copies — installed in the SAME
    /// transaction as that twin and never without it.
    ///
    /// This is the one key in a sweep whose outcome is evidence about ANOTHER
    /// key, and it is evidence because of the lifetime it does NOT share:
    /// BFE re-adds a persistent filter from its own store at every boot, so
    /// removing a live object under this key says a standing cover is
    /// installed HERE — on this boot, whichever boot armed it. Every sibling
    /// answering empty says the opposite, that no standing cover is installed
    /// and so no twin was added alongside one.
    ///
    /// The evidence is about the host, not about the twin's own record: it
    /// says whether a boot-time record is POSSIBLE here, never whether one
    /// exists. Only the twin's OWN delete can say that, and only when it
    /// removed a live object — see [`KeyLifetime::BootTime`]. On the boots
    /// where it cannot, this key is what is left.
    BootTimeSibling,
}

/// One key's contribution to a release verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyObservation {
    /// Operator-facing label. Named, never counted: with the binary gone an
    /// operator has only the label to look the key up by.
    pub key: &'static str,
    pub lifetime: KeyLifetime,
    pub outcome: KeyOutcome,
    /// What this key's outcome says about the OTHER keys in the sweep — see
    /// [`KeyRole`].
    pub role: KeyRole,
}

impl KeyObservation {
    /// Whether this observation PROVES its key now carries nothing.
    ///
    /// The whole rule, in one exhaustive match on the pair, so no call site
    /// re-derives it and no variant is grouped with another because they
    /// happen to share a consequence.
    pub fn proves_empty(&self) -> bool {
        match (self.lifetime, self.outcome) {
            // A removal we watched happen is proof for a key whose runtime
            // object and record are the same thing.
            (KeyLifetime::Persistent, KeyOutcome::Removed) => true,
            // The by-key delete addresses a persistent key's only record, so
            // an empty answer proves the key carries nothing.
            (KeyLifetime::Persistent, KeyOutcome::NotFound) => true,
            // A removal we watched happen is proof for a boot-time key too,
            // under bindreams/hole#1043's assumption that the by-key delete
            // purges the policy record along with the runtime object it
            // demonstrably removed. That assumption is the one thing here no
            // lane can measure — see [`KeyLifetime::BootTime`].
            (KeyLifetime::BootTime, KeyOutcome::Removed) => true,
            // A boot-time key answers empty on any boot where its runtime
            // object is not live, whether or not a record survives behind it.
            // This cell never moved and is not covered by #1043's assumption:
            // an empty answer is what the key gives on a host that armed the
            // switch years ago AND on one that never armed it.
            (KeyLifetime::BootTime, KeyOutcome::NotFound) => false,
            // The delete never got an answer about the key at all.
            (_, KeyOutcome::Failed) => false,
        }
    }
}

/// What a [`release_all`] sweep PROVED, as distinct from what it attempted.
///
/// `release_all` returning `Ok` means no delete failed. It does **not** mean
/// every cover key is demonstrably empty: a [`KeyLifetime::BootTime`] key that
/// answered [`KeyOutcome::NotFound`] is consistent both with "never installed"
/// and with "installed in an earlier boot, policy record still provisioned",
/// and nothing this crate can call separates them.
///
/// Collapsing those into a bare `Ok` is the #1003 hazard recreated for the
/// pre-BFE window: the MSI runs `bridge release-covers` under `Return="check"`,
/// reads the exit code as "safe to delete the binary", and `RemoveFiles` then
/// takes away the only thing that could have acted on the difference. So the
/// verdict carries the qualification instead of dropping it, and
/// `#[must_use]` keeps a caller from re-collapsing it by accident.
///
/// **This does not fail the release.** See [`KeyLifetime::BootTime`] for the
/// bound on the harm: refusing an uninstall over a seconds-long boot-window
/// block would trade it for a permanently unremovable product, which is
/// strictly worse. The gate's job is to stop claiming proof it does not have,
/// not to withhold an uninstall.
///
/// It carries a SECOND, independent answer, and the two must not be confused.
/// [`Self::is_proven`] is what the sweep proved; it is false on every Windows
/// sweep run on a boot where no bridge engaged, because the twins answer empty
/// there and an empty answer proves nothing about a boot-time key (see
/// [`KeyLifetime::BootTime`]). [`Self::leftover_keys`] is what is worth
/// telling an operator, which is narrower: an unproven key on a host where no
/// boot-time twin could ever have been armed did not strand anything, and
/// reporting one every time is how the host where it is real gets ignored
/// (see `cutover::release_clearance_report`).
///
/// Two independent things can say a record is possible, and `leftover_keys`
/// reports when EITHER does:
///
/// * [`KeyRole::BootTimeSibling`], collected in the same sweep — live
///   evidence, and the only one that survives a wiped `state_dir`;
/// * [`ArmingWitness`], the persisted record — the only one that survives the
///   sweep that REMOVES the sibling.
///
/// Neither alone is sound. The sibling is consumed by the first sweep that
/// removes it, after which every later sweep reads an empty sibling set as "no
/// cover was ever here" and goes silent for good; the record is lost by a
/// wiped state dir. See [`boottime_witness`] for the full argument.
///
/// **Exactly one observation retracts the record**: a twin whose delete
/// removed a live object, which is [`boottime_witness::WitnessUpdate::Disarm`]
/// and rests on bindreams/hole#1043's purge assumption. A twin that answered
/// EMPTY never retracts anything — that reading is #1003 itself.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "the uninstall gate reads this; dropping it restores the silent `Ok` of #1003"]
pub struct Clearance {
    unproven: Vec<&'static str>,
    sibling: SiblingEvidence,
    witness: ArmingWitness,
    boot_time: BootTimeSightings,
}

/// What the persisted record ([`boottime_witness`]) says about whether a
/// boot-time twin is outstanding on this host.
///
/// Four causes, mirroring [`lockdown_state::Intent`]'s split for the same
/// reason: "no file" and "a file that could not be read" are different
/// findings, and only one of them is consent to stay quiet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmingWitness {
    /// The record parsed and says a twin was armed here and has not since been
    /// watched being removed.
    Armed,
    /// The record parsed and says nothing is outstanding: every twin this host
    /// armed was later watched going.
    Disarmed,
    /// No record file at all. A host that never armed a twin — or one whose
    /// `state_dir` was wiped, which is why this is not the only evidence
    /// [`Clearance::leftover_keys`] consults.
    Unset,
    /// A record exists but could not be read, parsed, or matched the schema.
    /// Reports, for the same reason [`SiblingEvidence::Unknown`] does.
    Unreadable,
}

impl ArmingWitness {
    /// Whether this record leaves a boot-time record possible on this host.
    /// The whole rule, in one exhaustive match, so no call site re-derives it.
    fn record_possible(self) -> bool {
        match self {
            ArmingWitness::Armed | ArmingWitness::Unreadable => true,
            ArmingWitness::Disarmed | ArmingWitness::Unset => false,
        }
    }

    /// Fold two state dirs' records into one answer, the more cautious
    /// winning. The WFP filters a record describes are machine-wide while the
    /// record is per-`state_dir`, so the uninstall gate reads its peers' too —
    /// see [`Clearance::corroborate`].
    fn or(self, other: Self) -> Self {
        if self.record_possible() {
            self
        } else {
            other
        }
    }
}

/// What a sweep observed about the [`KeyLifetime::BootTime`] keys
/// specifically — the only class the persisted record speaks about.
///
/// Separate from [`Clearance::unproven`], which spans every lifetime: a
/// persistent key that a sweep could not delete is a real finding, but it says
/// nothing about whether a boot-time twin is outstanding, and writing the
/// record off it would be the same "shared consequence" merge
/// [`KeyOutcome`] refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BootTimeSightings {
    /// The sweep touched no boot-time key at all — macOS, and any future sweep
    /// list that drops them. It has nothing to say about the record.
    None,
    /// Every boot-time key the sweep touched proved itself empty — i.e. every
    /// one of them was watched being removed, the single outcome that can say
    /// so ([`KeyLifetime::BootTime`]).
    AllProven,
    /// At least one boot-time key's absence went unproven.
    SomeUnproven,
}

/// What a sweep's [`KeyRole::BootTimeSibling`] keys said about whether a
/// boot-time record could exist on this host at all.
///
/// Three causes, kept apart even though two of them share the consequence
/// "report it": a host that demonstrably holds a standing cover and a host
/// whose sibling deletes could not be read are not the same finding, and
/// merging them at the point of observation would leave nothing able to tell
/// them apart later. They are folded once, in [`Clearance::leftover_keys`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SiblingEvidence {
    /// A sibling's delete removed a live object: a standing cover is
    /// installed on this host, so a twin was added alongside it.
    Installed,
    /// Every sibling answered [`KeyOutcome::NotFound`]: no standing cover is
    /// installed here. The only [`SiblingEvidence`] that suppresses a report.
    Absent,
    /// The sweep could not rule a cover out — a sibling's delete neither
    /// removed an object nor found the key empty, or the sweep carried no
    /// sibling key at all. Absence of evidence, which this whole type exists
    /// to stop reading as evidence of absence.
    Unknown,
}

impl SiblingEvidence {
    /// Whether this sweep's siblings leave a boot-time record possible on this
    /// host. The whole rule, in one exhaustive match, so no call site
    /// re-derives it.
    ///
    /// `Absent` is the only answer that rules one out, and it does so only for
    /// THIS sweep's own live evidence — it says nothing about what an earlier
    /// sweep removed, which is why [`ArmingWitness`] is consulted beside it.
    fn record_possible(self) -> bool {
        match self {
            SiblingEvidence::Installed | SiblingEvidence::Unknown => true,
            SiblingEvidence::Absent => false,
        }
    }
}

/// Fold the sibling keys' outcomes into the one question a boot-time key
/// cannot answer about itself. Pure and total over the slice.
///
/// A sweep with NO sibling observation is [`SiblingEvidence::Unknown`], never
/// `Absent`: an empty set trivially satisfies "every sibling answered empty",
/// so the natural reading of the fold is also the one that would silently
/// suppress every report the moment a boot-time key outlived its sibling in
/// some future sweep list.
fn sibling_evidence(observations: &[KeyObservation]) -> SiblingEvidence {
    let outcomes: Vec<KeyOutcome> = observations
        .iter()
        .filter(|o| o.role == KeyRole::BootTimeSibling)
        .map(|o| o.outcome)
        .collect();
    if outcomes.is_empty() {
        return SiblingEvidence::Unknown;
    }
    if outcomes.contains(&KeyOutcome::Removed) {
        return SiblingEvidence::Installed;
    }
    if outcomes.iter().all(|&o| o == KeyOutcome::NotFound) {
        return SiblingEvidence::Absent;
    }
    SiblingEvidence::Unknown
}

impl Clearance {
    /// The verdict for a sweep with nothing left unproven.
    ///
    /// That is every platform whose covers are all
    /// [`KeyLifetime::Persistent`] — today, macOS. It is NOT every Windows
    /// key: the standing lockdown cover's boot-time block-all twins
    /// (bindreams/hole#998) are [`KeyLifetime::BootTime`], so a Windows sweep
    /// that did not watch them go is unproven and must build its verdict with
    /// [`Self::from_observations`] rather than reach for this.
    pub fn proven() -> Self {
        Self {
            unproven: Vec::new(),
            // No key went unproven, so no report can be built from this
            // whatever the sibling evidence would have been; `Absent` states
            // the platform's own reason rather than leaving a placeholder.
            sibling: SiblingEvidence::Absent,
            // Same reason, for the second evidence source: a platform with no
            // boot-time key class never writes a record, so `Unset` is its
            // standing answer rather than a placeholder.
            witness: ArmingWitness::Unset,
            boot_time: BootTimeSightings::None,
        }
    }

    /// Fold per-key observations into a verdict. Pure and total over the
    /// slice: it inspects every observation rather than stopping at the first
    /// unproven one, so the operator message can name all of them.
    ///
    /// The per-observation rule is [`KeyObservation::proves_empty`] and is not
    /// restated here — an observation is unproven iff it did not prove itself
    /// empty, so a new [`KeyOutcome`] or [`KeyLifetime`] variant cannot slip
    /// past this fold by failing to match a filter predicate written here.
    ///
    /// `witness` is the persisted record this sweep was folded against, and it
    /// is a PARAMETER rather than a default so no sweep can be built without
    /// answering the question. A sweep that has no record to consult (macOS,
    /// whose pf ruleset has no boot-time key class) passes
    /// [`ArmingWitness::Unset`] and says so.
    pub fn from_observations(observations: &[KeyObservation], witness: ArmingWitness) -> Self {
        Self {
            unproven: observations
                .iter()
                .filter(|o| !o.proves_empty())
                .map(|o| o.key)
                .collect(),
            sibling: sibling_evidence(observations),
            witness,
            boot_time: boot_time_sightings(observations),
        }
    }

    /// Fold another `state_dir`'s persisted record into this verdict.
    ///
    /// The record is per-`state_dir`; the WFP filters it describes are
    /// machine-wide. An elevated non-`--service` bridge keeps its state in the
    /// interactive user's profile, so the record of a twin IT armed does not
    /// sit where the MSI's SYSTEM-context `release-covers` reads. The
    /// uninstall gate therefore folds in every peer dir it already locks
    /// against a live bridge (`cutover::release_covers_with`); the more
    /// cautious answer wins.
    pub fn corroborate(mut self, witness: ArmingWitness) -> Self {
        self.witness = self.witness.or(witness);
        self
    }

    /// Whether the sweep proved every key it touched is empty. `false` does
    /// NOT mean a cover is present — it means one could not be ruled out.
    pub fn is_proven(&self) -> bool {
        self.unproven.is_empty()
    }

    /// The keys whose absence went unproven, in sweep order. Not deduplicated:
    /// distinct keys share a label, and collapsing them would under-report how
    /// much of the sweep was unproven.
    pub fn unproven_keys(&self) -> &[&'static str] {
        &self.unproven
    }

    /// The unproven keys that could actually have a record behind them ON
    /// THIS HOST — what an operator is told about, as distinct from what the
    /// sweep proved.
    ///
    /// Empty is NOT "the sweep proved everything": [`Self::is_proven`] is
    /// still the proof record and still false. Empty here means BOTH evidence
    /// sources agree no twin could be outstanding on this host — the sweep
    /// found no standing cover installed ([`SiblingEvidence::Absent`]) AND no
    /// record says one was ever armed ([`ArmingWitness::Unset`] or
    /// `Disarmed`). That is what almost every uninstall looks like, and
    /// reporting it every time is how the one host where a leftover is real
    /// gets ignored.
    ///
    /// **Either source reporting is enough**, and the union is the whole fix
    /// for the alternative: the sibling ALONE is consumed by the first sweep
    /// that removes it. An ordinary "turn the kill switch off, then uninstall"
    /// removes the sibling at the first step, and every sweep after it reads
    /// the empty sibling set as "no cover was ever here" — permanently silent,
    /// which is the direction that deletes `hole.exe` over a live twin. The
    /// record alone is lost by a wiped `state_dir`. Neither loss takes the
    /// other with it.
    ///
    /// The other [`SiblingEvidence`] answers report for two different reasons.
    /// `Installed` is the dangerous case this exists to keep visible — a kill
    /// switch armed in an earlier boot, BFE re-adding the persistent half at
    /// this one, the twins answering empty because no twin is ever live once
    /// BFE has started. `Unknown` reports for the opposite reason, that
    /// nothing was ruled out. [`ArmingWitness`] splits the same way.
    pub fn leftover_keys(&self) -> &[&'static str] {
        if self.sibling.record_possible() || self.witness.record_possible() {
            &self.unproven
        } else {
            &[]
        }
    }

    /// What this sweep's own observations say the persisted record should now
    /// hold — derived here, once, and never at a write site.
    ///
    /// Total over the pair. Two load-bearing cells. The `AllProven` one
    /// ignores the sibling entirely — a twin this sweep watched being removed
    /// is direct evidence about the twin, so there is nothing for a key that
    /// only speaks about the HOST to corroborate. The last one is the reverse:
    /// an unproven boot-time key on a host whose siblings all answered empty
    /// writes NOTHING rather than arming. "No cover is installed now" is not
    /// evidence about a twin's record in EITHER direction, so it neither
    /// reports nor suppresses.
    pub(crate) fn witness_update(&self) -> boottime_witness::WitnessUpdate {
        use boottime_witness::WitnessUpdate;
        match (self.boot_time, self.sibling) {
            // The sweep touched no boot-time key, so it saw nothing the record
            // is about.
            (BootTimeSightings::None, _) => WitnessUpdate::Leave,
            // Watched every one of them go — proof for any lifetime, under
            // bindreams/hole#1043's purge assumption.
            (BootTimeSightings::AllProven, _) => WitnessUpdate::Disarm,
            // A record is possible here and the live evidence for that is
            // about to be deleted by this very sweep. Copy it out first.
            (BootTimeSightings::SomeUnproven, SiblingEvidence::Installed | SiblingEvidence::Unknown) => {
                WitnessUpdate::Arm
            }
            (BootTimeSightings::SomeUnproven, SiblingEvidence::Absent) => WitnessUpdate::Leave,
        }
    }
}

/// Fold the boot-time keys' outcomes into what this sweep can say about the
/// persisted record. Pure and total over the slice.
///
/// Reads [`KeyObservation::proves_empty`] rather than re-deriving which
/// outcomes count, so this and [`Clearance::unproven`] cannot disagree about
/// whether a given key was proven.
///
/// `seen` is tracked separately from `unproven` rather than inferred from an
/// empty loop: "every boot-time key proved empty" is vacuously true of a sweep
/// that touched none, and that reading would clear a real record the moment
/// the twins left the sweep list.
fn boot_time_sightings(observations: &[KeyObservation]) -> BootTimeSightings {
    let mut seen = false;
    let mut unproven = false;
    for o in observations.iter().filter(|o| o.lifetime == KeyLifetime::BootTime) {
        seen = true;
        unproven |= !o.proves_empty();
    }
    match (seen, unproven) {
        (false, _) => BootTimeSightings::None,
        (true, true) => BootTimeSightings::SomeUnproven,
        (true, false) => BootTimeSightings::AllProven,
    }
}

/// One sweep's whole interaction with the persisted boot-time record: consult
/// it before the fold, then update it from what the sweep itself observed.
///
/// Every SWEEP that can remove a standing cover's `PERSISTENT` sibling goes
/// through here, which is what makes the three sites that DISCARD the returned
/// [`Clearance`] safe — `recover_lockdown`'s `Sweep` arm, `SystemRouting::
/// release_all_covers`, and the reconciler's `CoverStep::Release` through it.
///
/// Not every DELETE does. The Windows guard's `Drop` (`platform::Cover`'s
/// `Lockdown` arm) removes the same key list with no `state_dir` to write to,
/// so it can neither arm nor retract; the residual that leaves is disclosed in
/// [`boottime_witness`]'s module doc, and it is an over-report.
/// The evidence is persisted before anything is returned AT ALL — before the
/// `Ok` those three drop, and before the `Err` a failing sweep hands its
/// caller — so dropping the value costs an operator message on that one call
/// and nothing beyond it.
///
/// Generic over the sweep so the SEQUENCE this exists for — a sweep that
/// removes the sibling, followed by one that can no longer see it — is
/// drivable without a firewall, on every platform's lane. A single observation
/// slice cannot express it, which is why the defect was invisible to tests
/// built from one. The sweep returns a [`SweepOutcome`] rather than a `Result`
/// for the reason that type gives: a FAILING sweep is holding observations
/// too, and the sequence where that matters is equally undrivable from a type
/// that throws them away.
fn sweep_with_witness(
    state_dir: &Path,
    owner: Option<(u32, u32)>,
    sweep: impl FnOnce(ArmingWitness) -> SweepOutcome,
) -> Result<Clearance, RoutingError> {
    let witness = boottime_witness::load(state_dir);
    let SweepOutcome { clearance, failure } = sweep(witness);
    // The record is written from what the sweep OBSERVED, before its failure
    // reaches the caller. A failing sweep is not an unobservant one: this
    // codebase's own sweeps issue every delete before inspecting any code, so
    // `Err` arrives after the sibling's delete already succeeded — see
    // [`SweepOutcome`].
    boottime_witness::apply(state_dir, witness, clearance.witness_update(), owner);
    match failure {
        Some(e) => Err(e),
        None => Ok(clearance),
    }
}

/// One sweep's whole result: the verdict built from every observation it made,
/// and the failure — if any — it must still report.
///
/// Deliberately NOT a `Result<Clearance, _>`, and that is bindreams/hole#1010's
/// F1. Both Windows sweeps ISSUE every delete before inspecting any code (a
/// structural property `release_all` and `disengage_lockdown` both state), so
/// a sweep that ends in `Err` has already removed whatever it removed — up to
/// and including the standing cover's `PERSISTENT` sibling, the one piece of
/// live evidence no later sweep can re-derive. A `Result` drops those
/// observations along the `?`, which loses BOTH evidence sources in one act:
/// the sibling gone from the host, the record never written. The defence the
/// discard used to carry — "a sweep that failed observed nothing it can write
/// down" — is false for exactly that reason.
#[must_use = "this carries a `Clearance` AND a failure; dropping it discards both at once, which \
              is the pair this type exists to keep"]
pub(crate) struct SweepOutcome {
    clearance: Clearance,
    failure: Option<RoutingError>,
}

impl SweepOutcome {
    /// Every delete was issued and answered, and none failed.
    pub(crate) fn completed(clearance: Clearance) -> Self {
        Self {
            clearance,
            failure: None,
        }
    }

    /// The sweep failed. `clearance` is folded from what it DID observe, which
    /// is a complete observation set for a sweep that issued every delete
    /// before reading any code, and the empty fold for one that never reached
    /// the firewall at all.
    pub(crate) fn failed(clearance: Clearance, error: RoutingError) -> Self {
        Self {
            clearance,
            failure: Some(error),
        }
    }

    /// What the sweep observed, whether or not it also failed. This is the
    /// half the `?` used to throw away.
    #[cfg(test)]
    pub(crate) fn clearance(&self) -> &Clearance {
        &self.clearance
    }

    /// Collapse into the `Result` a caller with no record to update wants.
    ///
    /// [`sweep_with_witness`] deliberately does NOT use this: it destructures
    /// the struct so the observations reach the record before the failure
    /// reaches the caller. This is for the two callers that have no record in
    /// play at all — macOS's `Drop` wrapper (no boot-time key class) and the
    /// unit tests of the verdict folds.
    ///
    /// What it is NOT for is the sweeps: reaching for it there is how the
    /// observations got discarded in the first place.
    #[cfg(any(test, target_os = "macos"))]
    pub(crate) fn into_result(self) -> Result<Clearance, RoutingError> {
        match self.failure {
            Some(e) => Err(e),
            None => Ok(self.clearance),
        }
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

// Deliberately NOT platform-gated. The clearance fold is the decision the
// uninstall gate reads, and the key class it exists for is Windows-only — so
// gating its tests to Windows would put the proof on the same platform as the
// hazard and nowhere else. Pure, so every lane can falsify it.
#[cfg(test)]
#[path = "failclosed/clearance_tests.rs"]
mod clearance_tests;

// Same reason as clearance_tests above — a source-tree scan, so every lane can
// run it.
#[cfg(test)]
#[path = "failclosed/boot_time_tripwire_tests.rs"]
mod boot_time_tripwire_tests;

// Also a source-tree scan, also deliberately NOT platform-gated. The type it
// guards is Windows-only; the invariant (CLAUDE.md's "per-variant policy lives
// on the type") is not, and neither is reading text.
#[cfg(test)]
#[path = "failclosed/stale_key_policy_tests.rs"]
mod stale_key_policy_tests;

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

// Privileged-lane measurement (#998) of what WFP does with a BOOT-TIME filter:
// whether it accepts one under our persistent containers, keeps them, and
// removes it on a by-key delete. Windows-only — macOS's pf ruleset has no
// boot-time equivalent (pf rules do not survive a reboot at all, #617). Gated
// identically to `lockdown_privileged_tests` above.
#[cfg(all(test, target_os = "windows"))]
#[path = "failclosed/boottime_privileged_tests.rs"]
mod boottime_privileged_tests;
