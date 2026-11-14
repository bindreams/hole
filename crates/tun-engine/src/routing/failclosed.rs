//! Fail-closed network cover: block all egress except loopback, the SS server
//! IP, and (when a plugin needs it) the ECH-config DoH resolver, as an RAII
//! guard held across a connect attempt so a failed connect leaves the host
//! blocked, not leaked. OS specifics live in the platform submodules; this
//! facade is `#[cfg]`-free for callers. The design is in
//! docs/contributing/architecture/kill-switch.md.
//!
//! Mutators take `&CoverLock`, readers take a path ([`lockdown_cover_presence`], [`boottime_witness::load`]): a read
//! taken outside the lock races a locked writer as the old or the new state, and a read that decides a write is taken
//! again under the lock.

use std::borrow::Cow;
use std::net::IpAddr;
use std::path::Path;

use crate::error::RoutingError;
use util::versioned_file::Loaded;

/// The one port the resolver permit opens: the port `hole_bridge::dns::ech` dials for the ECH-config fetch
/// (`doh_url_for_ip` never builds a URL with another).
///
/// Declared here because this crate sits below `hole-bridge` and cannot import its `DOH_PORT`; `hole-bridge` imports
/// this and pins it against `DOH_PORT` (`resolver_permit_port_matches_doh_port`). Both platform modules use it.
pub const RESOLVER_PERMIT_PORT: u16 = 443;

/// A cover's on-disk state-file read, distinguishing "never engaged" from "the
/// evidence exists but cannot be read". [`release_all`] must never treat the
/// latter as the former, or a corrupt or version-skewed file would read as a clean host. Shared by both macOS
/// state modules.
#[derive(Debug, PartialEq)]
pub enum StateFile<T> {
    /// No file — no cover of this kind was ever engaged (or a prior release
    /// already cleared it).
    Absent,
    /// The read failed with an I/O error other than "not found": the bytes were
    /// never seen, so there is no token to salvage, and nothing may treat the
    /// record as absent or remove it.
    Unreadable,
    /// A file exists and its bytes were read, but they are not a record this
    /// release can use: corrupt, or at a version this release does not read.
    /// Treated as a cover to clear, never as absence.
    ///
    /// `pf_token` is whatever [`StateFile::unusable`] could salvage from the bytes. A version-skewed file still holds
    /// the only copy of the `pfctl -E` ticket; without it the sweep leaks pf's enable refcount until reboot. `None`
    /// when the bytes hold no usable `pf_token`.
    Unusable { pf_token: Option<String> },
    /// A file exists and parsed at the current schema version.
    Present(T),
}

impl<T> StateFile<T> {
    /// [`StateFile::Unusable`] for a record whose BYTES we hold, salvaging its
    /// `pf_token` if one can still be read out of them.
    ///
    /// Lenient where the typed deserialize is strict: it ignores the schema version and any wrong-typed sibling
    /// field. Shared by both macOS state files. `pub` like the type it constructs; a crate-private constructor would be
    /// dead code on every other target of this `#[cfg]`-free module.
    pub fn unusable(bytes: &[u8]) -> Self {
        let pf_token = serde_json::from_slice::<serde_json::Value>(bytes)
            .ok()
            .and_then(|v| v.get("pf_token")?.as_str().map(str::to_owned))
            .filter(|t| !t.is_empty());
        Self::Unusable { pf_token }
    }
}

impl<T: Clone> StateFile<T> {
    /// The fold of a read into the sweep's view: a record that is not `Current` keeps whatever token its bytes still
    /// hold, and a read that failed has no bytes.
    pub fn view(loaded: &Loaded<T>) -> StateFile<T> {
        match loaded {
            Loaded::Current { value, .. } => StateFile::Present(value.clone()),
            Loaded::Absent => StateFile::Absent,
            Loaded::Obsolete { raw, .. } => StateFile::unusable(raw.as_bytes()),
            Loaded::Newer { raw, .. } => StateFile::unusable(raw.as_bytes()),
            Loaded::Corrupt { raw, .. } => StateFile::unusable(raw.as_bytes()),
            Loaded::Unreadable { .. } => StateFile::Unreadable,
        }
    }
}

// macOS persists its pf enable token; Windows recovers WFP filters by fixed GUID and needs no state. Compiled on
// every platform's test build because the rules these records implement are platform-free.
#[cfg(any(target_os = "macos", test))]
pub mod failclosed_state;

#[cfg(any(target_os = "macos", test))]
pub mod lockdown_pf_state;

#[cfg(any(target_os = "macos", test))]
pub mod pf_record;

pub mod luid;
pub use luid::{LuidResolver, SystemLuidResolver};

pub mod lockdown_state;

pub mod boottime_witness;

pub mod cover_lock;
pub use cover_lock::{CoverKind, CoverLock, InstallStamp};

// Windows' boot-time twin read-back is its only caller, so a macOS production build omits it; every test build keeps
// it because the rule is platform-free.
#[cfg(any(target_os = "windows", test))]
pub(crate) mod readback;

// `pub(crate)` on the Windows arm only: `dns_confine::spec` reads `platform::{FILTER_GUIDS, LOCKDOWN_FILTER_GUIDS,
// PROVIDER_GUID, SUBLAYER_GUID}` to prove its WFP GUIDs are disjoint from the cover's.
#[cfg(target_os = "windows")]
#[path = "failclosed/windows.rs"]
pub(crate) mod platform;

#[cfg(target_os = "macos")]
#[path = "failclosed/macos.rs"]
mod platform;

// The pf cover's sequencing (engage, back-out, release, recovery) runs over injected `pfctl` and record seams. This
// compiles the macOS `platform` module a second time on test builds of other hosts, so its tests run everywhere.
#[cfg(all(test, not(target_os = "macos")))]
#[path = "failclosed/macos.rs"]
mod pf_on_any_host;

/// RAII guard for an engaged fail-closed cover. Dropping it disengages the
/// cover (Windows: delete the WFP filters by GUID; macOS: restore the host's rules, then clear the record and, only if
/// that clear took it, drop the pf enable refcount; a record that cannot be read stays). `Send`, so it can be held
/// across `.await`.
///
/// Opaque wrapper over the private `platform::Cover`, whose `Drop` does the disengage.
pub struct Cover {
    _inner: platform::Cover,
}

impl crate::routing::CoverGuard for Cover {
    /// Leave the filters in force across a cutover restart, where the new bridge re-adopts them: consumes the guard
    /// and empties what it holds, so its `Drop` disengages nothing. The platform guard's `detach` releases whatever
    /// this process still holds (on Windows the FWPM engine handle).
    fn disarm(self) {
        self._inner.detach();
    }

    /// Under `lock`, which must be its own state dir's, the guard's `Drop` (the only code that deletes) is the
    /// release, so it runs inside the caller's section.
    fn release(self, lock: &CoverLock) {
        self._inner.stamp().assert_held_under(lock);
        drop(self);
    }

    fn is_current(&self) -> bool {
        self._inner.stamp().is_current()
    }
}

/// Engage the cover blocking all egress except loopback, `server_ip`, and
/// (when `Some`) `resolver_ip` — see [`crate::routing::Routing::install_failclosed_cover`]
/// for what a caller must already have demonstrated to pass `Some` here.
/// `state_dir` is where macOS persists its enable token for crash recovery
/// (unused on Windows), taken from `lock`. On failure the host is left uncovered.
///
/// The returned guard is stamped by `lock`: it releases only while no later install of the transient cover
/// and no sweep that released it has happened ([`CoverLock::stamp_install`]).
pub fn engage(
    lock: &CoverLock,
    server_ip: IpAddr,
    resolver_ip: Option<IpAddr>,
    owner: Option<(u32, u32)>,
) -> Result<Cover, RoutingError> {
    Ok(Cover {
        _inner: platform::engage(lock, server_ip, resolver_ip, owner)?,
    })
}

/// Sweep a transient cover left behind by a crashed run. Idempotent — a no-op
/// when no cover is present. Called from `routing::recover_routes` at bridge
/// startup. When `adopting` is true a standing lockdown cover is being adopted,
/// so the transient restore must leave the lockdown ruleset in force (macOS
/// skips the `/etc/pf.conf` reload).
///
/// Outdates the transient stamps only when the sweep released the cover: one that failed leaves it in force, so a
/// guard still holding it keeps its stamp and its drop retries.
pub fn recover_cover(lock: &CoverLock, adopting: bool) {
    if platform::recover_cover(lock, adopting).is_ok() {
        lock.outdate_stamps(CoverKind::Transient);
    }
}

/// Engage the standing lockdown cover (loopback + TUN + onward-server + —on
/// Windows— plugin/bridge App-IDs permitted, all else blocked). Returns the
/// SAME [`Cover`] wrapper the transient `engage` returns — the platform guard
/// is kind-aware, so dropping it disengages the lockdown cover specifically.
/// On Windows the LUID is re-resolved here every engage (never persisted). On
/// failure the host is left uncovered; the bridge's fail-FATAL caller aborts
/// the start. `app_ids` is ignored on macOS (pf has no per-process matching).
///
/// On a platform whose standing cover arms boot-time keys
/// (`platform::STANDING_COVER_ARMS_BOOT_TIME`) the engage also records the
/// [`boottime_witness`]. The platform engage writes it, bound to the transaction commit (see `windows.rs`'s
/// `commit_and_record`), because post-commit work can fail over a cover already standing.
pub fn engage_lockdown(
    lock: &CoverLock,
    server_ip: IpAddr,
    tun_name: &str,
    resolver: &dyn LuidResolver,
    app_ids: &[std::path::PathBuf],
    owner: Option<(u32, u32)>,
) -> Result<Cover, RoutingError> {
    #[cfg(target_os = "windows")]
    let inner = {
        let luid = resolver.resolve(tun_name)?;
        platform::engage_lockdown(lock, server_ip, luid, app_ids, owner)?
    };
    #[cfg(target_os = "macos")]
    let inner = {
        let _ = (resolver, app_ids);
        platform::engage_lockdown(lock, server_ip, tun_name, owner)?
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

/// Classify a [`CoverRecovery`](crate::routing::CoverRecovery) into whether it disengages the standing cover.
/// Pure and platform-free. Only a recorded-off `Sweep` disengages; `Adopt` never does, because a recovery-time
/// delete would drop a running bridge's server permit when a second bridge adopts the cover (the permit refresh
/// lives in `engage_lockdown`).
pub(crate) fn recovery_dispatch(decision: crate::routing::CoverRecovery) -> RecoveryDispatch {
    use crate::routing::CoverRecovery::*;
    match decision {
        Noop | Adopt => RecoveryDispatch::Inert,
        Sweep => RecoveryDispatch::Disengage,
    }
}

/// Act on a `CoverRecovery` decision for the standing lockdown cover at
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
pub fn recover_lockdown(lock: &CoverLock, decision: crate::routing::CoverRecovery, tun_name: Option<&str>) {
    match recovery_dispatch(decision) {
        RecoveryDispatch::Inert => {
            // The standing cover must survive the restart, and may not be ours. On macOS a dead utun name in the
            // `pass out quick on <tun>` line matches no live interface; pf does not survive a reboot, so the next
            // connect's `engage_lockdown` re-enables pf and reloads the ruleset (the boot-to-first-connect interval is
            // unprotected).
            if decision == crate::routing::CoverRecovery::Adopt {
                if let Some(tun_name) = tun_name {
                    reclaim_stale_tun_permit(lock, tun_name);
                }
            }
            tracing::info!(
                ?decision,
                "lockdown recovery: no OS action beyond the TUN-permit reclaim"
            );
        }
        RecoveryDispatch::Disengage => {
            tracing::info!("lockdown recovery: sweeping leftover cover (intent off)");
            // Startup recovery has no operator to report the clearance to; `disengage_lockdown` has already
            // persisted the evidence in the `boottime_witness`.
            match disengage_lockdown(lock) {
                Ok(_clearance_is_persisted_not_reported_at_startup) => {}
                Err(e) => {
                    tracing::warn!(
                        error = &e as &dyn std::error::Error,
                        "lockdown sweep could not disengage the cover"
                    )
                }
            }
        }
    }
}

/// Windows only: delete the volatile TUN-interface permit pair when
/// `tun_name` no longer resolves to a live `NET_LUID`, i.e. its adapter is provably gone. Called from
/// [`recover_lockdown`] only on `Adopt`.
///
/// NDIS reassigns a freed `NetLuidIndex` to the next adapter of the same type, so a stale permit that survived a
/// crash could authorize an unrelated wintun adapter while the kill switch reads armed. A running bridge's own TUN
/// resolves, so this never deletes a permit a live bridge relies on.
///
/// A no-op on macOS, whose lockdown ruleset matches the TUN by literal interface name, which the OS does not reassign.
pub fn reclaim_stale_tun_permit(lock: &CoverLock, tun_name: &str) {
    #[cfg(target_os = "windows")]
    platform::reclaim_stale_tun_permit(lock, &luid::SystemLuidResolver, tun_name);
    #[cfg(not(target_os = "windows"))]
    let _ = (lock, tun_name);
}

/// Fail-loud disengage of a standing lockdown cover, with no running bridge.
/// Unlike [`recover_lockdown`]'s best-effort `Sweep`, this propagates failure, so `bridge unlock` can refuse to claim
/// success (and refuse to write the intent off) while the cover is still engaged. An absent cover is `Ok`; a real
/// failure (not elevated, engine open, `pfctl`) is `Err`. A pf refcount that will not drop is only logged.
///
/// `Ok` carries a [`Clearance`], as [`release_all`]'s does. macOS answers [`Clearance::proven`]: pf has no
/// boot-time analogue.
pub fn disengage_lockdown(lock: &CoverLock) -> Result<Clearance, RoutingError> {
    sweep_with_witness(lock, |witness| platform::disengage_lockdown(lock, witness))
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

/// Clear every fail-closed cover this platform can install, the transient and the standing one, without asking
/// whether either is present. The tray's Unblock item and turning the kill switch off both reach the host through
/// this function. The reasoning is in docs/contributing/architecture/kill-switch.md#the-release-contract.
///
/// 1. **Unconditional.** Never probes the live cover; idempotent. On macOS a clean host is read from Hole's own state
///    file (`StateFile::Absent`), so a state file lost under a live cover reads as clean and the call answers `Ok`
///    without touching pf.
/// 2. **Total.** Clears both cover kinds.
/// 3. **No short-circuit.** Every clear is attempted before any failure is examined; the only early return is a
///    Windows engine-open failure, where nothing could have been issued.
/// 4. **No false success over a detected cover.** `Ok` means every cover this call could detect is cleared; `Err`
///    may be reported over a host that is in fact open. `Ok` is qualified by its [`Clearance`]:
///    [`Clearance::is_proven`] is the narrower claim that every empty answer proved its key empty, which a
///    [`KeyLifetime::BootTime`] key answering [`KeyOutcome::NotFound`] does not. The uninstall gate must read the
///    narrower one.
/// 5. **Bookkeeping is best-effort, except the state-file clear.** A failing `pfctl -X` or Windows sublayer/provider
///    delete only logs. A cover's state-file clear is skipped whenever its restore did not confirm, and after a
///    confirmed restore a clear that cannot write is that cover's error. macOS clears the record before it drops the
///    token, and drops the token only if the clear took the record. A record that could not be read is kept, after
///    its restore, and the answer is an error.
///
/// Windows keeps no cover state file: the filter set is compiled-in fixed GUIDs, so only GUID sweeps run there.
pub fn release_all(lock: &CoverLock) -> Result<Clearance, RoutingError> {
    sweep_with_witness(lock, |witness| platform::release_all(lock, witness))
}

// Release clearance ===================================================================================================

/// Which record backs a fail-closed filter key, and therefore what a delete-by-key that finds nothing proves about
/// it. This is what [`Clearance`] carries.
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
    /// Windows `FWPM_FILTER_FLAG_BOOTTIME`: the runtime object is live only between kernel start and Base Filtering
    /// Engine start, so on any other boot the key answers "not found" whether or not a boot-time policy record is
    /// still provisioned behind it. "Not found" proves nothing.
    ///
    /// A watched removal ([`KeyOutcome::Removed`] → [`KeyObservation::proves_empty`]) is treated as proof, on the
    /// unmeasured assumption that `FwpmFilterDeleteByKey0` purges the policy record along with the runtime object.
    /// A stranded record blocks egress across the boot-to-BFE window only (unmeasured, and possibly worse for a host
    /// whose boot itself needs egress, where the block can keep the boot from reaching the BFE start that lifts it),
    /// which is why an unproven key does not fail a release but must never read as proof. See docs/contributing/architecture/kill-switch-windows.md#evidence-about-a-boot-time-key.
    BootTime,
}

/// What one delete-by-key observed about its key, keyed on the cause it reported.
///
/// Three return codes, three variants. Deriving one from the absence of another would fold an access denial or an RPC
/// failure into a removal, the verdict the MSI deletes `hole.exe` on. Per-variant policy lives on the type
/// (docs/contributing/architecture/kill-switch.md#the-decisions).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyOutcome {
    /// The delete removed a live object (`ERROR_SUCCESS`). Proof of removal for any lifetime: directly for
    /// [`KeyLifetime::Persistent`], and for [`KeyLifetime::BootTime`] under the purge assumption that variant states.
    Removed,
    /// The delete found nothing on the key (`FWP_E_FILTER_NOT_FOUND`). Proof
    /// of absence only for [`KeyLifetime::Persistent`].
    NotFound,
    /// The delete neither removed an object nor found the key empty: the OS refused or failed (not elevated, engine
    /// error, RPC failure). Proof of nothing, for any lifetime.
    ///
    /// It fails the release unless the key is [`KeyRole::Unlisted`] (`KeyRole::refusal_fails_the_sweep`), whose
    /// refusal is reported through [`Clearance::refused_strangers`] instead. Either way it reaches the clearance fold,
    /// because a Windows sweep issues every delete before reading any code and hands back both halves
    /// ([`SweepOutcome`]).
    Failed,
}

/// What a key's outcome is allowed to say about OTHER keys in the same sweep.
///
/// A [`KeyLifetime::BootTime`] key reports on itself only when its object was live enough to be removed; on every
/// other boot some other key has to separate "armed years ago" from "never armed", and exactly one can.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRole {
    /// Speaks only for itself. Every key whose own outcome is the whole
    /// answer about it.
    Plain,
    /// The `FWPM_FILTER_FLAG_PERSISTENT` half of the rule a [`KeyLifetime::BootTime`] twin copies, installed in the
    /// same transaction as that twin and never without it.
    ///
    /// BFE re-adds a persistent filter every boot, so removing a live object under this key says a standing cover is
    /// installed here, and every sibling answering empty says none is. The evidence is about the host, not the twin's
    /// own record: whether a boot-time record is possible, never whether one exists. Only the twin's own delete can
    /// say that, and only when it removed a live object.
    BootTimeSibling,
    /// A boot-time filter under Hole's provider that no key list names, found by enumeration
    /// (`windows::provider_sweep`) and then deleted by key.
    ///
    /// Unlike a listed key, it is KNOWN to exist: enumeration returned it. So a delete the OS refused is positive
    /// evidence a boot-time record is possible on this host, where a refused delete of a listed key proves nothing
    /// ([`KeyObservation::shows_a_boot_time_object`]).
    Unlisted,
    /// Not a key at all: the sweep's own enumeration of the boot-time filters under Hole's provider, which could not
    /// be read. It observed nothing about any filter, so it is evidence of nothing
    /// ([`KeyObservation::shows_a_boot_time_object`]) — but it is the one finding that says a stranger went
    /// unlooked-for, so it is reported whatever else is or is not (`ReportSection::UnenumeratedView`).
    Enumeration,
}

impl KeyRole {
    /// Whether a delete the OS refused fails the sweep that issued it. The whole rule, in one exhaustive match on the
    /// role.
    #[cfg(target_os = "windows")]
    pub(crate) fn refusal_fails_the_sweep(self) -> bool {
        match self {
            // A key this build installs and expects to remove: a refusal leaves a cover standing that the caller
            // would otherwise report gone.
            KeyRole::Plain => true,
            KeyRole::BootTimeSibling => true,
            // A filter this build never learned. A live boot-time filter is not enforced once BFE has started (an
            // assumption, no test measures it), so one the OS will not let go of blocks nothing now. Failing the
            // sweep over it would keep `bridge unlock` and the tray's Unblock from writing the lockdown intent off.
            // It is reported by its GUID instead.
            KeyRole::Unlisted => false,
            // Not a delete at all.
            KeyRole::Enumeration => false,
        }
    }
}

/// How a report words an unproven key: the three findings an operator is told apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReportSection {
    /// The label names a filter an operator can look up by key, and its absence is in question.
    Filter,
    /// The label names a filter enumeration found under Hole's provider that no key list names, and the OS refused to
    /// delete. Worded apart from [`Self::Filter`]: it is known to exist, and repeating the sweep is no remedy.
    RefusedStranger,
    /// The label names a look the sweep could not take. It is no key whose absence is in question, so no evidence
    /// about a record can excuse it: it is reported whatever else is or is not.
    UnenumeratedView,
}

impl ReportSection {
    /// Which section an unproven key belongs in. The whole rule, in one exhaustive match on the pair:
    /// `Clearance::leftover_filters`, `Clearance::refused_strangers`, `Clearance::unenumerated_views` and the
    /// always-reported gate of `Clearance::leftover_keys` all select on it.
    fn of(role: KeyRole, outcome: KeyOutcome) -> Self {
        match (role, outcome) {
            (KeyRole::Plain, _) => ReportSection::Filter,
            (KeyRole::BootTimeSibling, _) => ReportSection::Filter,
            (KeyRole::Unlisted, KeyOutcome::Failed) => ReportSection::RefusedStranger,
            (KeyRole::Unlisted, KeyOutcome::Removed | KeyOutcome::NotFound) => ReportSection::Filter,
            // The label names a look the sweep could not take, not a filter.
            (KeyRole::Enumeration, _) => ReportSection::UnenumeratedView,
        }
    }
}

/// One key's contribution to a release verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyObservation {
    /// Operator-facing label. Named, never counted: with the binary gone an
    /// operator has only the label to look the key up by. A key found by enumeration has no fixed label, so its
    /// label carries its filter GUID (braced, as `netsh wfp` prints it). A refused stranger's delete does not fail
    /// the sweep, so its GUID reaches the operator through the clearance report.
    pub key: Cow<'static, str>,
    pub lifetime: KeyLifetime,
    pub outcome: KeyOutcome,
    /// What this key's outcome says about the OTHER keys in the sweep — see
    /// [`KeyRole`].
    pub role: KeyRole,
    /// The code the OS answered the delete this observation rests on, as data for a report to print. `None` when no
    /// delete was issued (an enumeration that could not be read). It decides nothing: the outcome does.
    pub code: Option<u32>,
}

impl KeyObservation {
    /// Whether this observation is itself live evidence that a boot-time object exists on this host, so a
    /// boot-time record is possible. The whole rule, in one exhaustive match on the pair.
    fn shows_a_boot_time_object(&self) -> bool {
        match (self.role, self.outcome) {
            // BFE re-adds the persistent half every boot, so a removal says a standing cover is installed here.
            (KeyRole::BootTimeSibling, KeyOutcome::Removed) => true,
            (KeyRole::BootTimeSibling, KeyOutcome::NotFound | KeyOutcome::Failed) => false,
            // Found by enumeration, so the refusal is not "nothing there": the object is live.
            (KeyRole::Unlisted, KeyOutcome::Failed) => true,
            // A watched removal is proof about the key itself (`proves_empty`); a not-found after enumeration
            // found it is a race, and says nothing.
            (KeyRole::Unlisted, KeyOutcome::Removed | KeyOutcome::NotFound) => false,
            (KeyRole::Plain, _) => false,
            // An enumeration that could not be read looked at nothing, so it shows nothing.
            (KeyRole::Enumeration, _) => false,
        }
    }

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
            // A removal we watched happen is proof for a boot-time key too, under the purge assumption on
            // [`KeyLifetime::BootTime`].
            (KeyLifetime::BootTime, KeyOutcome::Removed) => true,
            // A boot-time key answers empty on any boot where its runtime object is not live, whether or not a record
            // survives behind it; the purge assumption does not cover this cell.
            (KeyLifetime::BootTime, KeyOutcome::NotFound) => false,
            // The delete never got an answer about the key at all.
            (_, KeyOutcome::Failed) => false,
        }
    }
}

/// What a [`release_all`] sweep proved, as distinct from what it attempted.
///
/// `Ok` from a sweep means no delete failed. It does not mean every key is demonstrably empty: a
/// [`KeyLifetime::BootTime`] key answering [`KeyOutcome::NotFound`] fits both "never installed" and "installed in an
/// earlier boot, record still provisioned". The verdict carries that qualification, which a bare `Ok` would drop and
/// the MSI would read as safe to delete the binary (docs/contributing/architecture/kill-switch-uninstall.md#what-ok-proves).
/// It does not fail the release; see [`KeyLifetime::BootTime`] for the bound on the harm.
///
/// It carries two independent answers. [`Self::is_proven`] is what the sweep proved: false on every Windows sweep
/// run on a boot where no bridge engaged. [`Self::leftover_keys`] is what is worth telling an operator, which is
/// narrower. It reports when either of two sources says a boot-time record is possible:
///
/// * [`KeyRole::BootTimeSibling`], collected in the same sweep: live evidence, and the only one that survives a wiped
///   `state_dir`;
/// * [`ArmingWitness`], the persisted record: the only one that survives the sweep that removes the sibling.
///
/// See [`boottime_witness`]. Exactly one observation retracts the record: a twin whose delete removed a live object
/// ([`boottime_witness::WitnessUpdate::Disarm`]). A twin that answered empty never does.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "the uninstall gate reads this; dropping it restores a silent `Ok`"]
pub struct Clearance {
    unproven: Vec<UnprovenKey>,
    sibling: SiblingEvidence,
    witness: ArmingWitness,
    boot_time: BootTimeSightings,
}

/// A key whose absence a sweep did not prove, with what decides how it is reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnprovenKey {
    label: Cow<'static, str>,
    role: KeyRole,
    /// Where a report puts it, decided once here from the observation's role and outcome ([`ReportSection::of`]).
    section: ReportSection,
    /// The code the OS answered the delete ([`KeyObservation::code`]).
    code: Option<u32>,
}

impl UnprovenKey {
    /// The operator-facing label ([`KeyObservation::key`]).
    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn role(&self) -> KeyRole {
        self.role
    }

    fn new(observation: &KeyObservation) -> Self {
        Self {
            label: observation.key.clone(),
            role: observation.role,
            section: ReportSection::of(observation.role, observation.outcome),
            code: observation.code,
        }
    }
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
    /// installed on this host, so a twin was added alongside it. Also an
    /// enumerated [`KeyRole::Unlisted`] filter whose delete was refused: a boot-time
    /// object is live here.
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
    if observations.iter().any(KeyObservation::shows_a_boot_time_object) {
        return SiblingEvidence::Installed;
    }
    let outcomes: Vec<KeyOutcome> = observations
        .iter()
        .filter(|o| o.role == KeyRole::BootTimeSibling)
        .map(|o| o.outcome)
        .collect();
    if outcomes.is_empty() {
        return SiblingEvidence::Unknown;
    }
    if outcomes.iter().all(|&o| o == KeyOutcome::NotFound) {
        return SiblingEvidence::Absent;
    }
    SiblingEvidence::Unknown
}

impl Clearance {
    /// The verdict for a sweep with nothing left unproven: every platform whose covers are all
    /// [`KeyLifetime::Persistent`], today macOS. Not every Windows key: the standing cover's boot-time block-all twins
    /// are [`KeyLifetime::BootTime`], so a Windows sweep that did not watch them go builds its verdict with
    /// [`Self::from_observations`].
    pub fn proven() -> Self {
        Self {
            unproven: Vec::new(),
            // No key went unproven, so no report is built from this whatever the sibling evidence would be.
            sibling: SiblingEvidence::Absent,
            // A platform with no boot-time key class never writes a record.
            witness: ArmingWitness::Unset,
            boot_time: BootTimeSightings::None,
        }
    }

    /// Fold per-key observations into a verdict. Pure and total over the slice: it inspects every observation, so the
    /// operator message can name all the unproven ones. An observation is unproven iff it did not prove itself empty
    /// ([`KeyObservation::proves_empty`]).
    ///
    /// `witness` is the persisted record this sweep was folded against. It is a parameter so no sweep can be built
    /// without answering the question; a platform with no record (macOS) passes [`ArmingWitness::Unset`].
    pub fn from_observations(observations: &[KeyObservation], witness: ArmingWitness) -> Self {
        Self {
            unproven: observations
                .iter()
                .filter(|o| !o.proves_empty())
                .map(UnprovenKey::new)
                .collect(),
            sibling: sibling_evidence(observations),
            witness,
            boot_time: boot_time_sightings(observations),
        }
    }

    /// Fold another `state_dir`'s persisted record into this verdict, the more cautious answer winning. The record is
    /// per-`state_dir` and the WFP filters it describes are machine-wide, so the uninstall gate folds in every peer
    /// directory it already locks against a live bridge (`cutover::release_covers_with`).
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
    pub fn unproven_keys(&self) -> &[UnprovenKey] {
        &self.unproven
    }

    /// The unproven keys that could have a record behind them on this host: what an operator is told about, as
    /// distinct from what the sweep proved.
    ///
    /// Empty is not "the sweep proved everything" ([`Self::is_proven`] stays false). It means both evidence sources
    /// agree no twin could be outstanding: the sweep found no standing cover ([`SiblingEvidence::Absent`]) and no
    /// record says one was armed ([`ArmingWitness::Unset`] or `Disarmed`). Either source reporting is enough: the
    /// sibling alone is consumed by the first sweep that removes it, and the record alone is lost with a wiped
    /// `state_dir`. `Installed` and `Unknown` report for different reasons (a cover is known to be armed; nothing was
    /// ruled out); [`ArmingWitness`] splits the same way.
    ///
    /// The exception is an unproven key in `ReportSection::UnenumeratedView`, an enumeration that could not be read:
    /// it is a look that did not happen, so no evidence about a record excuses it.
    pub fn leftover_keys(&self) -> impl Iterator<Item = &UnprovenKey> + '_ {
        let record_possible = self.sibling.record_possible() || self.witness.record_possible();
        self.unproven
            .iter()
            .filter(move |k| record_possible || k.section == ReportSection::UnenumeratedView)
    }

    /// The leftover keys that are filters whose absence is in question: [`Self::leftover_keys`] in
    /// `ReportSection::Filter`. What a report names as filters an operator can look up by key and could not be
    /// proven empty. The refused strangers ([`Self::refused_strangers`]) are worded apart.
    pub fn leftover_filters(&self) -> impl Iterator<Item = &UnprovenKey> + '_ {
        self.leftover_keys().filter(|k| k.section == ReportSection::Filter)
    }

    /// The views a sweep could not enumerate, so a filter in them went unlooked-for: [`Self::leftover_keys`] in
    /// `ReportSection::UnenumeratedView`. Always reported, and distinct from a key whose absence is in question: it
    /// names no filter, so a report words it apart from [`Self::leftover_filters`].
    pub fn unenumerated_views(&self) -> impl Iterator<Item = &UnprovenKey> + '_ {
        self.leftover_keys()
            .filter(|k| k.section == ReportSection::UnenumeratedView)
    }

    /// The filters under Hole's provider that no key list names, which enumeration found and the OS then refused to
    /// delete, each with the label that names it and the code the OS answered, when it did.
    ///
    /// Read off the unproven set directly, not through [`Self::leftover_keys`]: whether a report names it must not
    /// rest on what the sibling or the record say, because the filter is known to exist.
    pub fn refused_strangers(&self) -> impl Iterator<Item = (&str, Option<u32>)> + '_ {
        self.unproven
            .iter()
            .filter(|k| k.section == ReportSection::RefusedStranger)
            .map(|k| (k.label(), k.code))
    }

    /// What this sweep's own observations say the persisted record should now hold, derived here once and never at a
    /// write site.
    ///
    /// Two cells carry weight. `AllProven` ignores the sibling: a twin this sweep watched being removed is direct
    /// evidence about the twin. An unproven boot-time key on a host whose siblings all answered empty writes nothing:
    /// "no cover is installed now" is no evidence about a twin's record in either direction.
    pub(crate) fn witness_update(&self) -> boottime_witness::WitnessUpdate {
        use boottime_witness::WitnessUpdate;
        match (self.boot_time, self.sibling) {
            // The sweep touched no boot-time key, so it saw nothing the record
            // is about.
            (BootTimeSightings::None, _) => WitnessUpdate::Leave,
            // Watched every one of them go: proof under the purge assumption on [`KeyLifetime::BootTime`].
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
/// Reads [`KeyObservation::proves_empty`], so this and [`Clearance::unproven`] cannot disagree about whether a key
/// was proven. `seen` is tracked apart from `unproven` because "every boot-time key proved empty" is vacuously true
/// of a sweep that touched none.
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

/// One sweep's whole interaction with the persisted boot-time record: consult it before the fold, then update it from
/// what the sweep itself observed.
///
/// Every path that removes a standing cover's `PERSISTENT` sibling goes through here, which is what makes the sites
/// that discard the returned [`Clearance`] safe: `recover_lockdown`'s `Sweep` arm, `SystemRouting::release_all_covers`,
/// the reconciler's `CoverStep::Release`, and the standing guard's `Drop` on each platform. macOS has no sibling and no
/// boot-time key, so its record is never written, but it takes the same path. The evidence is persisted before
/// anything is returned, `Ok` or `Err`, so dropping the value costs an operator message on that one call and nothing
/// beyond it.
///
/// Generic over the sweep so a sweep that removes the sibling, followed by one that can no longer see it, is drivable
/// without a firewall. The sweep returns a [`SweepOutcome`] and not a `Result`, for the reason that type gives.
fn sweep_with_witness(
    lock: &CoverLock,
    sweep: impl FnOnce(ArmingWitness) -> SweepOutcome,
) -> Result<Clearance, RoutingError> {
    let state_dir = lock.state_dir();
    let SweepOutcome {
        clearance,
        failure,
        released,
    } = sweep(boottime_witness::load(state_dir));
    // Written from what the sweep observed, before its failure reaches the caller; see [`SweepOutcome`].
    boottime_witness::apply(lock, clearance.witness_update());
    // A kind the sweep released took what its held guards hold, whatever the other kind did. A kind it did not
    // keeps its stamps, so a guard's drop still retries what the sweep could not delete.
    for kind in &released {
        lock.outdate_stamps(*kind);
    }
    match failure {
        Some(e) => Err(e),
        None => Ok(clearance),
    }
}

/// One sweep's whole result: the verdict built from every observation it made, and the failure, if any, it must
/// still report.
///
/// Not a `Result<Clearance, _>`: both Windows sweeps issue every delete before inspecting any code, so a sweep that
/// ends in `Err` has already removed whatever it removed, up to the standing cover's `PERSISTENT` sibling, the one
/// piece of live evidence no later sweep can re-derive. A `Result` would drop those observations along the `?`.
#[must_use = "this carries a `Clearance` AND a failure; dropping it discards both at once, which \
              is the pair this type exists to keep"]
pub(crate) struct SweepOutcome {
    clearance: Clearance,
    failure: Option<RoutingError>,
    released: Vec<CoverKind>,
}

impl SweepOutcome {
    /// A sweep that answered for each cover kind it swept: `kinds` pairs a kind with the first error its own
    /// deletes met. A kind is released iff its entry is `None`, whatever the other kinds did, so a held guard of a
    /// kind that is gone stops deleting and one of a kind that is not still retries. The failure reported is the
    /// first `Some`, in the order given. `clearance` is folded from what the sweep DID observe, failed or not.
    pub(crate) fn per_kind(
        clearance: Clearance,
        kinds: impl IntoIterator<Item = (CoverKind, Option<RoutingError>)>,
    ) -> Self {
        let mut released = Vec::new();
        let mut failure = None;
        for (kind, error) in kinds {
            match error {
                None => released.push(kind),
                Some(e) => failure = failure.or(Some(e)),
            }
        }
        Self {
            clearance,
            failure,
            released,
        }
    }

    /// The sweep failed with no cover kind attributable and released nothing. `clearance` is the empty fold for a
    /// sweep that never reached the firewall at all.
    #[cfg(any(test, target_os = "windows"))]
    pub(crate) fn failed(clearance: Clearance, error: RoutingError) -> Self {
        Self {
            clearance,
            failure: Some(error),
            released: Vec::new(),
        }
    }

    /// What the sweep observed, whether or not it also failed.
    #[cfg(test)]
    pub(crate) fn clearance(&self) -> &Clearance {
        &self.clearance
    }

    /// The cover kinds whose release this sweep completed, whether or not it also failed.
    #[cfg(test)]
    pub(crate) fn released(&self) -> &[CoverKind] {
        &self.released
    }

    /// Collapse into the `Result` a caller with no record to update wants. For the unit tests of the verdict folds;
    /// [`sweep_with_witness`] destructures the struct instead, so the observations reach the record before the
    /// failure reaches the caller. Not for sweeps: collapsing there discards the observations.
    #[cfg(test)]
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

// Not platform-gated: the state writers and the symlink they must refuse are on every host.
#[cfg(test)]
#[path = "failclosed/state_symlink_tests.rs"]
mod state_symlink_tests;

// Not platform-gated: the fold of a read into `StateFile` is platform-free.
#[cfg(test)]
#[path = "failclosed/state_file_tests.rs"]
mod state_file_tests;

// Not platform-gated: the clearance fold is the decision the uninstall gate reads, and it is pure, so every lane can
// falsify it.
#[cfg(test)]
#[path = "failclosed/clearance_tests.rs"]
mod clearance_tests;

// Same reason as clearance_tests above — a source-tree scan, so every lane can
// run it.
#[cfg(test)]
#[path = "failclosed/boot_time_tripwire_tests.rs"]
mod boot_time_tripwire_tests;

// Also a source-tree scan, not platform-gated. The type it guards is Windows-only; the invariant (per-variant policy
// lives on the type, docs/contributing/architecture/kill-switch.md#the-decisions) is not.
#[cfg(test)]
#[path = "failclosed/stale_key_policy_tests.rs"]
mod stale_key_policy_tests;

#[cfg(all(any(test, feature = "test-utils"), any(target_os = "windows", target_os = "macos")))]
#[path = "failclosed/cover_oracle.rs"]
pub(crate) mod cover_oracle;

#[cfg(all(test, any(target_os = "windows", target_os = "macos")))]
#[path = "failclosed/cover_oracle_tests.rs"]
mod cover_oracle_tests;

// Names `hole_test_observability`, a dev-dependency: `cfg(test)` only, unlike the oracle it wraps.
#[cfg(all(test, any(target_os = "windows", target_os = "macos")))]
#[path = "failclosed/permit_scenario.rs"]
mod permit_scenario;

// Privileged-lane real-engage verification: engages the real OS cover and asserts it blocks egress. Gated to the
// elevated `hole-tests` TUN lane by the `TUN` label (see the module docs); excluded from the unprivileged pass.
#[cfg(test)]
#[path = "failclosed/lockdown_privileged_tests.rs"]
mod lockdown_privileged_tests;

// Privileged-lane proof that `release_all` clears both cover kinds on the real firewall and never a clean host's
// live ruleset. Gated like `lockdown_privileged_tests`.
#[cfg(test)]
#[path = "failclosed/release_privileged_tests.rs"]
mod release_privileged_tests;

// Privileged-lane falsification: engages the real standing lockdown cover against two live TUN devices and proves the
// tunnel-permit rule is sensitive to the interface it names, not merely present. Gated like
// `lockdown_privileged_tests`.
#[cfg(test)]
#[path = "failclosed/live_tun_permit_privileged_tests.rs"]
mod live_tun_permit_privileged_tests;

// Privileged-lane measurement of what WFP does with a boot-time filter: whether it accepts one under our persistent
// containers, keeps them, and removes it on a by-key delete. Windows-only: pf rules do not survive a reboot. Gated
// identically to `lockdown_privileged_tests` above.
#[cfg(all(test, target_os = "windows"))]
#[path = "failclosed/boottime_privileged_tests.rs"]
mod boottime_privileged_tests;

// Privileged-lane proof of the version-independent boot-time sweep against the real firewall: a provider-filtered
// enumeration returns boot-time filters at every layer, and a full sweep removes an unrecognised one and nothing else. Gated identically to `boottime_privileged_tests` above.
#[cfg(all(test, target_os = "windows"))]
#[path = "failclosed/provider_sweep_privileged_tests.rs"]
mod provider_sweep_privileged_tests;
