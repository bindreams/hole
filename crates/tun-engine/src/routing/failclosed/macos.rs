//! macOS fail-closed cover via pf (`pfctl`). The shape is in docs/contributing/architecture/kill-switch-macos.md;
//! this doc is the reference for the pf arguments. Two layers share the `Cover` guard:
//!
//! - **Transient cover** (`engage`/`disengage`): enables pf (refcounted, `pfctl -E`) and loads a self-contained
//!   ruleset (see `build_pf_ruleset`, via `pfctl -f -`, no `-Fa`) blocking everything but loopback, the server and
//!   the pinned resolver. Disengage restores `/etc/pf.conf`, clears the record and drops the refcount once that clear
//!   took the record ([`release`]).
//! - **Standing lockdown** (`engage_lockdown`/`lockdown_disengage`): loads a self-contained main ruleset (no `-Fa`)
//!   that carries the host's translation rules forward and blocks all egress except the TUN and the server IP.
//!   Disengage restores the pre-lockdown filter and nat from the persisted snapshot, or `/etc/pf.conf` when there is
//!   none or it will not load ([`restore_standing`]), clears the record and drops the refcount. Engage ensures pf is
//!   enabled: pf and its refcount reset across a reboot but the record persists, so a reconnect re-enables pf and
//!   loads a live ruleset instead of an inert one.
//!
//! # No `-Fa`
//!
//! `-Fa` flushes all pf state as its own committed kernel operation, so `-Fa -f -` was two transactions with a
//! pass-all host briefly live between them, including across a cover transition. A bare `pfctl -f -` is one
//! transaction for the rules (`DIOCADDRULE` stages into an inactive ruleset, `DIOCXCOMMIT` swaps it in under
//! `pf_lock`), so the old ruleset stays authoritative until the new one commits. That makes `engage` safe over a live
//! cover. It does not make the bridge's cover transitions gap-free: the repair path and the lockdown-newly-enabled path
//! drop the held [`Cover`] first, and `Drop` reloads `/etc/pf.conf`, so the host is open until the next engage.
//!
//! The `set` lines are outside that transaction: `pfctl` applies `set block-policy`/`skip`/`limit`/`timeout` through
//! their own immediate ioctls as it parses, and clears every interface's skip flag before it begins parsing. No `set`
//! ioctl is a permit, but a cover fails in both directions and this one fails by tightening: a cleared `skip on lo0`
//! re-exposes loopback to the previous ruleset's `block out all` for the whole parse. [`LOOPBACK_PASSES`] closes it.
//!
//! # Order of an engage
//!
//! A cold engage (pf disabled) has no gap that reordering could close: pf enforces nothing while disabled, so `-E` can
//! only add filtering, and loading first would lengthen the open stretch by one `pfctl` spawn. `-E` precedes the
//! persist, because enabling is what makes the host dark and a failed `pf_record::swap` would otherwise strand a
//! blocking host with no file to recover it from (`engage_with` step 3). The load is followed by a `pfctl -F states`
//! purge, because pf matches state before rules; whether a cover purges is [`purges_state`].
//!
//! # Release order
//!
//! A record names only a token Hole holds ([`super::pf_record`]), so a release restores the host, clears the record,
//! and drops the cover's `pfctl -E` token only if that clear took the record that named it ([`release`]).
//!
//! - A clear that cannot write is the release's error and drops nothing, so the retry still has its token.
//! - A failed restore is the release's error and touches neither record nor token: the cover stays in force, evidence
//!   and refcount together, until a later release restores.
//! - A record that could not be read is left in place; after a good restore the release answers an error.
//! - A drop that fails is only logged: the refcount stays until a reboot, and with the rules restored it blocks
//!   nothing. Dropping Hole's token releases Hole's hold only: pf stays enabled while any other refcount holds it.
//! - Every `pfctl -X` goes through [`drop_or_warn`] over the caller's ops seam. An engage whose record write replaced
//!   one naming another token drops that token ([`drop_displaced`]). Every one of these runs under the cover lock.
//!
//! # Caveats
//!
//! pf has no programmatic API: `pfctl` text I/O is the interface, as `netsh` and `route` are on Windows.
//!
//! - The transient restore reloads `/etc/pf.conf`; the lockdown restore reloads the captured snapshot. Neither can
//!   recover prior `set` options (pf exposes no dump of them), so both restore under pf defaults.
//! - The `pfctl -E` token is parsed from stderr, its only exposure.

// Test builds on other hosts compile this module to drive its sequencers; the
// production `pfctl` entry points have no caller there.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::net::IpAddr;
use std::path::Path;

#[cfg(target_os = "macos")]
use super::super::run_capturing;
use super::super::{BestEffortPhase, FatalPhase, Phase};
use crate::error::{RoutingError, StateOp};
#[cfg(target_os = "macos")]
use util::system_tool::SystemTool;
// `macos.rs` is mounted as `mod platform` under `failclosed`, so `super` is the
// `failclosed` module and `failclosed_state` is its sibling child.
use super::failclosed_state as state;
use super::lockdown_pf_state as lockdown_state;
use super::pf_record::{self, Cleared};
use super::Clearance;
use super::StateFile;
use super::SweepOutcome;
use super::RESOLVER_PERMIT_PORT;
use super::{CoverKind, CoverLock, InstallStamp};

/// Whether this platform's standing cover arms [`super::KeyLifetime::BootTime`] keys, and so whether an engage has a
/// [`super::boottime_witness`] to record. False on macOS: pf has no boot-time analogue, since a ruleset does not
/// survive a reboot. Both sweep entry points here therefore ignore their `witness` argument and answer
/// [`Clearance::proven`].
pub(crate) const STANDING_COVER_ARMS_BOOT_TIME: bool = false;

/// Checked by the compiler: Windows records the witness inside its own engage, gated on this flag, and macOS has no
/// such site. Giving this platform boot-time keys without a record write would leave the uninstall gate blind, so
/// flipping the constant fails the build until the write exists.
const _: () = assert!(
    !STANDING_COVER_ARMS_BOOT_TIME,
    "macOS arms no boot-time key and has no site that records the boot-time witness; a platform \
     that arms one needs both"
);

/// Build the self-contained pf ruleset (loaded via `pfctl -f -`).
///
/// `set block-policy drop` silently drops blocked packets (no RST/ICMP). `block out all` is the fail-closed default;
/// the `quick` pass rules for the server IP and (when given) the resolver the caller's own `ech-doh` URL names win
/// without depending on pf's last-match rule. `resolver_ip` is `None` whenever nothing should be permitted (see
/// `Routing::install_failclosed_cover`). The resolver pass is scoped to `proto tcp port` [`RESOLVER_PERMIT_PORT`],
/// unlike the server permit.
///
/// Loopback is exempted twice, by [`LOOPBACK_SKIP`] and [`LOOPBACK_PASSES`]. Both permits go through [`permit`], which
/// is where the `no state` rule lives.
pub fn build_pf_ruleset(server_ip: IpAddr, resolver_ip: Option<IpAddr>) -> String {
    let resolver_pass = resolver_ip
        .map(|ip| {
            permit(&format!(
                "pass out quick proto tcp from any to {ip} port {RESOLVER_PERMIT_PORT}"
            ))
        })
        .unwrap_or_default();
    format!(
        "set block-policy drop\n\
         {LOOPBACK_SKIP}\
         {LOOPBACK_PASSES}\
         block out all\n\
         {server_pass}\
         {resolver_pass}",
        server_pass = permit(&format!("pass out quick from any to {server_ip}")),
    )
}

/// Terminate a cover `pass` rule with `no state`. Every permit in every cover ruleset goes through here.
///
/// `pfctl` normalizes a bare `pass out quick from any to 1.1.1.1` to `... flags S/SA keep state`, which matches only a
/// SYN, so a mid-stream segment of a permitted flow with no state entry falls through to the block-all base and is
/// discarded under `block-policy drop` (`transient_cover_permits_are_never_syn_only` and its lockdown twin run the
/// real `pfctl -vn -f -`). Each cover reaches a flow with no entry by its own route:
///
/// - [`CoverKind::Transient`]: the flow had an entry and lost it to the engage's host-wide `pfctl -F states`
///   ([`purges_state`]). The resolver permit is the sharp edge: the resolver is typically a public DoH address a
///   browser on the machine already holds a connection to.
/// - [`CoverKind::Lockdown`]: the flow never had an entry. The tunnel is already carrying traffic when the ruleset
///   commits, and on stock macOS the engage's own `pfctl -E` is what enabled pf.
///
/// `no state` suppresses the `flags S/SA` default, so the permit matches mid-stream. Neither ruleset carries a
/// `block in`, so an outbound-only permit needs no state for return traffic. A matching `nat`/`rdr` rule (only
/// [`build_lockdown_main_ruleset`] carries translation) makes pf create state anyway, which is harmless. Same
/// primitive as [`LOOPBACK_PASSES`].
fn permit(rule: &str) -> String {
    format!("{rule} no state\n")
}

/// The `set` half of the loopback exemption: it passes loopback "as if pf was disabled", with no state entry for the
/// transient cover's `pfctl -F states` purge ([`purges_state`]) to flush.
///
/// Separate from [`LOOPBACK_PASSES`] because `require-order` puts Options before Translation before Filter, and
/// [`build_lockdown_main_ruleset`] fits the host's `nat` snapshot between the two.
pub const LOOPBACK_SKIP: &str = "set skip on lo0\n";

/// The rule half of the loopback exemption, closing the window [`LOOPBACK_SKIP`] cannot. Both halves are mandatory in
/// every cover ruleset; dropping either severs loopback by its own route.
///
/// `pfctl` clears every interface's skip flag (`DIOCCLRIFFLAG`) before it parses or commits a load, so across that span
/// lo0 is filtered again while the previous ruleset is authoritative. If that ruleset is a live cover, loopback meets
/// its `block out all` and is discarded: an `ssh -L` forward or an IDE socket stalls, a loopback datagram is lost.
/// Rules stay authoritative until commit, so the outgoing ruleset's own lo0 `pass` carries loopback across the next
/// load: a cover transition, the `/etc/pf.conf` restore in [`disengage`], and lockdown engage and disengage.
///
/// `no state` for the reason [`permit`] gives; these rules are written out because they are a const.
///
/// Both directions, though only `out` is load-bearing against today's out-only blocks: these rules stand in for
/// [`LOOPBACK_SKIP`], which is direction-agnostic, and an `out`-only stand-in would stop covering the moment a ruleset
/// grows a `block in`.
pub const LOOPBACK_PASSES: &str = "pass out quick on lo0 all no state\n\
                                   pass in quick on lo0 all no state\n";

/// Normalize a snapshot fragment to end in exactly one `\n`. Empty stays empty
/// (so an absent NAT section contributes no stray blank line); non-empty text
/// gets a single trailing newline if it lacks one.
pub fn ensure_trailing_nl(s: &str) -> String {
    if s.is_empty() || s.ends_with('\n') {
        s.to_owned()
    } else {
        format!("{s}\n")
    }
}

/// The pf rule label our block-all base carries, and the name
/// [`lockdown_cover_presence`] reads back out of `pfctl -s labels`.
pub const LOCKDOWN_PF_LABEL: &str = "hole-lockdown";

/// Build the self-contained main ruleset for the standing lockdown, loaded via `pfctl -f -` (no `-Fa`). It is the
/// host's egress policy while engaged: `block drop out quick all` is the fail-closed base, with earlier `quick` permits
/// for the TUN and the server IP.
///
/// `set` lives here (it is a parse error inside an anchor), and the host's translation rules (`nat_snapshot`, from
/// `pfctl -sn`) are carried forward so the session does not flush NAT. Order is `require-order`: Options, Translation,
/// Filter. The server permit precedes `block drop out quick inet6 all` so a v6 server is not killed; pf has no
/// per-process matching, so it is IP-based.
///
/// Loopback is exempted as in [`build_pf_ruleset`]. The passes lead the filter section, because the `quick` inet6
/// block would otherwise end evaluation on a `::1` packet. The server and TUN permits go through [`permit`].
///
/// The base rule's [`LOCKDOWN_PF_LABEL`] is load-bearing: it is the only presence evidence for
/// [`lockdown_cover_presence`] that does not come from `state_dir`. Without it presence is file-only, which cannot
/// produce `Live`.
pub fn build_lockdown_main_ruleset(tun_name: &str, server_ip: IpAddr, nat_snapshot: &str) -> String {
    let proto = "tcp"; // +udp once a UDP-transport plugin lands; egress is TCP-only today.
    format!(
        "set block-policy drop\n\
         {LOOPBACK_SKIP}\
         {nat}\
         {LOOPBACK_PASSES}\
         {server_pass}\
         {tun_pass}\
         block drop out quick inet6 all\n\
         block drop out quick all label \"{label}\"\n",
        nat = ensure_trailing_nl(nat_snapshot),
        server_pass = permit(&format!("pass out quick proto {proto} from any to {server_ip}")),
        tun_pass = permit(&format!("pass out quick on {tun_name} all")),
        label = LOCKDOWN_PF_LABEL,
    )
}

/// Whether a `pfctl -s labels` listing names our rule label. The label is the
/// FIRST whitespace-delimited field of a line (the rest are counters), so the
/// match is anchored there — a host label that merely contains ours as a
/// substring is not ours.
pub fn labels_listing_carries_our_label(labels_output: &str) -> bool {
    labels_output
        .lines()
        .any(|l| l.split_whitespace().next() == Some(LOCKDOWN_PF_LABEL))
}

/// Fold a `pfctl -s labels` invocation into pf's answer about our label:
/// `Some(true)` it is loaded, `Some(false)` it is not, `None` pf could not be
/// asked (spawn failure or a non-success exit).
///
/// `None`, not `Some(false)`, is what keeps the two-source design honest: a `pfctl` that could not run is no evidence
/// the cover is gone. Each failure warns, apart, so a log shows that pf was never asked.
pub(crate) fn pf_label_answer(out: Result<std::process::Output, RoutingError>) -> Option<bool> {
    let out = match out {
        Ok(out) => out,
        Err(e) => {
            tracing::warn!(
                error = &e as &dyn std::error::Error,
                "`pfctl -s labels` could not be run, so pf's own answer about the lockdown cover \
                 is unavailable and presence falls back to the state file alone"
            );
            return None;
        }
    };
    if !out.status.success() {
        tracing::warn!(
            status = ?out.status,
            stderr = %String::from_utf8_lossy(&out.stderr).trim(),
            "`pfctl -s labels` ran but exited non-zero, so pf's own answer about the lockdown \
             cover is unavailable and presence falls back to the state file alone"
        );
        return None;
    }
    Some(labels_listing_carries_our_label(&String::from_utf8_lossy(&out.stdout)))
}

/// Build the ruleset that restores the host's pre-lockdown policy on Sweep,
/// reloaded via `pfctl -f -`. Composes the captured translation (`nat_snapshot`,
/// from `pfctl -sn`) and filter (`main_snapshot`, from `pfctl -sr`) snapshots.
///
/// `set require-order no` leads: `pfctl -sr` on macOS interleaves a normalization line (`scrub-anchor "com.apple/*"`)
/// with filter rules, so concatenating `{nat}{filter}` puts translation before normalization, a `require-order` parse
/// error that would fail the restore. Disabling the check lets pfctl accept the snapshots verbatim.
pub fn build_lockdown_restore_ruleset(nat_snapshot: &str, main_snapshot: &str) -> String {
    format!(
        "set require-order no\n\
         set block-policy drop\n\
         {nat}{filter}",
        nat = ensure_trailing_nl(nat_snapshot),
        filter = main_snapshot,
    )
}

/// Parse the enable token from `pfctl -E` output (it prints `Token : <n>`).
pub fn parse_enable_token(output: &str) -> Option<String> {
    output
        .lines()
        .find_map(|l| l.split_once("Token :").map(|(_, t)| t.trim().to_owned()))
        .filter(|t| !t.is_empty())
}

/// Parse `pfctl -s info` for the `Status: Enabled` line.
pub fn parse_pf_enabled(output: &str) -> bool {
    output
        .lines()
        .any(|l| l.trim_start().starts_with("Status:") && l.contains("Enabled"))
}

/// How `engage_lockdown` must (re)enable pf. Pure so it is table-tested; the live
/// `pfctl` calls stay behind the privileged path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PfEngageAction {
    /// No persisted state: snapshot the host + `pfctl -E` + capture the token.
    FreshEnable,
    /// Adopt re-engage AND pf still enabled: reuse the persisted token (no `-E`).
    ReuseToken,
    /// Adopt re-engage but pf is DISABLED (a reboot reset it AND its refcount): the
    /// persisted token is stale, so `pfctl -E` again and persist the fresh token.
    Reenable,
}

/// Decide how to (re)enable pf for a lockdown engage. `pf_enabled` is read from `pfctl -s info`; `has_persisted` is
/// whether a valid `bridge-lockdown-pf.json` exists. The ruleset always loads into an enabled pf, never an inert one.
fn engage_pf_action(pf_enabled: bool, has_persisted: bool) -> PfEngageAction {
    match (has_persisted, pf_enabled) {
        (false, _) => PfEngageAction::FreshEnable,
        (true, true) => PfEngageAction::ReuseToken,
        (true, false) => PfEngageAction::Reenable,
    }
}

// --- engage layer ---

const PFCONF: &str = "/etc/pf.conf";

/// Runs `pfctl` through [`SystemTool::Pfctl`] (absolute path).
#[cfg(target_os = "macos")]
fn pfctl<P: Phase>(args: &[&str], stdin: Option<&[u8]>, phase: P) -> Result<std::process::Output, RoutingError> {
    run_capturing(SystemTool::Pfctl, args, stdin, phase)
        .map_err(|e| RoutingError::RouteSetup(format!("pfctl spawn failed: {e}")))
}

/// Test builds on a host without `pfctl` drive every sequencer through its ops
/// seam; reaching the real tool there is a test that forgot to inject one.
#[cfg(not(target_os = "macos"))]
fn pfctl<P: Phase>(_args: &[&str], _stdin: Option<&[u8]>, _phase: P) -> Result<std::process::Output, RoutingError> {
    unreachable!("pfctl exists only on macOS; inject the ops seam")
}

/// `pfctl -E` (refcounted enable) + parse the enable token from its output. The
/// token prints to stderr (or stdout on some hosts), so try both.
fn enable_pf_capture_token() -> Result<String, RoutingError> {
    let en = pfctl(&["-E"], None, FatalPhase::CoverEngage)?;
    parse_enable_token(&String::from_utf8_lossy(&en.stderr))
        .or_else(|| parse_enable_token(&String::from_utf8_lossy(&en.stdout)))
        .ok_or_else(|| RoutingError::RouteSetup("pfctl -E returned no token".into()))
}

/// pf-backed cover guard. Drop disengages per its stamp's [`CoverKind`], while its install is the latest
/// ([`InstallStamp`]): the transient cover restores `/etc/pf.conf`; the lockdown cover restores the captured snapshot
/// (else `/etc/pf.conf`, [`restore_standing`]).
pub struct Cover {
    /// `None` once `detach` has consumed the claim, which makes `Drop` a no-op.
    held: Option<Held>,
    stamp: InstallStamp,
}

/// What a live [`Cover`] must hand to its disengage.
struct Held {
    token: String,
}

impl Cover {
    /// Release this process's claim on the cover without disengaging it. macOS holds no process-local OS resource:
    /// `Drop`'s `pfctl -X <token>` releases pf's enable refcount, so leaving pf enabled just means emptying the guard.
    pub(crate) fn detach(mut self) {
        self.held = None;
    }

    pub(crate) fn stamp(&self) -> &InstallStamp {
        &self.stamp
    }
}

impl Held {
    fn disengage(&self, kind: CoverKind, lock: &CoverLock) {
        match kind {
            // A user-stop drop never has a standing cover being adopted.
            CoverKind::Transient => disengage(&self.token, lock),
            CoverKind::Lockdown => lockdown_disengage(lock),
        }
    }
}

/// Whether an engage of this cover kind follows its ruleset load with a host-wide pf state purge (`pfctl -F states`).
/// The one place either engage decides whether a flow established before it survives it.
///
/// pf matches the state table before the ruleset, and `DIOCXCOMMIT` leaves a state whose creating rule was removed
/// alive, so a flow already holding a state entry when a cover loads keeps flowing past `block out all` until the entry
/// expires (`tcp.established` defaults to 86400s and every packet refreshes it). Dropping `-Fa` no longer purges state
/// as a side effect, so an engage that needs one purges explicitly.
///
/// - [`CoverKind::Transient`]: **purge.** pf may already be enabled ahead of it (Internet Sharing, another VPN, a
///   hand-run `pfctl -e`, or a standing ruleset left by an outgoing bridge's `CoverGuard::disarm`), and the transient
///   cover is engaged before any tunnel of ours exists. The flush is host-wide (`DIOCCLRSTATES`), so it also takes the
///   entries of flows this ruleset permits; what protects those is the ruleset, never the flush's scope. Loopback is
///   exempted with `set skip on lo0`, and the server and resolver permits carry `no state` ([`permit`]).
/// - [`CoverKind::Lockdown`]: **do not purge.** `engage_lockdown` runs with the tunnel live, and the flush would kill
///   the tunnel the kill switch exists to protect. Not purging does not by itself carry the tunnel across the load,
///   because on a pf this engage's own `pfctl -E` enabled there is no state to preserve, so the lockdown's permits are
///   `no state` too. Purging everything except the tunnel needs `DIOCKILLSTATES`' `psk_dst.neg`, which `pfctl` has no
///   flag for.
const fn purges_state(kind: CoverKind) -> bool {
    match kind {
        CoverKind::Transient => true,
        CoverKind::Lockdown => false,
    }
}

/// Load `ruleset` as this cover's live pf policy, then apply [`purges_state`]. Both engages go through here, so the
/// purge policy has one implementation.
///
/// The purge runs only after a successful load: flushing first leaves a window in which state is gone but the
/// permissive ruleset being replaced is still live, so packets re-create their state under it. A failed load never
/// committed, so no purge is attempted.
///
/// A failed purge is logged, not propagated. The engage returns `Ok` with the cover loaded, but flows that already held
/// a state entry keep passing it, and the only trace is the warn in `bridge.log`. Failing the engage instead is fatal
/// to the start, and the transient path unwinds by reloading `/etc/pf.conf`, a fully open host, which is worse than a
/// cover whose purge did not land.
fn load_cover_ruleset<T: CoverRulesetOps + ?Sized>(
    kind: CoverKind,
    ruleset: &str,
    ops: &mut T,
) -> Result<(), RoutingError> {
    ops.load_ruleset(ruleset)?;
    if purges_state(kind) {
        if let Err(e) = ops.flush_states() {
            tracing::warn!(
                error = &e as &dyn std::error::Error,
                "pf state purge failed after the cover ruleset loaded; flows established before \
                 this engage may keep flowing past it"
            );
        }
    }
    Ok(())
}

/// The narrow seam [`load_cover_ruleset`] needs: load a ruleset and, per [`purges_state`], flush pf's state table.
/// Split out of [`EngageOps`] (its supertrait) so `engage_lockdown`'s ruleset-load step does not need a full
/// `EngageOps` with the `lock` and `owner` it never reads.
pub(crate) trait CoverRulesetOps {
    /// `pfctl -f -` with `text` on stdin.
    fn load_ruleset(&mut self, text: &str) -> Result<(), RoutingError>;
    /// `pfctl -F states`: purge pf's state table, host-wide.
    fn flush_states(&mut self) -> Result<(), RoutingError>;
    /// `pfctl -X <token>`: drop a pf enable refcount. Callers go through [`drop_or_warn`].
    fn drop_token(&mut self, token: &str) -> Result<(), RoutingError>;
}

/// Seam over the pf and state-file mutations an engage performs, so its ordering (enable, persist, load, purge), its
/// unwind on a failed persist, and which cover kinds purge are table-tested without `pfctl`. As with [`PfOps`], the
/// production implementation ([`RealEngageOps`]) folds a non-success `pfctl` exit into `Err`.
pub(crate) trait EngageOps: CoverRulesetOps {
    /// `pfctl -s info`, parsed: is pf currently enabled?
    fn pf_enabled(&mut self) -> Result<bool, RoutingError>;
    /// `pfctl -E` (refcounted enable) + capture the enable token.
    fn enable_capture_token(&mut self) -> Result<String, RoutingError>;
    /// Write `bridge-failclosed.json`. Returns the token the record it replaced named, if any ([`pf_record::swap`]).
    fn save_transient(&mut self, st: &state::FailClosedState) -> Result<Option<String>, RoutingError>;
    /// The transient cover's full restore, `disengage(token, lock)`.
    fn transient_restore(&mut self, token: &str);
}

/// Drop the token an engage's record write displaced. The write took the only record that named it, so nobody else
/// will: a leftover from a cover whose release did not finish, or a token salvaged from an unusable file. Skipped when
/// nothing was displaced or the record named the new token already; a failed drop never fails the engage.
fn drop_displaced(displaced: Option<&str>, new: &str, drop: impl FnOnce(&str) -> Result<(), RoutingError>) {
    let Some(old) = displaced.filter(|old| *old != new) else {
        return;
    };
    drop_or_warn(old, "for the token a new cover's record replaced", drop);
}

pub fn engage(
    lock: &CoverLock,
    server_ip: IpAddr,
    resolver_ip: Option<IpAddr>,
    owner: Option<(u32, u32)>,
) -> Result<Cover, RoutingError> {
    let token = engage_with(server_ip, resolver_ip, &mut RealEngageOps { lock, owner })?;
    Ok(Cover {
        held: Some(Held { token }),
        stamp: lock.stamp_install(CoverKind::Transient),
    })
}

/// `engage`'s sequencing over the [`EngageOps`] seam. Returns the pf enable
/// token the caller wraps in a [`Cover`].
fn engage_with(
    server_ip: IpAddr,
    resolver_ip: Option<IpAddr>,
    ops: &mut dyn EngageOps,
) -> Result<String, RoutingError> {
    // 1. Read whether pf is enabled. Diagnostic only (its single reader is a log field in `recover_cover`), so it is
    //    best-effort: failing the engage over it would fail the cover open for a read no cover-establishing step needs.
    //    A failure is recorded as `false`, because the field is a `bool` (see its doc).
    let was_enabled = match ops.pf_enabled() {
        Ok(enabled) => enabled,
        Err(e) => {
            tracing::warn!(
                error = &e as &dyn std::error::Error,
                "could not read whether pf was already enabled; recording it as not enabled and \
                 continuing the engage — this read is diagnostic and the cover does not depend on it"
            );
            false
        }
    };

    // 2. Enable pf (refcounted) and capture the token, before the load (module doc, "Order of an engage").
    let token = ops.enable_capture_token()?;

    // 3. Persist before loading the blocking ruleset, so a crash after this point is recoverable (`pfctl -X <token>`).
    //    The refcount is held from step 2 on, so a persist failure undoes the `-E` before propagating, or pf stays
    //    enabled until reboot under an unreferenced token with no state file to recover it from. Only the refcount
    //    can be stranded: `swap` is temp file plus rename, so a failed save leaves no partial file.
    let st = state::FailClosedState {
        pf_token: token.clone(),
        pf_was_enabled: was_enabled,
    };
    let displaced = match ops.save_transient(&st) {
        Ok(displaced) => displaced,
        Err(e) => {
            drop_or_warn(&token, "unwinding a failed transient engage", |t| ops.drop_token(t));
            return Err(e);
        }
    };
    drop_displaced(displaced.as_deref(), &token, |old| ops.drop_token(old));

    // 4. Load the self-contained blocking ruleset from stdin, no `-Fa` (module doc). The purge that follows is
    //    [`purges_state`]'s call.
    let ruleset = build_pf_ruleset(server_ip, resolver_ip);
    if let Err(e) = load_cover_ruleset(CoverKind::Transient, &ruleset, ops) {
        // A failed engage is the one place this module fails open on its own error: a half-loaded ruleset must not
        // keep blocking. A failed `pfctl -f -` never committed its rules, so the host still filters under the
        // previously loaded ruleset, but what `pfctl` does outside the ticket lands anyway (the `set` ioctls, the
        // cleared skip flags). None of those is a permit; they tighten, and a load that failed before its
        // `set skip on lo0` parsed leaves lo0 filtered under the previous ruleset until a later load restates the
        // flag. [`LOOPBACK_PASSES`] keeps loopback flowing meanwhile. Restoring `/etc/pf.conf` returns the host to its
        // canonical baseline rather than leaving it under a stale cover ruleset. No standing cover is being adopted
        // here, so the restore must run.
        //
        // Known residual (bindreams/hole#1004, open): if this call is a transition over a still-live prior cover,
        // that cover blocked right up until this failed load, and the `/etc/pf.conf` reload below replaces it with
        // the open baseline. `engage` has no parameter that tells a first engage from a transition, so the warn below
        // fires unconditionally. It is worded as a possibility because it fires before the restore, and a restore
        // that itself fails leaves the host behind the prior cover.
        tracing::warn!(
            "the transient cover's ruleset failed to load; restoring /etc/pf.conf, which REPLACES \
             whatever ruleset was live. If this engage was a TRANSITION over a still-live prior \
             cover, that cover was blocking the host until this instant and the restore below \
             REOPENS it (bindreams/hole#1004); a restore that fails instead logs its own failure \
             below and leaves the host behind that prior cover"
        );
        ops.transient_restore(&token);
        return Err(e);
    }

    Ok(token)
}

impl Drop for Cover {
    fn drop(&mut self) {
        if let Some(held) = self.held.take() {
            self.stamp
                .release_on_drop(|lock| held.disengage(self.stamp.kind(), lock));
        }
    }
}

/// `pfctl -X` for a token Hole holds, best-effort, through the `drop` the caller's ops seam provides (its
/// `drop_token`): every drop site comes here, so a test double sees every one. A failure is logged and nothing else:
/// every caller is already mid-unwind or mid-teardown with its own outcome to return, pf may have retired the token (a
/// reboot) and the code cannot tell that from a real failure, and a record that waited on a drop that always fails
/// would be a lockout. `drop` reports the exit status as well as the spawn ([`pfctl_status`]), so a token pf rejects is
/// not read as a success. `context` finishes "pfctl -X failed ...".
fn drop_or_warn(token: &str, context: &str, drop: impl FnOnce(&str) -> Result<(), RoutingError>) {
    if let Err(e) = drop(token) {
        tracing::warn!(
            token = %token,
            error = &e as &dyn std::error::Error,
            "pfctl -X failed {context}; pf keeps that refcount until a reboot resets it"
        );
    }
}

/// Restore the host and give up the transient cover's record and refcount. When `adopting` is false it reloads the
/// canonical `/etc/pf.conf`: the cover's own block-all ruleset is still live, so the reload is what lifts the block.
/// When a standing cover is being adopted the reload is skipped, because it would wipe the standing lockdown ruleset
/// (the live main ruleset) before Adopt.
///
/// A failed restore keeps the token and the record, so the next sweep still sees a cover rather than a clean host over
/// a block ([`release`]). `Ok` when the cover is gone; a failure is logged here and returned. Called by `Drop`
/// and the transient engage's back-out (through [`disengage`], which discard it: neither can act on it) and by
/// [`recover_cover_with`], whose caller outdates stamps only on `Ok`.
fn release_transient(
    token: Result<Option<&str>, RoutingError>,
    adopting: bool,
    ops: &mut dyn PfOps,
) -> Result<(), RoutingError> {
    let restored = if adopting {
        tracing::info!("standing lockdown cover being adopted; skipping /etc/pf.conf reload during transient sweep");
        Ok(())
    } else {
        ops.reload_default()
    };
    let released = release(ops, CoverKind::Transient, token, restored);
    if let Err(e) = &released {
        tracing::warn!(
            error = e as &dyn std::error::Error,
            "the transient cover was not released during cover disengage; its record is left for recovery"
        );
    }
    released
}

/// [`release_transient`] over the real `pfctl` and record, for the cover whose token is `token`. The failure is
/// already logged, and a `Drop` has nowhere to send it.
fn disengage(token: &str, lock: &CoverLock) {
    let _ = release_transient(Ok(Some(token)), false, &mut RealPfOps { lock });
}

pub fn recover_cover(lock: &CoverLock, adopting: bool) -> Result<(), RoutingError> {
    recover_cover_with(
        pf_record::read::<state::FailClosedState>(lock.state_dir()),
        adopting,
        &mut RealPfOps { lock },
    )
}

/// `recover_cover`'s trichotomy over [`StateFile`], with the [`PfOps`] injected. `Ok` when the cover is gone or
/// there was none; a release that left it in force (a failed restore, a record that stays) is the error.
///
/// The record is read as a [`StateFile`], which keeps `Unusable` apart from `Absent`: for a sweep they are opposite
/// facts. `Absent` is "no cover was ever engaged". `Unusable` is Hole's own unreconciled record that one was engaged
/// and never confirmed released (a corrupt or truncated file, or a version skew from a rollback), and collapsing it
/// would leave a crashed run's `block out all` on the host with the automatic sweep declining to act.
fn recover_cover_with(
    file: StateFile<state::FailClosedState>,
    adopting: bool,
    ops: &mut dyn PfOps,
) -> Result<(), RoutingError> {
    file.warn_if_not_evidence();
    match &file {
        StateFile::Absent => {
            tracing::debug!("no failclosed-state file, nothing to recover");
            return Ok(());
        }
        StateFile::Present(st) => tracing::info!(
            was_enabled = ?st.pf_was_enabled,
            "recovering fail-closed cover from crashed run"
        ),
        StateFile::Unusable { .. } => {}
        StateFile::Unreadable => {}
    }
    release_transient(file.release_token(), adopting, ops)
}

// --- lockdown layer ---

/// Snapshot the host's filter (`-sr`) and translation (`-sn`) rules and persist them with `token`
/// (persist-before-mutate). Returns the nat snapshot for the engage ruleset. Separate so the caller can unwind its `?`
/// error path (drop the pf refcount) without leaking the `-E` enable.
///
/// It runs before `engage_lockdown` loads anything: once our own labelled ruleset is loaded, `pfctl -sr` no longer sees
/// the host's policy, so a mutation ahead of this capture destroys the only copy of the baseline. The presence probe
/// leads because if our own cover is already loaded, `pfctl -sr` would return our block-all as the host's policy; it
/// asks [`lockdown_cover_presence`] and does not parse rule text.
fn capture_and_persist(
    token: &str,
    lock: &CoverLock,
    owner: Option<(u32, u32)>,
) -> Result<(String, Option<String>), RoutingError> {
    let presence = lockdown_cover_presence(lock.state_dir());
    let main_snapshot = pfctl_stdout(pfctl(&["-sr"], None, FatalPhase::CoverEngage), "pfctl -sr")?;
    let nat_snapshot = pfctl_stdout(pfctl(&["-sn"], None, FatalPhase::CoverEngage), "pfctl -sn")?;
    persist_baseline(token, lock, owner, presence, main_snapshot, nat_snapshot)
}

/// Persist the engage-time baseline. Pure over its inputs, so the self-capture guard is table-tested without pf.
/// Returns the nat snapshot for the engage ruleset and the token the replaced record named, if any
/// ([`drop_displaced`]).
///
/// When `presence` is [`CoverPresence::Live`](crate::routing::CoverPresence::Live) it persists `main_snapshot` empty
/// with `main_snapshot_captured: false`, and warns. The nat snapshot is persisted and returned exactly as `pfctl -sn`
/// gave it: those are the host's translation rules, carried into the engage ruleset, so zeroing them would flush live
/// host NAT with nothing on disk to restore from.
fn persist_baseline(
    token: &str,
    lock: &CoverLock,
    owner: Option<(u32, u32)>,
    presence: crate::routing::CoverPresence,
    main_snapshot: String,
    nat_snapshot: String,
) -> Result<(String, Option<String>), RoutingError> {
    let captured = presence != crate::routing::CoverPresence::Live;
    if !captured {
        tracing::warn!(
            "a lockdown cover is already loaded, so there is no pre-lockdown host ruleset to capture; \
             recording no baseline (a restore will reload /etc/pf.conf)"
        );
    }
    let displaced = pf_record::swap(
        lock,
        &lockdown_state::LockdownPfState {
            pf_token: token.to_owned(),
            main_snapshot: if captured { main_snapshot } else { String::new() },
            nat_snapshot: nat_snapshot.clone(),
            main_snapshot_captured: captured,
        },
        owner,
    )
    .map_err(|e| RoutingError::state_op_failed(StateOp::Write, "lockdown-pf-state", &e))?;
    Ok((nat_snapshot, displaced))
}

/// Engage the standing lockdown cover. Persist-before-mutate, no `-Fa`. It ensures pf is enabled (`engage_pf_action`
/// on the `pfctl -s info` read), so the ruleset never loads into a disabled, inert pf. The three cases:
///
/// - `FreshEnable` (no persisted state): `pfctl -E` and capture the token, snapshot `pfctl -sr` and `pfctl -sn`,
///   persist both before mutating.
/// - `ReuseToken` (adopt re-engage, pf still enabled): reuse the persisted token and snapshots. Re-running `-sr` and
///   `-sn` would snapshot our own lockdown ruleset as the host's.
/// - `Reenable` (adopt re-engage, pf disabled by a reboot): the token is stale, so `pfctl -E` for a fresh one and
///   re-persist it under the same host snapshot. Otherwise the ruleset loads into a disabled pf and the cover is inert
///   while reported active.
///
/// Then load the main ruleset via `pfctl -f -`. The load is last in every case: it must not precede
/// `capture_and_persist`'s snapshot, and a cold engage has no window that reordering could close (module doc).
///
/// On load failure the host is restored (`lockdown_disengage`) and `Err` returned; the bridge's fail-fatal caller
/// aborts the start.
pub fn engage_lockdown(
    lock: &CoverLock,
    server_ip: IpAddr,
    tun_name: &str,
    owner: Option<(u32, u32)>,
) -> Result<Cover, RoutingError> {
    // Decision-only: `LockdownPfState` records no `pf_was_enabled` bit, unlike the transient `FailClosedState`.
    let info = pfctl_stdout(pfctl(&["-s", "info"], None, FatalPhase::CoverEngage), "pfctl -s info")?;
    let pf_enabled = parse_pf_enabled(&info);
    // The record as a `StateFile`: an unusable or unreadable one is no baseline to reuse, and its token is dropped when
    // the engage's own record replaces it.
    let persisted = match pf_record::read::<lockdown_state::LockdownPfState>(lock.state_dir()) {
        StateFile::Present(st) => Some(st),
        StateFile::Absent => None,
        StateFile::Unusable { .. } => None,
        StateFile::Unreadable => None,
    };
    let mut ops = RealCoverRulesetOps;

    let (token, nat_snapshot) = match engage_pf_action(pf_enabled, persisted.is_some()) {
        // Adopt re-engage within one boot: pf still enabled and the token and snapshot held. Reuse both, so the host
        // policy survives for the eventual restore, and do not double `-E`.
        PfEngageAction::ReuseToken => {
            let st = persisted.expect("ReuseToken implies persisted state");
            (st.pf_token, st.nat_snapshot)
        }
        // The record survived but a reboot reset pf and its refcount. Enable afresh and re-persist the same host
        // snapshot under the fresh token; never re-snapshot the live lockdown ruleset.
        PfEngageAction::Reenable => {
            let st = persisted.expect("Reenable implies persisted state");
            let token = enable_pf_capture_token()?;
            let fresh = lockdown_state::LockdownPfState {
                pf_token: token.clone(),
                main_snapshot: st.main_snapshot,
                nat_snapshot: st.nat_snapshot.clone(),
                // Carried, not re-asserted: claiming a capture that never happened would restore an empty pass-all
                // ruleset.
                main_snapshot_captured: st.main_snapshot_captured,
            };
            match pf_record::swap(lock, &fresh, owner) {
                Ok(displaced) => drop_displaced(displaced.as_deref(), &token, |old| ops.drop_token(old)),
                Err(e) => {
                    drop_or_warn(&token, "unwinding a failed lockdown re-enable", |t| ops.drop_token(t));
                    return Err(RoutingError::state_op_failed(StateOp::Write, "lockdown-pf-state", &e));
                }
            }
            (token, st.nat_snapshot)
        }
        // First engage: enable + snapshot the host.
        PfEngageAction::FreshEnable => {
            let token = enable_pf_capture_token()?;
            // The refcount is held, so undo the `-E` on a capture or persist failure, or it leaks with no state file.
            match capture_and_persist(&token, lock, owner) {
                Ok((nat_snapshot, displaced)) => {
                    drop_displaced(displaced.as_deref(), &token, |old| ops.drop_token(old));
                    (token, nat_snapshot)
                }
                Err(e) => {
                    drop_or_warn(&token, "unwinding a failed lockdown engage", |t| ops.drop_token(t));
                    return Err(e);
                }
            }
        }
    };

    let main = build_lockdown_main_ruleset(tun_name, server_ip, &nat_snapshot);
    // Through the shared loader, so "no state purge" is [`purges_state`]'s decision and not the absence of a call here.
    if let Err(e) = load_cover_ruleset(CoverKind::Lockdown, &main, &mut ops) {
        // Restore the host before failing, so a partially loaded ruleset never strands it.
        lockdown_disengage(lock);
        return Err(e);
    }

    Ok(Cover {
        held: Some(Held { token }),
        stamp: lock.stamp_install(CoverKind::Lockdown),
    })
}

/// Fail-loud disengage of the standing cover: restore the host ([`restore_standing`]: the captured snapshot, else
/// `/etc/pf.conf`), clear the record, drop our pf refcount ([`release`]). Every release of the standing cover that is
/// not `release_all` comes here: `bridge unlock`, the startup sweep when the intent is off, the standing guard's `Drop`
/// and the back-out of a failed engage.
///
/// Gates on [`lockdown_cover_presence`] (pf's own answer folded with the state file), not on the file alone: pf's label
/// can outlive a lost or corrupted file. Only a presence of
/// [`CoverPresence::Absent`](crate::routing::CoverPresence::Absent) is a silent `Ok`; one that could not be established
/// ([`CoverPresence::Unreachable`](crate::routing::CoverPresence::Unreachable) or
/// [`CoverPresence::Indeterminate`](crate::routing::CoverPresence::Indeterminate)) refuses rather than claim success
/// having done nothing. A restore that fails propagates the error and leaves the record, and the token stays held with
/// it ([`release`]). A token that fails to drop is logged and is not the answer.
///
/// pf exposes no dump of prior `set` options, so the restore reloads the host's filter and nat rules under pf defaults.
///
/// The clearance is always [`Clearance::proven`], for the reason [`release_all`] gives: pf has no boot-time analogue,
/// so every macOS cover key is [`super::KeyLifetime::Persistent`].
pub(super) fn disengage_lockdown(lock: &CoverLock, _witness: super::ArmingWitness) -> SweepOutcome {
    // Presence and the state file come from one read ([`lockdown_presence_and_state`]), and the file is passed on as a
    // `StateFile` so a salvaged `pf_token` from an `Unusable` record still reaches `pfctl -X`.
    let (presence, file) = lockdown_presence_and_state(lock.state_dir());
    let error = disengage_lockdown_with(presence, file, &mut RealPfOps { lock }).err();
    SweepOutcome::per_kind(Clearance::proven(), [(CoverKind::Lockdown, error)])
}

/// `disengage_lockdown`'s sequencing, with presence and the [`PfOps`] seam
/// injected so the gate (and the "nothing to restore from" fallback) is
/// table-tested without shelling out to `pfctl`.
fn disengage_lockdown_with(
    presence: crate::routing::CoverPresence,
    st: StateFile<lockdown_state::LockdownPfState>,
    ops: &mut dyn PfOps,
) -> Result<(), RoutingError> {
    use crate::routing::CoverPresence;
    match presence {
        // Both sources agree there is nothing — no pfctl spawned.
        CoverPresence::Absent => return Ok(()),
        // Neither source could confirm anything: claiming success would be a false `Ok`. Refuse, and name the manual
        // recovery command.
        CoverPresence::Unreachable | CoverPresence::Indeterminate => {
            return Err(RoutingError::RouteSetup(
                "could not determine whether a lockdown cover is present; nothing was done — \
                 run `sudo pfctl -f /etc/pf.conf` to restore the system firewall manually"
                    .to_string(),
            ));
        }
        CoverPresence::Live | CoverPresence::Recorded => {}
    }

    let restored = restore_standing(&st, ops);

    // After a good restore, drops the token the record names (an unusable record's included) once the record no
    // longer names it.
    release(ops, CoverKind::Lockdown, st.release_token(), restored)
}

/// Fold the two independent presence sources into one answer. `pf_label` is
/// what pf said (`Some(true)`: our own rule label is loaded; `Some(false)`: it
/// is not; `None`: pf could not be asked); `file` is Hole's own
/// `bridge-lockdown-pf.json`.
///
/// pf's own confirmation wins outright. Failing that, a state file — readable
/// or not — is Hole's unreconciled record that a cover was engaged and never
/// confirmed released, which is [`CoverPresence::Recorded`](crate::routing::CoverPresence::Recorded). Only a pf that
/// answered "no" with nothing on disk contradicting it is `Absent`; a pf that
/// could not answer at all, with no file either, is `Unreachable`.
pub(crate) fn fold_presence(
    pf_label: Option<bool>,
    file: &super::StateFile<lockdown_state::LockdownPfState>,
) -> crate::routing::CoverPresence {
    use crate::routing::CoverPresence;
    match (pf_label, file) {
        (Some(true), _) => CoverPresence::Live,
        (_, StateFile::Present(_)) => CoverPresence::Recorded,
        (_, StateFile::Unusable { .. }) => CoverPresence::Recorded,
        (_, StateFile::Unreadable) => CoverPresence::Recorded,
        (Some(false), StateFile::Absent) => CoverPresence::Absent,
        (None, StateFile::Absent) => CoverPresence::Unreachable,
    }
}

/// Whether a standing lockdown cover is present, per pf and per Hole's own
/// state file. The pf half asks `pfctl -s labels` for [`LOCKDOWN_PF_LABEL`],
/// which is the only evidence here independent of `state_dir`.
pub fn lockdown_cover_presence(state_dir: &Path) -> crate::routing::CoverPresence {
    lockdown_presence_and_state(state_dir).0
}

/// [`lockdown_cover_presence`] and the record it was folded from, in one read, so the gate and the token cannot come
/// from two reads of the same file: a `Recorded` presence paired with a record that vanished in between would skip
/// `pfctl -X` for a cover it just confirmed.
fn lockdown_presence_and_state(
    state_dir: &Path,
) -> (
    crate::routing::CoverPresence,
    StateFile<lockdown_state::LockdownPfState>,
) {
    let pf_label = pf_label_answer(pfctl(&["-s", "labels"], None, BestEffortPhase::RecoverCover));
    let file = pf_record::read::<lockdown_state::LockdownPfState>(state_dir);
    (fold_presence(pf_label, &file), file)
}

/// Best-effort wrapper for the standing guard's `Drop` (user-stop) and the engage's back-out: disengage and log.
/// Neither has a caller to surface an error to. It runs this module's [`disengage_lockdown`] under the shared
/// `sweep_with_witness`, so a confirmed release outdates the kind's stamps like every other sweep. Not the facade's
/// cfg-dispatched sweep: a `pf_on_any_host` build must reach this module's `pfctl`, not another host's.
fn lockdown_disengage(lock: &CoverLock) {
    if let Err(e) = super::sweep_with_witness(lock, |witness| disengage_lockdown(lock, witness)) {
        tracing::warn!(
            error = &e as &dyn std::error::Error,
            "lockdown disengage failed during Drop or an engage's back-out"
        );
    }
}

// release_all =========================================================================================================

/// Seam over the pf operations `release_all_with` needs, so the ordering, the
/// no-short-circuit property, and the clear-only-on-confirm rule are
/// table-tested without shelling out to `pfctl`. A non-success `pfctl` exit
/// status is ALREADY folded into `Err` by the implementation (`RealPfOps`),
/// so `release_all_with` itself never inspects an exit code.
pub(crate) trait PfOps {
    /// `pfctl -f /etc/pf.conf`: reload the host's canonical ruleset.
    fn reload_default(&mut self) -> Result<(), RoutingError>;
    /// `pfctl -f -` with `text` on stdin: load a specific ruleset.
    fn load_ruleset(&mut self, text: &str) -> Result<(), RoutingError>;
    /// `pfctl -X <token>`: drop a pf enable refcount. Callers go through [`drop_or_warn`]; a failure is never a
    /// release's error.
    fn drop_token(&mut self, token: &str) -> Result<(), RoutingError>;
    /// Clear the transient cover's record under `token` ([`pf_record::clear_if_token`]): only a record naming it.
    /// What it found is a [`Cleared`]; a record that could not be read is `Kept`.
    fn clear_transient(&mut self, token: Option<&str>) -> Result<Cleared, RoutingError>;
    /// The same for the standing lockdown cover's record.
    fn clear_standing(&mut self, token: Option<&str>) -> Result<Cleared, RoutingError>;
}

/// The disclosure for an unusable record that yielded no token, the one case where nothing can be done about the
/// refcount. Shared by [`release`].
fn warn_unsalvageable_token(what: &str) {
    tracing::warn!(
        "{what} file is unusable and no pf token could be read out of it — a pf enable refcount \
         may be leaked (pf then stays enabled over the canonical /etc/pf.conf, which blocks \
         nothing, and a reboot resets it)"
    );
}

/// What a cover's record is called in a log line.
fn what(kind: CoverKind) -> &'static str {
    match kind {
        CoverKind::Transient => "transient failclosed-state",
        CoverKind::Lockdown => "standing lockdown-pf-state",
    }
}

/// Clear a cover's record under `token`. Keyed by [`CoverKind`] here and not a method on it because the clear is a
/// [`PfOps`] call, and `PfOps` is macOS-only while `CoverKind` is shared with Windows.
fn clear(kind: CoverKind, ops: &mut dyn PfOps, token: Option<&str>) -> Result<Cleared, RoutingError> {
    match kind {
        CoverKind::Transient => ops.clear_transient(token),
        CoverKind::Lockdown => ops.clear_standing(token),
    }
}

/// A clear that left a record it could not read is an error, never a success.
fn refused(cleared: Cleared) -> Result<(), RoutingError> {
    cleared.refusal().map_or(Ok(()), Err)
}

/// The release of one cover, after its restore was attempted. `token` is [`StateFile::release_token`]'s answer.
///
/// A record names only a token Hole holds ([`super::pf_record`]), so the record is cleared first and the token dropped
/// after, and only once the clear took the record that named it:
///
/// - A restore that failed is the error, as it came, and touches neither record nor token: the cover is still in
///   force, and the record and the refcount are what a later release acts by.
/// - A restore that held clears the record, and drops the token only if that clear took the record that named it. A
///   clear that cannot write is the error and drops nothing: the record still names a token Hole holds, and the retry
///   works. A clear that finds another token's record or none drops nothing either: the engage that displaced it
///   dropped it already. A record that could not be read stays and is the error.
///
/// A record that could not be read has no token to drop or clear by: it is left in place, and after a good restore the
/// answer is the refusal.
fn release(
    ops: &mut dyn PfOps,
    kind: CoverKind,
    token: Result<Option<&str>, RoutingError>,
    restored: Result<(), RoutingError>,
) -> Result<(), RoutingError> {
    let token = match token {
        Ok(token) => token,
        Err(unread) => {
            restored?;
            return Err(unread);
        }
    };
    restored?;
    let cleared = clear(kind, ops, token)?;
    if cleared.took_a_record_naming_no_token(token) {
        warn_unsalvageable_token(what(kind));
    }
    if let (Some(token), true) = (token, cleared.may_drop_the_token()) {
        drop_or_warn(token, &format!("releasing the {} pf refcount", what(kind)), |t| {
            ops.drop_token(t)
        });
    }
    refused(cleared)
}

/// The standing cover's restore: its captured snapshot, else `/etc/pf.conf`. Every release of the standing cover
/// goes through it: `release_all`, and `disengage_lockdown_with` for all its callers (the standing guard's `Drop`,
/// the back-out of a failed engage, the startup sweep when the intent is off, and `bridge unlock`).
///
/// [`StateFile::restore_choice`] chooses: only a record with a captured baseline has a snapshot to load, and every
/// other record reloads `/etc/pf.conf` (loading an empty snapshot would leave a pass-all host; see
/// `LockdownPfState::main_snapshot_captured`). A snapshot that will not load falls back to `/etc/pf.conf` rather than
/// leave the host blocked; when that fails too, the fallback's error is the answer (the last restore that ran) and
/// the snapshot's is logged.
fn restore_standing(
    standing: &StateFile<lockdown_state::LockdownPfState>,
    ops: &mut dyn PfOps,
) -> Result<(), RoutingError> {
    let Some(st) = standing.restore_choice() else {
        return ops.reload_default();
    };
    let snapshot_err = match ops.load_ruleset(&build_lockdown_restore_ruleset(&st.nat_snapshot, &st.main_snapshot)) {
        Ok(()) => return Ok(()),
        Err(e) => e,
    };
    match ops.reload_default() {
        Ok(()) => {
            tracing::warn!(
                error = &snapshot_err as &dyn std::error::Error,
                "captured pf snapshot could not load; fell back to the default ruleset — \
                 the host's captured pf rules could not be restored"
            );
            Ok(())
        }
        Err(fallback_err) => {
            tracing::error!(
                error = &snapshot_err as &dyn std::error::Error,
                "captured pf snapshot could not load, and neither could the default ruleset"
            );
            Err(fallback_err)
        }
    }
}

/// The unconditional two-cover clear, a pure sequencer over an injected [`PfOps`] so it is table-tested without pf. See
/// `failclosed::release_all` for the contract.
///
/// Two blocks, one error per cover, no `?`: a `?` would short-circuit the block that had not run yet. Each block's
/// failure decides only its own cover's release, which is restore, then clear the record, then drop the token if the
/// clear took the record ([`release`]).
pub(crate) fn release_all_with(
    transient: StateFile<state::FailClosedState>,
    standing: StateFile<lockdown_state::LockdownPfState>,
    ops: &mut dyn PfOps,
) -> SweepOutcome {
    // Each cover's release after its restore.
    let release_transient = |ops: &mut dyn PfOps, restored: Result<(), RoutingError>| {
        release(ops, CoverKind::Transient, transient.release_token(), restored).err()
    };
    let release_standing = |ops: &mut dyn PfOps, restored: Result<(), RoutingError>| {
        release(ops, CoverKind::Lockdown, standing.release_token(), restored).err()
    };

    // Block 1, transient cover. A failure here does not stop block 2: the standing cover blocks indefinitely and is
    // attempted regardless.
    transient.warn_if_not_evidence();
    let transient_err = match &transient {
        StateFile::Absent => None,
        StateFile::Present(_) => {
            let restored = ops.reload_default();
            release_transient(ops, restored)
        }
        StateFile::Unusable { .. } => {
            let restored = ops.reload_default();
            release_transient(ops, restored)
        }
        StateFile::Unreadable => {
            let restored = ops.reload_default();
            release_transient(ops, restored)
        }
    };

    // Block 2 — standing cover.
    let standing_err = match &standing {
        StateFile::Absent => None,
        StateFile::Present(_) => {
            let restored = restore_standing(&standing, ops);
            release_standing(ops, restored)
        }
        StateFile::Unusable { .. } => {
            let restored = restore_standing(&standing, ops);
            release_standing(ops, restored)
        }
        StateFile::Unreadable => {
            let restored = restore_standing(&standing, ops);
            release_standing(ops, restored)
        }
    };

    SweepOutcome::per_kind(
        Clearance::proven(),
        [
            (CoverKind::Transient, transient_err),
            (CoverKind::Lockdown, standing_err),
        ],
    )
}

/// Production [`PfOps`]: maps each method onto the existing `pfctl` helper,
/// converting a non-success exit status into `Err`.
struct RealPfOps<'a> {
    lock: &'a CoverLock,
}

/// Production [`EngageOps`]: the same mapping for the engage layer, one
/// [`FatalPhase::CoverEngage`] throughout — an engage is fail-fatal in both
/// covers, unlike [`RealPfOps`]'s best-effort recovery phase.
struct RealEngageOps<'a> {
    lock: &'a CoverLock,
    owner: Option<(u32, u32)>,
}

/// `pfctl -f -` with `text` on stdin, one [`FatalPhase::CoverEngage`] implementation shared by [`RealEngageOps`] and
/// [`RealCoverRulesetOps`].
///
/// `pub(super)` for the privileged test module, which loads a pre-fix control ruleset as the positive control for the
/// mid-stream proof. Production loads go through one of the two `*Ops` impls, which give each its phase.
pub(super) fn real_load_ruleset(text: &str) -> Result<(), RoutingError> {
    pfctl_status(
        pfctl(&["-f", "-"], Some(text.as_bytes()), FatalPhase::CoverEngage),
        "pfctl load",
    )
}

/// `pfctl -X <token>`: the one spawn site of a refcount drop, shared by every real ops impl. Best-effort whichever
/// phase asked: a token pf no longer holds fails here, and the caller logs it ([`drop_or_warn`]).
fn real_drop_token(token: &str) -> Result<(), RoutingError> {
    pfctl_status(pfctl(&["-X", token], None, BestEffortPhase::RecoverCover), "pfctl -X")
}

/// `pfctl -F states`, shared and `pub(super)` like [`real_load_ruleset`].
pub(super) fn real_flush_states() -> Result<(), RoutingError> {
    pfctl_status(
        pfctl(&["-F", "states"], None, FatalPhase::CoverEngage),
        "pfctl -F states",
    )
}

impl CoverRulesetOps for RealEngageOps<'_> {
    fn load_ruleset(&mut self, text: &str) -> Result<(), RoutingError> {
        real_load_ruleset(text)
    }

    fn flush_states(&mut self) -> Result<(), RoutingError> {
        real_flush_states()
    }

    fn drop_token(&mut self, token: &str) -> Result<(), RoutingError> {
        real_drop_token(token)
    }
}

impl EngageOps for RealEngageOps<'_> {
    fn pf_enabled(&mut self) -> Result<bool, RoutingError> {
        let info = pfctl_stdout(pfctl(&["-s", "info"], None, FatalPhase::CoverEngage), "pfctl -s info")?;
        Ok(parse_pf_enabled(&info))
    }

    fn enable_capture_token(&mut self) -> Result<String, RoutingError> {
        enable_pf_capture_token()
    }

    fn save_transient(&mut self, st: &state::FailClosedState) -> Result<Option<String>, RoutingError> {
        pf_record::swap(self.lock, st, self.owner)
            .map_err(|e| RoutingError::state_op_failed(StateOp::Write, "failclosed-state", &e))
    }

    fn transient_restore(&mut self, token: &str) {
        disengage(token, self.lock);
    }
}

/// Production [`CoverRulesetOps`] for a bare ruleset load and purge, with no `lock` or `owner` (see
/// [`engage_lockdown`]).
struct RealCoverRulesetOps;

impl CoverRulesetOps for RealCoverRulesetOps {
    fn load_ruleset(&mut self, text: &str) -> Result<(), RoutingError> {
        real_load_ruleset(text)
    }

    fn flush_states(&mut self) -> Result<(), RoutingError> {
        real_flush_states()
    }

    fn drop_token(&mut self, token: &str) -> Result<(), RoutingError> {
        real_drop_token(token)
    }
}

/// A `pfctl` output's stdout on success, or `Err` naming `what` and stderr on a non-zero exit. Every read of a snapshot
/// or status line goes through this: a failed run read as an empty answer would persist an empty snapshot that later
/// loads as the "restore", discarding the host's real pf policy.
fn pfctl_stdout(out: Result<std::process::Output, RoutingError>, what: &str) -> Result<String, RoutingError> {
    let out = out?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(RoutingError::RouteSetup(format!(
            "{what} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

fn pfctl_status(out: Result<std::process::Output, RoutingError>, what: &str) -> Result<(), RoutingError> {
    pfctl_stdout(out, what).map(|_| ())
}

impl PfOps for RealPfOps<'_> {
    fn reload_default(&mut self) -> Result<(), RoutingError> {
        pfctl_status(
            pfctl(&["-f", PFCONF], None, BestEffortPhase::RecoverCover),
            "pf default-ruleset reload",
        )
    }

    fn load_ruleset(&mut self, text: &str) -> Result<(), RoutingError> {
        pfctl_status(
            pfctl(&["-f", "-"], Some(text.as_bytes()), BestEffortPhase::RecoverCover),
            "pf ruleset load",
        )
    }

    fn drop_token(&mut self, token: &str) -> Result<(), RoutingError> {
        real_drop_token(token)
    }

    fn clear_transient(&mut self, token: Option<&str>) -> Result<Cleared, RoutingError> {
        pf_record::clear_if_token::<state::FailClosedState>(self.lock, token)
            .map_err(|e| RoutingError::state_op_failed(StateOp::Clear, "failclosed-state", &e))
    }

    fn clear_standing(&mut self, token: Option<&str>) -> Result<Cleared, RoutingError> {
        pf_record::clear_if_token::<lockdown_state::LockdownPfState>(self.lock, token)
            .map_err(|e| RoutingError::state_op_failed(StateOp::Clear, "lockdown-pf-state", &e))
    }
}

/// Clear every fail-closed cover macOS can install, without asking whether either is present. See
/// `failclosed::release_all` for the contract; this reads both records and delegates the sequencing to
/// [`release_all_with`].
///
/// The clearance is always [`Clearance::proven`]: pf has no boot-time analogue, so there is nothing a release can leave
/// unproven. macOS's `Ok` over a still-blocked host (promise 1, an entirely absent state file) is a different residual
/// and is not what the clearance tracks.
pub(super) fn release_all(lock: &CoverLock, _witness: super::ArmingWitness) -> SweepOutcome {
    let transient = pf_record::read::<state::FailClosedState>(lock.state_dir());
    let standing = pf_record::read::<lockdown_state::LockdownPfState>(lock.state_dir());
    release_all_with(transient, standing, &mut RealPfOps { lock })
}

#[cfg(test)]
#[path = "macos_tests.rs"]
mod macos_tests;

// Privileged-lane real-engage tests. A descendant of this module because they use [`Cover`]'s private `token` field and
// the private [`pfctl`] helper.
#[cfg(all(test, target_os = "macos"))]
#[path = "macos_transition_tests.rs"]
mod macos_transition_tests;
