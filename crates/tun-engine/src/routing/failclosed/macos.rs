//! macOS fail-closed cover via pf (`pfctl`). Two layers share the `Cover` guard:
//!
//! - **Transient cover** (`engage`/`disengage`): enables pf (refcounted,
//!   `pfctl -E`) and loads a self-contained ruleset (see `build_pf_ruleset`,
//!   via `pfctl -f -`, NO `-Fa`) blocking everything but loopback, the
//!   server, and the pinned resolver. Disengage restores the canonical
//!   `/etc/pf.conf`, clears the record and drops the refcount once that clear took the record (Release order,
//!   below). Dropping `-Fa` is load-bearing:
//!   `-Fa` flushes ALL pf state as its own, separately committed kernel
//!   operation, so `-Fa -f -` was two transactions with a
//!   pass-all host briefly live between them — including across a cover
//!   TRANSITION (a second `engage` replacing a still-live one, with no
//!   intervening `disengage`). That makes `engage` itself safe over a live
//!   cover; it does NOT make the bridge's cover transitions gap-free. The
//!   bridge's repair path and its lockdown-newly-enabled path both drop the held
//!   [`Cover`] first, and `Drop` reloads `/etc/pf.conf`, so the host is open
//!   until the next engage (bindreams/hole#758). A bare `pfctl -f -` load is a single pf
//!   transaction FOR THE RULES (DIOCADDRULE stages into an inactive ruleset
//!   under a ticket, DIOCXCOMMIT swaps it in atomically under `pf_lock`), so
//!   the old ruleset stays authoritative right up until the new one is fully
//!   committed. The `set` lines are NOT in that ticket: `pfctl` applies
//!   `set block-policy` / `skip` / `limit` / `timeout` through their own
//!   immediate ioctls as it parses, and it CLEARS every interface's skip flag
//!   in `main()` before it even begins parsing — both outside
//!   `DIOCXBEGIN`/`DIOCXCOMMIT`. The atomicity claim therefore covers the rules
//!   only, and the gap that leaves is a real one. It is not a hole in the
//!   fail-OPEN direction — none of those `set` ioctls is a permit — but a cover
//!   fails in BOTH directions, and this one fails by TIGHTENING: a cleared
//!   `skip on lo0` re-exposes loopback to the previous ruleset's `block out
//!   all` for the whole parse. `LOOPBACK_PASSES` is what closes it; see that
//!   const. Reading "no permit opens" as "no failure" is the same
//!   merge-two-causes-on-one-consequence mistake.
//!   A COLD engage (pf currently disabled) has NO gap of that class, and both
//!   engages deliberately keep `-E` first there. pf enforces nothing while
//!   disabled, so the pre-`-E` host is already maximally open and `-E` can
//!   only ADD filtering, whatever ruleset happens to be loaded; loading first
//!   would lengthen the fully-open stretch by one `pfctl` spawn, not shorten
//!   it. Order matters the other way instead: enabling is what makes the host
//!   dark, so it must precede the persist, or a failed `pf_record::swap` strands a
//!   blocking host with no file to recover it from (see `engage_with`'s step
//!   3). The load is followed by a `pfctl -F states` purge, which is what makes
//!   the cover apply to flows that predate it — pf matches state before rules.
//!   See `purges_state` for why that is the transient cover's call to make and
//!   not the standing lockdown's.
//! - **Standing lockdown** (`engage_lockdown`/`lockdown_disengage`): loads a
//!   self-contained MAIN ruleset (NO `-Fa`) that carries the host's translation
//!   rules forward and blocks all egress except the TUN and server IP. Disengage
//!   restores the host's pre-lockdown filter+nat from the persisted snapshot,
//!   clears the record and drops the refcount once that clear took the record. A record with no captured baseline
//!   reloads `/etc/pf.conf` instead, and so does a snapshot that will not load
//!   ([`restore_standing`]). Engage
//!   idempotently ENSURES pf is enabled (pf is disabled — and its refcount reset
//!   — across a reboot, but the state file persists), so a reconnect re-enables
//!   pf and loads a live ruleset instead of an inert one.
//!
//! - **Release order.** A record names only a token Hole holds ([`super::pf_record`]), so a release
//!   restores the host, clears the record, and drops the cover's `pfctl -E` token only if that clear
//!   took the record that named it ([`release`]). A clear that cannot write is the release's error and
//!   drops nothing, so the retry still has its token. A failed restore is the release's error and
//!   touches neither record nor token: the cover stays in force, evidence and refcount together, until
//!   a later release restores. A record that could not be read is left in place: after a good restore the
//!   release answers an error, never success. A drop that fails is only
//!   logged: the refcount stays until a reboot resets it, and with the host's rules restored it
//!   blocks nothing. Dropping Hole's token releases Hole's hold only: pf stays enabled over the restored
//!   rules while any other refcount holds it. Every `pfctl -X` goes through [`drop_or_warn`] over the caller's ops
//!   seam. An engage whose record write replaced one naming another token drops that token
//!   ([`drop_displaced`]). Every one of these runs under the cover lock.
//!
//! Documented caveats (pf has no programmatic API — `pfctl` text I/O IS the
//! interface, as `netsh`/`route` are for routing):
//! - The transient restore reloads `/etc/pf.conf`; the lockdown restore reloads
//!   the captured snapshot, or `/etc/pf.conf` when none was captured or it will
//!   not load. Neither can recover prior `set` options (pf exposes no dump of
//!   them), so both restore under pf defaults.
//! - The `pfctl -E` token is parsed from stderr — its only exposure.

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

/// Whether this platform's standing cover arms [`super::KeyLifetime::BootTime`]
/// keys, and therefore whether an engage has a [`super::boottime_witness`] to
/// record. **False on macOS**: pf has no boot-time analogue — a ruleset does
/// not survive a reboot at all (bindreams/hole#617) — so no macOS engage can
/// strand one and no macOS sweep consults or writes the record. That is also
/// why both sweep entry points here ignore their `witness` argument; they
/// answer [`Clearance::proven`] unconditionally, which carries no unproven key
/// for a witness to qualify.
pub(crate) const STANDING_COVER_ARMS_BOOT_TIME: bool = false;

/// The other half of that sentence, checked by the compiler. Windows writes
/// the record inside its own engage (`windows.rs`'s `commit_and_record`),
/// gated on this flag; macOS has no such site at all. Giving this platform
/// boot-time keys without also giving it a record write would leave the
/// uninstall gate blind on a platform that could strand one — so flipping the
/// constant fails the build until the write exists.
const _: () = assert!(
    !STANDING_COVER_ARMS_BOOT_TIME,
    "macOS arms no boot-time key and has no site that records the boot-time witness; a platform \
     that arms one needs both"
);

/// Build the self-contained pf ruleset (loaded via `pfctl -f -`).
///
/// `set block-policy drop` silently drops blocked packets (no RST/ICMP).
/// `block out all` is the fail-closed default; the `quick` pass rules for the
/// server IP and (when given) the resolver the caller's own `ech-doh` URL names
/// win without depending on pf's last-match rule. The `to {ip}` form carries a
/// v6 address as written. `resolver_ip` is `None` whenever nothing should be
/// permitted — see `Routing::install_failclosed_cover`'s doc for the exact
/// conditions. The resolver pass is scoped to `proto tcp port`
/// [`RESOLVER_PERMIT_PORT`] (see that const's doc for why this is the only port
/// this fetch can need) — NOT the server permit's unrestricted shape.
///
/// Loopback is exempted TWICE, by [`LOOPBACK_SKIP`] *and* [`LOOPBACK_PASSES`]
/// — see the latter for why one exemption is not enough. Both permits are
/// emitted through [`permit`], which is where the `no state` rule lives.
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

/// Terminate a cover `pass` rule with the `no state` qualifier EVERY permit in
/// EVERY cover ruleset carries, and hold the single statement of why. A permit
/// that does not come through here is a bug, in both covers and for two
/// different reasons.
///
/// `pfctl` normalizes a bare `pass out quick from any to 1.1.1.1` to
/// `... flags S/SA keep state` — measured, not assumed
/// (`transient_cover_permits_are_never_syn_only` and its lockdown twin run the
/// real `pfctl -vn -f -`). Such a rule matches ONLY a SYN, so a mid-stream
/// segment of a flow the permit names falls through to the block-all base and
/// is discarded under `block-policy drop` whenever that flow has no pf state
/// entry to be matched against first. Each cover reaches that condition by its
/// own route:
///
/// - [`CoverKind::Transient`] — the flow HAD an entry and lost it. The engage
///   follows its load with `pfctl -F states` ([`purges_state`]), which is
///   host-wide (`DIOCCLRSTATES`, no `psk_ifname`/`psk_ownername`), so it takes
///   the entries of flows this ruleset PERMITS along with everyone else's. The
///   resolver permit is the sharp edge: `resolver_ip` is the caller's own
///   `ech-doh` host, typically a well-known public DoH address a browser on the
///   same machine is already holding a TLS connection to.
/// - [`CoverKind::Lockdown`] — the flow never had an entry. `engage_lockdown`
///   runs AFTER `routing.install`, so the tunnel is already carrying traffic
///   when the ruleset commits; on stock macOS (pf loaded, never enabled) the
///   engage's own `pfctl -E` is what enabled pf, and pf creates no state for
///   packets it never saw. [`purges_state`] not purging preserves nothing,
///   because there is nothing there to preserve.
///
/// `no state` suppresses the `flags S/SA` default — that default is gated on
/// the rule keeping state — so the permit matches a mid-stream segment and
/// leaves nothing for a purge to take. Neither ruleset carries a `block in`, so
/// an outbound-only permit needs no state entry for its return traffic either.
/// Same primitive and same reason as [`LOOPBACK_PASSES`]; the one wrinkle noted
/// there applies here too — a matching `nat`/`rdr` rule (only
/// [`build_lockdown_main_ruleset`] carries translation) makes pf create state
/// regardless, which is harmless, because what severed the flow was the
/// `flags S/SA` MATCH and not the state entry.
fn permit(rule: &str) -> String {
    format!("{rule} no state\n")
}

/// The `set` half of the loopback exemption, holding its STEADY state: it
/// passes loopback "as if pf was disabled", with no state entry for the
/// transient cover's own `pfctl -F states` purge ([`purges_state`]) to flush.
///
/// Kept separate from [`LOOPBACK_PASSES`] because `require-order` puts Options
/// before Translation before Filter, and [`build_lockdown_main_ruleset`] fits
/// the host's `nat` snapshot between the two.
pub const LOOPBACK_SKIP: &str = "set skip on lo0\n";

/// The rule half of the loopback exemption, holding the one window
/// [`LOOPBACK_SKIP`] cannot hold for itself. Both halves are mandatory in every
/// cover ruleset; dropping either silently severs loopback, by its own route.
///
/// `set skip` is not part of the rule ticket. `pfctl`'s `main()` clears every
/// interface's skip flag (`DIOCCLRIFFLAG`, via `pfctl_clear_interface_flags`)
/// BEFORE `pfctl_rules()` — so before the `/etc/pf.os` fingerprint reload, the
/// parse, and `DIOCXBEGIN`. Across that whole span lo0 is filtered again while
/// the PREVIOUS ruleset is still the authoritative one, and if that previous
/// ruleset is a live cover, loopback meets its `block out all` and is discarded
/// under `block-policy drop`: an `ssh -L` forward or an IDE↔language-server
/// socket stalls to the macOS minimum RTO, a loopback datagram is lost
/// outright. Rules, unlike `set`, live inside the ticket and stay authoritative
/// to `DIOCXCOMMIT` — so it is the OUTGOING ruleset's own lo0 `pass` that
/// carries loopback across the NEXT load's flag-clear window. Every load
/// replacing a live cover is affected alike: a cover transition, the
/// `/etc/pf.conf` restore in [`disengage`], and lockdown engage/disengage.
///
/// `no state` is load-bearing here, for the reason [`permit`] states for every
/// permit in every cover ruleset; these rules are written out rather than built
/// by it only because they are a const. Without it they would reintroduce the
/// stateful-`pass` failure [`LOOPBACK_SKIP`] exists to avoid. (One exception,
/// benign: a matching nat/rdr rule makes pf create state even for a `no state`
/// filter rule. Only [`build_lockdown_main_ruleset`] carries translation rules,
/// and that cover does not purge — [`purges_state`].)
///
/// BOTH directions, though only `out` is load-bearing against today's
/// out-only blocks, because these rules stand in for [`LOOPBACK_SKIP`] and
/// `set skip` is direction-agnostic. An `out`-only stand-in would be a partial
/// replacement that silently stops covering the moment a ruleset grows a
/// `block in`.
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

/// Build the self-contained MAIN ruleset for the standing lockdown, loaded via
/// `pfctl -f -` (NO `-Fa`). It IS the host's egress policy while engaged:
/// `block drop out quick all` is the fail-closed base, with earlier `quick`
/// permits for the TUN and the server IP.
///
/// `set` lives here (main-ruleset-only — it is a parse error inside an anchor),
/// and the host's translation rules (`nat_snapshot`, from `pfctl -sn`) are
/// carried forward so the session does not flush NAT. Ordering is
/// `require-order`-enforced: Options -> Translation (nat) -> Filter. The server
/// permit precedes `block drop out quick inet6 all` so a v6 server is not
/// killed. pf has no per-process matching, so the server permit is IP-based.
///
/// Loopback is exempted twice over, by [`LOOPBACK_SKIP`] and
/// [`LOOPBACK_PASSES`], exactly as in [`build_pf_ruleset`]. The passes LEAD the
/// filter section: `block drop out quick inet6 all` is `quick`, so it would
/// terminate evaluation on a `::1` packet before any later lo0 rule. The server
/// and TUN permits are emitted through [`permit`] — the tunnel this ruleset
/// exists to protect is already LIVE when it commits, so a permit that matched
/// only a SYN would drop it.
///
/// The base rule's [`LOCKDOWN_PF_LABEL`] is **load-bearing**, not decoration:
/// it is the only evidence [`lockdown_cover_presence`] has that does not come
/// from `state_dir`. Dropping it returns macOS to file-only presence, which
/// cannot produce `Live` and therefore can neither repair an intent file nor
/// detect that we are about to snapshot our own cover as the host baseline.
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
/// `None` — not `Some(false)` — is what keeps the two-source design honest: a
/// pfctl that could not run is no evidence the cover is gone.
///
/// Both failures warn, and warn apart. `None` is the right ANSWER but a silent
/// one, indistinguishable in a log from a pfctl that ran and found nothing —
/// and this feeds `lockdown_presence_and_state`, so an operator debugging a
/// stuck disengage would otherwise have no trace that pf was never asked.
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
/// `set require-order no` leads: `pfctl -sr` on macOS emits a NORMALIZATION line
/// (`scrub-anchor "com.apple/*"`) interleaved with filter rules, so naively
/// concatenating `{nat}{filter}` puts translation before normalization — a
/// `require-order` parse error that would silently fail the restore. Disabling
/// the order check lets pfctl accept the snapshots verbatim, exactly as the
/// host had them loaded.
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

/// Decide how to (re)enable pf for a lockdown engage. `pf_enabled` is read from
/// `pfctl -s info`; `has_persisted` is whether a valid `bridge-lockdown-pf.json`
/// exists. The persisted-but-disabled case is the connected-session fail-open this
/// closes: always load the ruleset into an ENABLED pf, never an inert one.
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
    /// Release this process's claim on the cover without disengaging it.
    ///
    /// macOS holds NO process-local OS resource here: `token` is the
    /// `pfctl -E` enable ticket, and `Drop`'s `pfctl -X <token>` releases pf's
    /// enable refcount rather than freeing anything owned by this process.
    /// Leaving pf enabled is precisely what detaching means, so emptying the
    /// guard (`Drop` then disengages nothing) is the whole operation — unlike
    /// Windows, which must close its FWPM engine handle here.
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

/// Whether an engage of this cover kind follows its ruleset load with a
/// host-wide pf state purge (`pfctl -F states`). The ONE place either engage
/// decides whether a flow established before it survives it.
///
/// pf matches the state table **before** the ruleset (`pf_test` calls
/// `pf_test_state_*` and only reaches `pf_test_rule` on `s == NULL`), and
/// `DIOCXCOMMIT` leaves `tree_id` untouched — a state whose creating rule the
/// commit removed is kept alive by `rule->states`. So a flow already holding a
/// state entry when a cover loads keeps flowing past `block out all` until its
/// entry expires: `tcp.established` defaults to 86400s and every packet
/// refreshes it, so a long-lived upload, an SSH session or a WebSocket never
/// expires at all. Dropping `-Fa` (see this module's doc) no longer purges
/// state as a side effect, so each engage that needs one purges explicitly
/// here.
///
/// - [`CoverKind::Transient`] — **purge**. Reachable whenever pf was already
///   enabled ahead of us: Internet Sharing, another VPN, a hand-run
///   `pfctl -e`, or a cross-process transient engage over a still-live
///   standing ruleset left by an outgoing bridge's `CoverGuard::disarm`. There
///   is no tunnel of ours for it to kill — the transient cover is engaged in
///   `hold_pending`, *before* `start_inner`. The flush is nonetheless HOST-WIDE
///   (`DIOCCLRSTATES`, no `psk_ifname`/`psk_ownername`) — it takes the entries
///   of flows this ruleset PERMITS along with everyone else's — so what protects
///   the traffic this cover means to permit is the ruleset, never the flush's
///   scope, and nothing here may assume that traffic is a fresh post-engage
///   connection. Loopback is exempted with `set skip on lo0` rather than a
///   state-bearing `pass` ([`build_pf_ruleset`]); the server and resolver
///   permits carry `no state` ([`permit`]), so a flow whose entry this flush
///   took still matches its permit mid-stream.
/// - [`CoverKind::Lockdown`] — **do not purge** (bindreams/hole#1015's
///   remaining half, sequenced behind bindreams/hole#1002).
///   `engage_lockdown` runs with the tunnel LIVE, and `pfctl -F states` →
///   `DIOCCLRSTATES` is host-wide with neither `psk_ifname` nor
///   `psk_ownername` set: it would kill the very tunnel the kill switch
///   exists to protect. Not purging is not by itself enough to CARRY that
///   tunnel across the load — on a pf this engage's own `pfctl -E` enabled
///   there is no state to preserve — which is why the lockdown's permits are
///   `no state` too ([`permit`]). "Everything except the tunnel" needs
///   `DIOCKILLSTATES`' `psk_dst.neg`, which macOS's `pfctl` CLI has no flag
///   to set, so it is not expressible through the only interface pf offers.
const fn purges_state(kind: CoverKind) -> bool {
    match kind {
        CoverKind::Transient => true,
        CoverKind::Lockdown => false,
    }
}

/// Load `ruleset` as this cover's live pf policy, then apply [`purges_state`].
/// Both engages go through here, so the purge policy has one implementation
/// and one test, not one per call site.
///
/// The purge runs only AFTER a successful load, never before: flushing first
/// leaves a window in which state is gone but the permissive ruleset being
/// replaced is still live, so packets simply re-create their state under it.
/// A failed load never committed, so there is no new policy for a purge to
/// enforce and none is attempted.
///
/// A failed purge is logged, not propagated — the chosen contract (owner
/// decision), not an oversight. The engage then returns `Ok` with the cover
/// loaded, but flows that already held a state entry keep passing it
/// (pf matches state before rules); the only trace is the warn in
/// `bridge.log`, and nothing is surfaced to the caller or the user. Failing the
/// engage instead is fatal to the start and the transient path unwinds by
/// reloading `/etc/pf.conf` — a fully open host, which is worse than a cover
/// whose purge did not land. So the purge never promotes itself into an
/// engage failure.
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

/// Narrow seam [`load_cover_ruleset`] actually needs: load a ruleset and,
/// depending on [`purges_state`], flush pf's state table. Split out of
/// [`EngageOps`] (its supertrait) so the one caller that only ever needs
/// these two calls — `engage_lockdown`'s ruleset-load step — can be handed
/// exactly this instead of standing up a full `EngageOps` implementation
/// that also drags in `lock`/`owner` for methods it never calls.
pub(crate) trait CoverRulesetOps {
    /// `pfctl -f -` with `text` on stdin.
    fn load_ruleset(&mut self, text: &str) -> Result<(), RoutingError>;
    /// `pfctl -F states`: purge pf's state table, host-wide.
    fn flush_states(&mut self) -> Result<(), RoutingError>;
    /// `pfctl -X <token>`: drop a pf enable refcount. Callers go through [`drop_or_warn`].
    fn drop_token(&mut self, token: &str) -> Result<(), RoutingError>;
}

/// Seam over the pf + state-file mutations an engage performs, so its ordering
/// (enable → persist → load → purge), its unwind on a failed persist, and
/// which cover kinds purge pf state are table-tested without shelling out to
/// `pfctl`. As with [`PfOps`], a non-success `pfctl` exit status is folded
/// into `Err` by the production implementation ([`RealEngageOps`]).
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
    // 1. Read current enabled-state (read-only) — DIAGNOSTIC ONLY, so it is
    //    best-effort. `pf_was_enabled`'s single reader is a log field in
    //    `recover_cover`; nothing branches on it. Propagating a failure here
    //    would fail the cover OPEN — `install_failclosed_cover`'s caller logs
    //    "host NOT blocked, proceeding open" and starts the session uncovered —
    //    over a read that none of the cover-establishing steps below needs. A
    //    failure is recorded as `false`: the field is a `bool` because a
    //    rolled-back binary must still parse the state file (see its doc).
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

    // 2. Enable pf (refcounted) and capture the token. This runs BEFORE the
    //    load in both the warm and the cold case — see this module's doc for
    //    why a cold engage has no window to close by reordering, and why
    //    reordering would break step 3.
    let token = ops.enable_capture_token()?;

    // 3. Persist BEFORE loading the blocking ruleset (persist-before-mutate),
    //    so a crash after this point is recoverable (`pfctl -X <token>`).
    //
    //    The refcount is held from step 2 on, so a persist failure must undo
    //    the `-E` before propagating — else the refcount leaks with no state
    //    file to recover it from, exactly as `engage_lockdown`'s `FreshEnable`
    //    and `Reenable` arms already unwind. The failures this covers are the
    //    ones `pf_record::swap` really has: an unwritable state dir, a full disk,
    //    a state dir that is a symlink or has a third party's owner (refused).
    //    NOT a failed chown — `swap` hands the file over with `fchown`, which
    //    logs and swallows, so it cannot fail this call. Without the unwind, pf
    //    stays enabled until reboot under an unreferenced token — a
    //    fail-CLOSED leak hiding behind a path whose traffic verdict is
    //    fail-open. The refcount is the ONLY thing stranded: `swap` is
    //    temp file + rename, and the rename is both the sole writer of
    //    `bridge-failclosed.json` and the last step whose failure fails the
    //    save (a directory flush that fails after it is logged, and the save is
    //    `Ok`), so a failed save leaves no partial file for a later sweep to
    //    act on.
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

    // 4. Load our self-contained blocking ruleset from stdin — NO `-Fa`; see
    //    this module's doc for why that is atomic for the rules. The state
    //    purge that follows is [`purges_state`]'s call, not this site's.
    let ruleset = build_pf_ruleset(server_ip, resolver_ip);
    if let Err(e) = load_cover_ruleset(CoverKind::Transient, &ruleset, ops) {
        // A *failed engage* is the sole place this module fails OPEN on its own
        // error: we must not leave a half-loaded ruleset blocking traffic. A
        // failed `pfctl -f -` load never committed its RULES, so the host still
        // filters under whatever ruleset was loaded before this call. That is NOT the same
        // as "a no-op on the live config": everything `pfctl` does outside the
        // ticket lands even when the load then fails — the `set block-policy`/
        // `skip`/`limit`/`timeout` ioctls it issues as it parses (module doc),
        // and the interface skip flags it clears before parsing, which is why
        // `set skip` has to be restated by every ruleset. None of those is a
        // permit, so no hole opens; they TIGHTEN, which on this path is the
        // more dangerous direction and is not bounded by a window. A load that
        // failed before its `set skip on lo0` parsed leaves lo0 filtered under
        // the still-live previous ruleset INDEFINITELY — until some later
        // successful load restates the flag. `LOOPBACK_PASSES` is why that is
        // survivable: the previous ruleset carries its own lo0 passes, inside
        // the ticket, so loopback keeps flowing however long the flag stays
        // cleared. Restoring `/etc/pf.conf` here does not "undo a
        // flush" (there is none), it returns the host to its canonical
        // baseline rather than leaving it under a stale cover ruleset. The
        // PR3 cutover treats an engage error as fatal and aborts before
        // stopping the old bridge, so the tunnel is never torn down
        // uncovered. No standing cover is being adopted on this
        // engage-failure path, so the `/etc/pf.conf` restore must run.
        //
        // Known residual (bindreams/hole#1004, not fixed here): if THIS call
        // is a transition over a still-live prior cover (see this module's
        // doc), that prior cover's ruleset was still loaded and still
        // blocking right up until this failed load — the `/etc/pf.conf`
        // reload below replaces it with the open host baseline rather than
        // leaving the still-good prior ruleset in place. `engage` has no
        // parameter today to tell "first engage" from "transition" apart —
        // which is why the warn below fires unconditionally: this site cannot
        // tell the harmless case from the one that is about to open a host a
        // live cover was still holding, so it says so and leaves that to the
        // reader.
        //
        // Prospective, not accomplished: this fires BEFORE the restore it
        // describes, and `transient_restore` reports back nothing a phrasing
        // could branch on. A restore that itself fails leaves the host behind
        // the prior cover's block-all, so a categorical "the host is now OPEN"
        // would be a falsehood stated as fact — and the only thing
        // contradicting it would be `disengage`'s own failure lines below,
        // which is exactly what this warn now sends the reader to.
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
/// a block ([`release`]). Shared by `Drop`, `recover_cover` and the transient engage's back-out.
fn disengage_with(token: Result<Option<&str>, RoutingError>, adopting: bool, ops: &mut dyn PfOps) {
    let restored = if adopting {
        tracing::info!("standing lockdown cover being adopted; skipping /etc/pf.conf reload during transient sweep");
        Ok(())
    } else {
        ops.reload_default()
    };
    if let Err(e) = release(ops, CoverKind::Transient, token, restored) {
        tracing::warn!(
            error = &e as &dyn std::error::Error,
            "the transient cover was not released during cover disengage; its record is left for recovery"
        );
    }
}

/// [`disengage_with`] over the real `pfctl` and record, for the cover whose token is `token`.
fn disengage(token: &str, lock: &CoverLock) {
    disengage_with(Ok(Some(token)), false, &mut RealPfOps { lock });
}

pub fn recover_cover(lock: &CoverLock, adopting: bool) {
    recover_cover_with(
        pf_record::read::<state::FailClosedState>(lock.state_dir()),
        adopting,
        &mut RealPfOps { lock },
    );
}

/// `recover_cover`'s trichotomy over [`StateFile`], with the [`PfOps`] injected.
///
/// Reads the record as a [`StateFile`], which keeps `Unusable` apart from `Absent`,
/// and for a SWEEP those two are opposite facts. `Absent` is "no cover was ever engaged". `Unusable` is
/// Hole's own unreconciled record that one WAS engaged and never confirmed
/// released — a corrupt file, a truncated write, or a version skew (a rollback
/// across a bumped schema version). Collapsing it would leave a
/// crashed covered run's `block out all` on the host with the automatic sweep
/// declining to act, and only the manual `bridge unlock` left to escape — the
/// same conflation `release_all_with` already refuses to make.
fn recover_cover_with(file: StateFile<state::FailClosedState>, adopting: bool, ops: &mut dyn PfOps) {
    file.warn_if_not_evidence();
    match &file {
        StateFile::Absent => {
            tracing::debug!("no failclosed-state file, nothing to recover");
            return;
        }
        StateFile::Present(st) => tracing::info!(
            was_enabled = ?st.pf_was_enabled,
            "recovering fail-closed cover from crashed run"
        ),
        StateFile::Unusable { .. } => {}
        StateFile::Unreadable => {}
    }
    disengage_with(file.release_token(), adopting, ops);
}

// --- lockdown layer ---

/// Snapshot the host's filter (`-sr`) and translation (`-sn`) rules and persist
/// them with `token` (persist-before-mutate). Returns the nat snapshot for the
/// engage ruleset. Separated so its `?`-error path can be unwound (drop the pf
/// refcount) by the caller without leaking the `-E` enable.
///
/// Runs before `engage_lockdown` loads anything, and that is load-bearing: once
/// our own labelled ruleset is the loaded one, `pfctl -sr` no longer sees the
/// host's policy, and the state file that would otherwise hold it does not
/// exist yet. A mutation ahead of this capture therefore destroys the only copy
/// of the baseline, permanently — every later engage re-reads its own cover.
///
/// `presence` is the engage's one measurement, taken before it changed anything: if OUR OWN cover is already the
/// loaded ruleset, `pfctl -sr` would hand back our block-all as if it were the host's policy. Detection asks
/// [`lockdown_cover_presence`] rather than parsing rule text, so it depends on no claim about `pfctl -sr`'s print
/// format.
fn capture_and_persist(
    token: &str,
    lock: &CoverLock,
    owner: Option<(u32, u32)>,
    presence: crate::routing::CoverPresence,
) -> Result<(String, Option<String>), RoutingError> {
    let main_snapshot = pfctl_stdout(pfctl(&["-sr"], None, FatalPhase::CoverEngage), "pfctl -sr")?;
    let nat_snapshot = pfctl_stdout(pfctl(&["-sn"], None, FatalPhase::CoverEngage), "pfctl -sn")?;
    persist_baseline(token, lock, owner, presence, main_snapshot, nat_snapshot)
}

/// Persist the engage-time baseline. Pure over its inputs — the snapshots and
/// the measured `presence` come from the caller — so the self-capture guard is
/// table-tested without touching pf. Returns the nat snapshot for the engage
/// ruleset and the token the replaced record named, if any ([`drop_displaced`]).
///
/// When `presence` is [`CoverPresence::Live`](crate::routing::CoverPresence::Live)
/// this does exactly three things differently: it persists `main_snapshot`
/// empty, it persists `main_snapshot_captured: false`, and it warns. It
/// persists `nat_snapshot` exactly as `pfctl -sn` returned it and returns that
/// same value — those are the HOST's translation rules, carried forward
/// verbatim into the ruleset engage loads, so zeroing them would flush a live
/// host NAT the moment the cover engages, with nothing on disk to restore from.
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

/// Engage the standing lockdown cover. Persist-before-mutate, no `-Fa`. Engage
/// idempotently ENSURES pf is enabled (`engage_pf_action` on the `pfctl -s info`
/// read) so the ruleset never loads into a disabled, INERT pf. The three cases
/// (single-line bullets keep clippy's doc_lazy_continuation happy):
///
/// - `FreshEnable` (no persisted state): `pfctl -E` (refcount) + capture token, snapshot `pfctl -sr` (filter) and `pfctl -sn` (nat), persist {token, snapshots} before mutating.
/// - `ReuseToken` (Adopt re-engage, pf still enabled): reuse the persisted token + snapshots; re-running `-sr`/`-sn` would snapshot our OWN lockdown ruleset as the host and lose the real host policy.
/// - `Reenable` (Adopt re-engage but pf DISABLED, e.g. a reboot reset pf and its refcount): the persisted token is stale, so `pfctl -E` for a FRESH token and re-persist it under the SAME host snapshot. Without this the ruleset loads into a disabled pf and the cover is inert while reported active — egress in the clear during an armed session, not just the boot window.
///
/// Then load the self-contained main ruleset via `pfctl -f -` (NO `-Fa`), so the
/// block takes effect while host translation is carried forward. The load is
/// LAST in every case, including a cold one: it must not precede
/// `capture_and_persist`'s snapshot (which it would overwrite — see that
/// function's doc), and a cold engage has no window that reordering could close
/// (this module's doc).
///
/// On load failure Err is returned and the bridge's fail-FATAL caller aborts the start. A failed engage never touches
/// the rules: `pfctl -f` commits a whole ruleset or none (measured by the privileged `macos_lockdown_failed_engage_`
/// tests, which compare `pfctl -sr` across a failed load), so whatever was loaded before stays, and a cover in force
/// stays in force. pf applies `set` options outside that transaction, and they are identical across lockdown engages.
/// It gives back only what it took, through [`unwind_engage`]: the fresh token (`FreshEnable`, `Reenable`) and its
/// record write, which is put back as read before the engage, or cleared if there was none. `ReuseToken` took
/// nothing. The token the engage's record write displaced is dropped only once the load succeeded, so the put-back
/// never names a token that was dropped.
pub fn engage_lockdown(
    lock: &CoverLock,
    server_ip: IpAddr,
    tun_name: &str,
    owner: Option<(u32, u32)>,
) -> Result<Cover, RoutingError> {
    // The `pfctl -s info` read is decision-only — `LockdownPfState` records no
    // `pf_was_enabled` bit (unlike the transient `FailClosedState`).
    let info = pfctl_stdout(pfctl(&["-s", "info"], None, FatalPhase::CoverEngage), "pfctl -s info")?;
    let pf_enabled = parse_pf_enabled(&info);
    // The engage's one presence measurement, with the record it was folded from: taken before anything changes, it
    // decides the baseline capture. An unusable or unreadable record is no baseline to reuse, and its token is
    // dropped when the engage's own record replaces it.
    let (presence, record) = lockdown_presence_and_state(lock.state_dir());
    let prior = match record {
        StateFile::Present(st) => Some(st),
        StateFile::Absent => None,
        StateFile::Unusable { .. } => None,
        StateFile::Unreadable => None,
    };
    let mut ops = RealCoverRulesetOps;

    let action = engage_pf_action(pf_enabled, prior.is_some());
    // `fresh` is whether this engage took the token (`ReuseToken` takes none), `displaced` the token its record write
    // replaced.
    let (token, nat_snapshot, fresh, displaced) = match action {
        // Live Adopt re-engage within one boot: pf still enabled and we hold the
        // token+snapshot. Reuse both so the real host policy is preserved for the
        // eventual restore. ReuseToken assumes our refcount is still live (the
        // reboot case is `Reenable`); do not double `-E`.
        PfEngageAction::ReuseToken => {
            let st = prior.as_ref().expect("ReuseToken implies persisted state");
            (st.pf_token.clone(), st.nat_snapshot.clone(), false, None)
        }
        // Persisted state survived but pf was disabled (reboot reset pf and its
        // refcount). Enable afresh and re-persist the SAME host snapshot under the
        // fresh token — never re-snapshot the live lockdown ruleset. The single
        // `pfctl -X <fresh-token>` on disengage matches this single `-E`.
        PfEngageAction::Reenable => {
            let st = prior.as_ref().expect("Reenable implies persisted state");
            let token = enable_pf_capture_token()?;
            let fresh = lockdown_state::LockdownPfState {
                pf_token: token.clone(),
                main_snapshot: st.main_snapshot.clone(),
                nat_snapshot: st.nat_snapshot.clone(),
                // Carried, not re-asserted: this re-persists the SAME baseline
                // under a fresh token, so claiming a capture that never
                // happened would restore an empty pass-all ruleset.
                main_snapshot_captured: st.main_snapshot_captured,
            };
            let displaced = match pf_record::swap(lock, &fresh, owner) {
                Ok(displaced) => displaced,
                Err(e) => {
                    unwind_engage(lock, owner, Some(&token), prior.as_ref(), |t| ops.drop_token(t));
                    return Err(RoutingError::state_op_failed(StateOp::Write, "lockdown-pf-state", &e));
                }
            };
            (token, st.nat_snapshot.clone(), true, displaced)
        }
        // First engage: enable + snapshot the host.
        PfEngageAction::FreshEnable => {
            let token = enable_pf_capture_token()?;
            // The refcount is now held. Capture + persist may fail, so undo the
            // `-E` on any error before propagating — else the refcount leaks with
            // no state file to recover it from.
            match capture_and_persist(&token, lock, owner, presence) {
                Ok((nat_snapshot, displaced)) => (token, nat_snapshot, true, displaced),
                Err(e) => {
                    unwind_engage(lock, owner, Some(&token), None, |t| ops.drop_token(t));
                    return Err(e);
                }
            }
        }
    };

    let main = build_lockdown_main_ruleset(tun_name, server_ip, &nat_snapshot);
    // Through the shared loader, so this path's "no state purge" is
    // [`purges_state`]'s decision rather than the absence of a call here. Only
    // `load_ruleset`/`flush_states` are needed here, so this passes the
    // narrow `CoverRulesetOps` seam (`RealCoverRulesetOps`) rather than
    // standing up a full `RealEngageOps` with a `lock`/`owner` this call
    // never reads.
    if let Err(e) = load_cover_ruleset(CoverKind::Lockdown, &main, &mut ops) {
        unwind_engage(lock, owner, fresh.then_some(token.as_str()), prior.as_ref(), |t| {
            ops.drop_token(t)
        });
        return Err(e);
    }
    drop_displaced(displaced.as_deref(), &token, |old| ops.drop_token(old));

    Ok(Cover {
        held: Some(Held { token }),
        stamp: lock.stamp_install(CoverKind::Lockdown),
    })
}

/// What a failed [`engage_lockdown`] gives back: the `fresh` token it took (`None`: it took none) and the record it
/// wrote for it. `prior` is the record read before the engage, `None` if there was no usable one: it is written back,
/// or the record is cleared when there is none. The record goes first and the token after, once the record no longer
/// names it ([`super::pf_record`]); a record that cannot be written back still names the token, which stays held. A
/// record that does not name `fresh` (the engage failed before writing it) is not the engage's to change. It never
/// reloads rules: a failed load changed none, and the cover in force before the engage, if any, is the user's.
fn unwind_engage(
    lock: &CoverLock,
    owner: Option<(u32, u32)>,
    fresh: Option<&str>,
    prior: Option<&lockdown_state::LockdownPfState>,
    drop: impl FnOnce(&str) -> Result<(), RoutingError>,
) {
    let Some(fresh) = fresh else { return };
    let current = pf_record::read::<lockdown_state::LockdownPfState>(lock.state_dir());
    if pf_record::names(&current, Some(fresh)) {
        let put_back = match prior {
            Some(prior) => pf_record::swap(lock, prior, owner).map(|_| ()),
            None => pf_record::clear_if_token::<lockdown_state::LockdownPfState>(lock, Some(fresh)).map(|_| ()),
        };
        if let Err(e) = put_back {
            let e = RoutingError::state_op_failed(StateOp::Write, "lockdown-pf-state", &e);
            tracing::warn!(
                error = &e as &dyn std::error::Error,
                "a failed lockdown engage could not undo its record; the record still names the engage's pf token, \
                 which stays held"
            );
            return;
        }
    }
    drop_or_warn(fresh, "unwinding a failed lockdown engage", drop);
}

/// Fail-loud disengage of the standing cover: restore the host ([`restore_standing`]: the captured snapshot, else
/// `/etc/pf.conf`), clear the record, drop our pf refcount ([`release`]). Every release of the standing cover that is
/// not `release_all` comes here: `bridge unlock`, the startup sweep when the intent is off and the standing guard's
/// `Drop`. A failed engage does not: it gives back only what it took ([`unwind_engage`]).
///
/// Gates on [`lockdown_cover_presence`] — pf's own answer folded with the
/// state file — not on the file alone (#882): a state file that is absent or
/// unusable is not proof pf was never engaged, since pf's label can outlive a
/// lost or corrupted file. Only a presence [`CoverPresence::Absent`](crate::routing::CoverPresence::Absent) (both
/// sources agree there is nothing) is a silent `Ok`; a presence that could not
/// be established at all ([`CoverPresence::Unreachable`](crate::routing::CoverPresence::Unreachable)/
/// [`CoverPresence::Indeterminate`](crate::routing::CoverPresence::Indeterminate)) refuses rather than claim success having
/// done nothing. A restore that fails propagates the error and LEAVES the
/// state file in place, so a retry (or the next start) still sees the cover
/// rather than reading "disengaged" while the block persists; the token stays
/// held with it ([`release`]). A token that fails to drop is logged and is not
/// the answer: after a good restore it blocks nothing.
///
/// Caveat: pf exposes no dump of prior `set` options, so the restore reloads the
/// host's filter+nat rules under pf defaults (same class of limitation the
/// transient cover documents for its `/etc/pf.conf` reload).
/// The clearance is unconditionally [`Clearance::proven`], for the reason
/// [`release_all`] gives: pf has no boot-time analogue — a ruleset does not
/// survive a reboot at all — so every macOS cover key is
/// [`super::KeyLifetime::Persistent`] and a disengage has nothing to leave
/// unproven.
pub(super) fn disengage_lockdown(lock: &CoverLock, _witness: super::ArmingWitness) -> SweepOutcome {
    // `Clearance::proven` on both arms: this platform has no boot-time key
    // class, so a macOS disengage carries nothing for the record to learn
    // from whether it succeeded or failed. The failing arm's clearance is
    // dropped by `sweep_with_witness` in any case — only its
    // `witness_update` is read, and that is `Leave` here.
    //
    // Presence and the state file come from ONE read
    // ([`lockdown_presence_and_state`]), and the file is passed on as a
    // `StateFile`: collapsing `Unusable` to an absent record here would hide the
    // salvaged `pf_token` that [`disengage_lockdown_with`] hands `pfctl -X`.
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
        // Neither source could confirm anything either way: claiming success
        // here would be the #882 bug in a different guise. Refuse loud and
        // name the manual recovery command.
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

    // After a good restore it drops the token the record names, an UNUSABLE record's included, once the record no
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

/// [`lockdown_cover_presence`] and the record it was folded from, in ONE read.
/// `disengage_lockdown` needs both, and taking them separately would let the
/// gate and the token come from two different reads of the same file — a
/// `Recorded` presence paired with a record that vanished in between skips
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

/// Best-effort wrapper for the standing guard's `Drop` (user-stop): disengage and log. `Drop` has no caller to surface
/// an error to. It runs this module's [`disengage_lockdown`] under the shared
/// `sweep_with_witness`, so a confirmed release outdates the kind's stamps like every other sweep. Not the facade's
/// cfg-dispatched sweep: a `pf_on_any_host` build must reach this module's `pfctl`, not another host's.
fn lockdown_disengage(lock: &CoverLock) {
    if let Err(e) = super::sweep_with_witness(lock, |witness| disengage_lockdown(lock, witness)) {
        tracing::warn!(
            error = &e as &dyn std::error::Error,
            "lockdown disengage failed during Drop"
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

/// The disclosure for an unusable record that yielded no token at all — the
/// one case where nothing can be done about the refcount. Shared by
/// [`release`], so every release discloses the same leak the same way.
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
/// A record that could not be read has no token to drop or clear by: it is left in place. After a good restore the
/// answer is the refusal, never success; a failed restore is the error, as above.
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
/// the startup sweep when the intent is off, and `bridge unlock`).
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

/// The unconditional two-cover clear, factored as a pure sequencer over an
/// injected [`PfOps`] so it is table-tested without touching pf. See
/// `failclosed::release_all`'s doc for the contract this implements.
///
/// Two blocks, one error per cover, no `?` — a `?` would short-circuit the block
/// that had not run yet. Each block's failure decides only its own cover's
/// release. Each cover is restored, then its record cleared, then its token dropped if that clear took the record
/// ([`release`]).
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

    // Block 1 — transient cover. A reload failure is recorded but does NOT
    // stop block 2: the standing cover is the one that blocks indefinitely
    // and must be attempted regardless.
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

/// `pfctl -f -` with `text` on stdin, one [`FatalPhase::CoverEngage`]
/// implementation shared by [`RealEngageOps`] and [`RealCoverRulesetOps`] so
/// the narrower seam is not a second copy of the shell-out.
///
/// `pub(super)` for the privileged test module next door, which loads a
/// deliberately PRE-FIX control ruleset as the positive control for the
/// mid-stream proof. Not a seam production code may reach for: every
/// production load goes through one of the two `*Ops` impls above, which is
/// what gives each its phase.
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

/// `pfctl -F states`, same sharing rationale — and same `pub(super)` caveat —
/// as [`real_load_ruleset`].
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

/// Production [`CoverRulesetOps`] for a bare ruleset-load-and-purge, with no
/// `lock`/`owner` — unlike [`RealEngageOps`], which the `Lockdown` engage
/// path does not need for this step (see its call site in
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

/// A `pfctl` output's stdout on success, or `Err` naming `what` + stderr on a
/// non-zero exit. Every read of a `pfctl` snapshot or status line must go
/// through this: reading `.stdout` off an `Ok(Output)` without checking
/// `status.success()` treats a failed `pfctl` run as an empty answer instead
/// of a failure — an empty filter/nat snapshot then persists and later loads
/// verbatim as the "restore", silently discarding the host's real pf policy.
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

/// Clear every fail-closed cover macOS can install — both the transient
/// block-until-connected cover and the standing lockdown cover — without
/// asking whether either is present. See `failclosed::release_all` for the
/// full contract; this loads both state-file presences and delegates the
/// sequencing to [`release_all_with`].
///
/// The clearance is unconditionally [`Clearance::proven`]: pf has no boot-time
/// analogue — a ruleset does not survive a reboot at all — so every macOS
/// cover key is [`super::KeyLifetime::Persistent`] and there is nothing a
/// release can leave unproven. macOS's own "`Ok` over a still-blocked host" residual is a
/// different one (an entirely absent state file, clause 1) and is not what
/// this type tracks.
pub(super) fn release_all(lock: &CoverLock, _witness: super::ArmingWitness) -> SweepOutcome {
    let transient = pf_record::read::<state::FailClosedState>(lock.state_dir());
    let standing = pf_record::read::<lockdown_state::LockdownPfState>(lock.state_dir());
    // Both arms `Clearance::proven`, for the reason `disengage_lockdown`
    // gives: no boot-time key class here, so nothing a failure could have
    // observed and withheld.
    release_all_with(transient, standing, &mut RealPfOps { lock })
}

#[cfg(test)]
#[path = "macos_tests.rs"]
mod macos_tests;

/// Privileged-lane real-engage tests. A DESCENDANT of this module, not a
/// sibling of the other `*_privileged_tests.rs` files under `failclosed`,
/// because they reach for [`Cover`]'s private `token` field and the private
/// [`pfctl`] helper — and that is what descendance buys, not sharing a file
/// with [`macos_tests`].
#[cfg(all(test, target_os = "macos"))]
#[path = "macos_transition_tests.rs"]
mod macos_transition_tests;
