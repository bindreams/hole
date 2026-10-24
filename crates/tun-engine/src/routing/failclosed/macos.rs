//! macOS fail-closed cover via pf (`pfctl`). Two layers share the `Cover` guard:
//!
//! - **Transient cover** (`engage`/`disengage`): enables pf (refcounted,
//!   `pfctl -E`) and loads a self-contained ruleset (see `build_pf_ruleset`,
//!   via `pfctl -f -`, NO `-Fa`) blocking everything but loopback, the
//!   server, and the pinned resolver. Disengage restores the canonical
//!   `/etc/pf.conf` and drops the refcount. Dropping `-Fa` is load-bearing:
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
//!   dark, so it must precede the persist, or a failed `state::save` strands a
//!   blocking host with no file to recover it from (see `engage_with`'s step
//!   3). The load is followed by a `pfctl -F states` purge, which is what makes
//!   the cover apply to flows that predate it — pf matches state before rules.
//!   See `purges_state` for why that is the transient cover's call to make and
//!   not the standing lockdown's.
//! - **Standing lockdown** (`engage_lockdown`/`lockdown_disengage`): loads a
//!   self-contained MAIN ruleset (NO `-Fa`) that carries the host's translation
//!   rules forward and blocks all egress except the TUN and server IP. Disengage
//!   restores the host's pre-lockdown filter+nat from the persisted snapshot —
//!   not a blind `/etc/pf.conf` reload — and drops the refcount. Engage
//!   idempotently ENSURES pf is enabled (pf is disabled — and its refcount reset
//!   — across a reboot, but the state file persists), so a reconnect re-enables
//!   pf and loads a live ruleset instead of an inert one.
//!
//! - **Claim before restore.** A release rewrites each live record as a tombstone
//!   (`releasing`) before any pf call, restores, drops the token, and only then
//!   clears the tombstone, so a failed drop leaves the record for a retry. A token
//!   is dropped once however many parties ask ([`super::dropped_tokens`]), and an
//!   engage never writes a record once a release has begun
//!   ([`super::release_epoch`]). An engage that lost backs out and, if its own
//!   restore fails, puts its record back. The rules are in [`super::pf_claim`], the
//!   interleavings in `macos_interleaving_tests`.
//!
//! Documented caveats (pf has no programmatic API — `pfctl` text I/O IS the
//! interface, as `netsh`/`route` are for routing):
//! - The transient restore reloads `/etc/pf.conf`; the lockdown restore reloads
//!   the captured snapshot. Neither can recover prior `set` options (pf exposes
//!   no dump of them), so both restore under pf defaults.
//! - The `pfctl -E` token is parsed from stderr — its only exposure.

// Test builds on other hosts compile this module to drive its sequencers; the
// production `pfctl` entry points have no caller there.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::net::IpAddr;
use std::path::Path;

#[cfg(target_os = "macos")]
use super::super::run_capturing;
use super::super::{BestEffortPhase, FatalPhase, Phase};
use crate::error::RoutingError;
#[cfg(target_os = "macos")]
use util::system_tool::SystemTool;
// `macos.rs` is mounted as `mod platform` under `failclosed`, so `super` is the
// `failclosed` module and `failclosed_state` is its sibling child.
use super::dropped_tokens;
use super::failclosed_state as state;
use super::lockdown_pf_state as lockdown_state;
use super::pf_claim::{self, Cleared, Record};
use super::release_epoch::ReleaseWatch;
use super::Clearance;
use super::StateFile;
use super::Swap;
use super::SweepOutcome;
use super::RESOLVER_PERMIT_PORT;

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
                error = %util::error_chain::error_chain(&e),
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

/// The ruleset that restores the host to `st`'s baseline, or `None` when it has
/// no captured baseline and `/etc/pf.conf` is the restore target — see
/// `LockdownPfState::main_snapshot_captured`.
fn baseline_restore_ruleset(st: &lockdown_state::LockdownPfState) -> Option<String> {
    st.main_snapshot_captured
        .then(|| build_lockdown_restore_ruleset(&st.nat_snapshot, &st.main_snapshot))
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
fn enable_pf_capture_token(state_dir: &Path) -> Result<String, RoutingError> {
    let en = pfctl(&["-E"], None, FatalPhase::CoverEngage)?;
    let token = parse_enable_token(&String::from_utf8_lossy(&en.stderr))
        .or_else(|| parse_enable_token(&String::from_utf8_lossy(&en.stdout)))
        .ok_or_else(|| RoutingError::RouteSetup("pfctl -E returned no token".into()))?;
    dropped_tokens::minted(state_dir, &token);
    Ok(token)
}

/// `pfctl -X <token>`, once per token ([`dropped_tokens::drop_once`]).
fn real_drop_token<P: Phase>(state_dir: &Path, token: &str, phase: P) -> Result<(), RoutingError> {
    dropped_tokens::drop_once(state_dir, token, || {
        pfctl_status(pfctl(&["-X", token], None, phase), "pfctl -X")
    })
}

/// Which cover a [`Cover`] guard owns — selects its Drop disengage path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CoverKind {
    Transient,
    Lockdown,
}

/// pf-backed cover guard. Drop disengages per [`CoverKind`]: the transient
/// cover restores `/etc/pf.conf`; the lockdown cover restores the snapshot.
pub struct Cover {
    token: String,
    state_dir: std::path::PathBuf,
    kind: CoverKind,
}

impl Cover {
    /// Release this process's claim on the cover without disengaging it.
    ///
    /// macOS holds NO process-local OS resource here: `token` is the
    /// `pfctl -E` enable ticket, and `Drop`'s `pfctl -X <token>` releases pf's
    /// enable refcount rather than freeing anything owned by this process.
    /// Leaving pf enabled is precisely what detaching means, so skipping
    /// `Drop` is the whole operation — unlike Windows, which must close its
    /// FWPM engine handle here.
    pub(crate) fn detach(self) {
        std::mem::forget(self);
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
                error = %util::error_chain::error_chain(&e),
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
/// that also drags in `state_dir`/`owner` for methods it never calls.
pub(crate) trait CoverRulesetOps {
    /// `pfctl -f -` with `text` on stdin.
    fn load_ruleset(&mut self, text: &str) -> Result<(), RoutingError>;
    /// `pfctl -F states`: purge pf's state table, host-wide.
    fn flush_states(&mut self) -> Result<(), RoutingError>;
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
    /// Read `bridge-failclosed.json` as the engage's view of the record: the
    /// expectation every later write is a compare-and-set against.
    fn read_transient(&mut self) -> StateFile<state::FailClosedState>;
    /// Write `bridge-failclosed.json` iff it still reads as `expected`
    /// ([`state::swap`]). A record a release changed since is
    /// [`RoutingError::SupersededByRelease`], and nothing is written.
    fn save_transient(
        &mut self,
        expected: &StateFile<state::FailClosedState>,
        st: &state::FailClosedState,
    ) -> Result<(), RoutingError>;
    /// The commit check after the ruleset loads: `Ok` iff the record is still
    /// the live one naming `token`. A release is `SupersededByRelease`; a record
    /// that cannot be read is a failure, not a release.
    fn transient_commit_check(&mut self, token: &str) -> Result<(), RoutingError>;
    /// `pfctl -X <token>`: drop a pf enable refcount, once per token
    /// ([`dropped_tokens::drop_once`]).
    fn drop_token(&mut self, token: &str) -> Result<(), RoutingError>;
    /// The back-out: [`disengage_with`] for `token`. Whether the restore was
    /// confirmed.
    fn transient_restore(&mut self, token: &str) -> bool;
    /// Put this engage's record back after a restore that failed
    /// ([`state::reassert`]), so recovery has something to act on.
    fn reassert_transient(&mut self, token: &str);
}

/// Drop the token an engage's record write displaced. The write took the only
/// record that named it, so nobody else will: a leftover from a cover whose release
/// did not finish, or a salvaged token from an unusable file. A drop that fails
/// is logged and the refcount stays until pf is reset, as it did before the write.
fn drop_displaced(overwritten: Option<&str>, new: &str, drop_token: impl FnOnce(&str) -> Result<(), RoutingError>) {
    let Some(old) = overwritten.filter(|old| *old != new) else {
        return;
    };
    if let Err(e) = drop_token(old) {
        tracing::warn!(
            error = %util::error_chain::error_chain(&e),
            "pfctl -X failed for the token a new cover's record replaced; pf keeps that refcount until it is reset"
        );
    }
}

pub fn engage(
    server_ip: IpAddr,
    resolver_ip: Option<IpAddr>,
    state_dir: &Path,
    owner: Option<(u32, u32)>,
    watch: &ReleaseWatch,
) -> Result<Cover, RoutingError> {
    let token = engage_with(
        server_ip,
        resolver_ip,
        &mut RealEngageOps {
            state_dir,
            owner,
            watch,
        },
    )?;
    Ok(Cover {
        token,
        state_dir: state_dir.to_owned(),
        kind: CoverKind::Transient,
    })
}

/// `engage`'s sequencing over the [`EngageOps`] seam. Returns the pf enable
/// token the caller wraps in a [`Cover`].
fn engage_with(
    server_ip: IpAddr,
    resolver_ip: Option<IpAddr>,
    ops: &mut dyn EngageOps,
) -> Result<String, RoutingError> {
    // 0. The record as it reads at entry; the baseline for every compare-and-set below.
    let expected = ops.read_transient();

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
                error = %util::error_chain::error_chain(&e),
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
    //    ones `state::save` really has: an unwritable state dir, a full disk.
    //    NOT a failed chown — `save` chowns via `chown_if_some`, which logs
    //    and swallows, so it cannot fail this call. Without the unwind, pf
    //    stays enabled until reboot under an unreferenced token — a
    //    fail-CLOSED leak hiding behind a path whose traffic verdict is
    //    fail-open. The refcount is the ONLY thing stranded: `save` is
    //    tempfile + `persist`, and `persist` is both the sole writer of
    //    `bridge-failclosed.json` and the last fallible step, so a failed save
    //    leaves no partial file for a later sweep to act on.
    let st = state::FailClosedState {
        version: state::SCHEMA_VERSION,
        pf_token: token.clone(),
        pf_was_enabled: was_enabled,
        releasing: false,
    };
    // The record this overwrites may name a token nothing else will drop: a leftover
    // from a cover whose release did not finish. The engage takes it over.
    if let Err(e) = ops.save_transient(&expected, &st) {
        if let Err(xe) = ops.drop_token(&token) {
            tracing::warn!(error = %util::error_chain::error_chain(&xe), "pfctl -X failed unwinding a failed transient engage");
        }
        return Err(e);
    }
    drop_displaced(expected.pf_token(), &token, |old| ops.drop_token(old));

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
        back_out_transient(ops, &token);
        return Err(e);
    }

    // 5. Commit check: the record is no longer step 3's, so a release took it and
    //    its token; only the ruleset we just loaded is left to undo.
    if let Err(e) = ops.transient_commit_check(&token) {
        tracing::warn!(
            error = %e,
            "the transient cover's record is no longer this engage's; backing the engage out"
        );
        back_out_transient(ops, &token);
        return Err(e);
    }

    Ok(token)
}

/// Undo a transient engage: restore, which drops the token only if its own clear
/// removed the record, and, if the restore did not confirm, put the engage's
/// record back so a release that already finished (or is about to clear) cannot
/// leave a host re-blocked by this engage with nothing to recover it from.
fn back_out_transient(ops: &mut dyn EngageOps, token: &str) {
    if !ops.transient_restore(token) {
        ops.reassert_transient(token);
    }
}

impl Drop for Cover {
    fn drop(&mut self) {
        match self.kind {
            // A user-stop drop never has a standing cover being adopted.
            CoverKind::Transient => {
                disengage(Some(&self.token), &self.state_dir, false);
            }
            CoverKind::Lockdown => lockdown_disengage(&self.state_dir),
        }
    }
}

/// Restore the host and give up the transient cover's record and refcount.
/// When `adopting` is false it reloads the canonical `/etc/pf.conf`: the cover's
/// own block-all ruleset is still live, so the reload is what returns the host.
/// When a standing cover is being adopted the reload is skipped, because it
/// would wipe the standing lockdown ruleset (the live main ruleset) before
/// Adopt.
///
/// The token is dropped, and the record cleared, only once the restore is
/// confirmed: a failed (but not adopting) restore leaves both in place, so the
/// next sweep still sees a cover rather than a clean host over a block. The
/// record goes only after the token is dropped ([`settle`]), so a drop that
/// fails leaves it for the next sweep. Whether the restore was confirmed.
/// Shared by `Drop`, `recover_cover` and the transient engage's back-out.
fn disengage_with(token: Option<&str>, adopting: bool, ops: &mut dyn PfOps) -> bool {
    if adopting {
        tracing::info!("standing lockdown cover being adopted; skipping /etc/pf.conf reload during transient sweep");
    } else if let Err(e) = ops.reload_default() {
        tracing::warn!(error = %util::error_chain::error_chain(&e), "pf ruleset restore failed during cover disengage");
        tracing::warn!(
            "leaving failclosed-state file in place: the /etc/pf.conf restore did not confirm — clearing it              now would make the next sweep read a clean host while the block persists"
        );
        return false;
    }
    if let Err(e) = settle(
        ops,
        Record::Transient,
        token,
        false,
        DropFailure::Warn("pfctl -X failed during cover disengage"),
    ) {
        tracing::warn!(
            error = %util::error_chain::error_chain(&e),
            "the transient cover's token could not be settled during cover disengage; it is left for recovery"
        );
    }
    true
}

/// [`disengage_with`] over the real `pfctl` and record.
fn disengage(token: Option<&str>, state_dir: &Path, adopting: bool) -> bool {
    disengage_with(token, adopting, &mut RealPfOps { state_dir })
}

/// Seam over the one mutation [`recover_cover`] performs, so its trichotomy
/// over the persisted record is table-tested without shelling out to `pfctl`.
pub(crate) trait RecoverOps {
    /// [`disengage`]: restore the replacement ruleset, drop `token`'s pf enable
    /// refcount when one is on record, and clear the state file on a confirmed
    /// restore.
    fn restore(&mut self, token: Option<&str>, adopting: bool);
}

pub fn recover_cover(state_dir: &Path, adopting: bool) {
    recover_cover_with(
        state::load_presence(state_dir),
        adopting,
        &mut RealRecoverOps { state_dir },
    );
}

/// `recover_cover`'s trichotomy over [`StateFile`], with the mutation injected.
///
/// Reads [`state::load_presence`], NOT `state::load`: `load` collapses
/// `Unusable` into `None` alongside `Absent`, and for a SWEEP those two are
/// opposite facts. `Absent` is "no cover was ever engaged". `Unusable` is
/// Hole's own unreconciled record that one WAS engaged and never confirmed
/// released — a corrupt file, a truncated write, or a version skew (a rollback
/// across a bumped [`state::SCHEMA_VERSION`]). Collapsing it would leave a
/// crashed covered run's `block out all` on the host with the automatic sweep
/// declining to act, and only the manual `bridge unlock` left to escape — the
/// same conflation `release_all_with` already refuses to make.
fn recover_cover_with(file: StateFile<state::FailClosedState>, adopting: bool, ops: &mut dyn RecoverOps) {
    match file {
        StateFile::Absent => tracing::debug!("no failclosed-state file, nothing to recover"),
        StateFile::Present(st) => {
            tracing::info!(
                was_enabled = ?st.pf_was_enabled,
                "recovering fail-closed cover from crashed run"
            );
            ops.restore(Some(&st.pf_token), adopting);
        }
        StateFile::Unusable { pf_token } => {
            tracing::warn!(
                token_salvaged = pf_token.is_some(),
                "failclosed-state file is unusable; recovering the cover anyway — an unreadable \
                 record is not evidence there is no cover to clear"
            );
            ops.restore(pf_token.as_deref(), adopting);
        }
    }
}

/// Production [`RecoverOps`]: the real [`disengage`].
struct RealRecoverOps<'a> {
    state_dir: &'a Path,
}

impl RecoverOps for RealRecoverOps<'_> {
    fn restore(&mut self, token: Option<&str>, adopting: bool) {
        disengage(token, self.state_dir, adopting);
    }
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
/// The presence probe leads: if OUR OWN cover is already the loaded ruleset,
/// `pfctl -sr` would hand back our block-all as if it were the host's policy.
/// Detection asks [`lockdown_cover_presence`] rather than parsing rule text, so
/// it depends on no claim about `pfctl -sr`'s print format.
fn capture_and_persist(
    token: &str,
    site: RecordSite<'_>,
    expected: &StateFile<lockdown_state::LockdownPfState>,
) -> Result<lockdown_state::LockdownPfState, RoutingError> {
    let presence = lockdown_cover_presence(site.state_dir);
    let main_snapshot = pfctl_stdout(pfctl(&["-sr"], None, FatalPhase::CoverEngage), "pfctl -sr")?;
    let nat_snapshot = pfctl_stdout(pfctl(&["-sn"], None, FatalPhase::CoverEngage), "pfctl -sn")?;
    persist_baseline(token, site, expected, presence, main_snapshot, nat_snapshot)
}

/// Where an engage writes its records, as whom, and the watch that ends its right
/// to: a write is refused ([`RoutingError::SupersededByRelease`]) once a release has
/// begun since the watch opened.
#[derive(Clone, Copy)]
pub(crate) struct RecordSite<'a> {
    pub state_dir: &'a Path,
    pub owner: Option<(u32, u32)>,
    pub watch: &'a ReleaseWatch,
}

/// Persist the engage-time baseline. Pure over its inputs — the snapshots and
/// the measured `presence` come from the caller — so the self-capture guard is
/// table-tested without touching pf. Returns the record it wrote: the engage
/// takes its ruleset's nat rules from it and keeps it as the baseline to restore.
///
/// When `presence` is [`CoverPresence::Live`](crate::routing::CoverPresence::Live)
/// this does exactly three things differently: it persists `main_snapshot`
/// empty, it persists `main_snapshot_captured: false`, and it warns. It
/// persists `nat_snapshot` exactly as `pfctl -sn` returned it and returns it in
/// the record — those are the HOST's translation rules, carried forward
/// verbatim into the ruleset engage loads, so zeroing them would flush a live
/// host NAT the moment the cover engages, with nothing on disk to restore from.
///
/// The write is a compare-and-set against `expected`, the record as the engage
/// read it at entry, and it is refused once a release has begun: a release that
/// cleared, replaced or claimed it since makes this
/// [`RoutingError::SupersededByRelease`] with nothing written, never a baseline
/// stacked on a host the release already restored.
fn persist_baseline(
    token: &str,
    site: RecordSite<'_>,
    expected: &StateFile<lockdown_state::LockdownPfState>,
    presence: crate::routing::CoverPresence,
    main_snapshot: String,
    nat_snapshot: String,
) -> Result<lockdown_state::LockdownPfState, RoutingError> {
    let captured = presence != crate::routing::CoverPresence::Live;
    if !captured {
        tracing::warn!(
            "a lockdown cover is already loaded, so there is no pre-lockdown host ruleset to capture; \
             recording no baseline (a restore will reload /etc/pf.conf)"
        );
    }
    let record = lockdown_state::LockdownPfState {
        version: lockdown_state::SCHEMA_VERSION,
        pf_token: token.to_owned(),
        main_snapshot: if captured { main_snapshot } else { String::new() },
        nat_snapshot,
        main_snapshot_captured: captured,
        releasing: false,
    };
    swap_lockdown_record(site, expected, &record)?;
    Ok(record)
}

/// [`lockdown_state::swap`], with its two failures as the [`RoutingError`]s an
/// engage reports: a lost compare is [`RoutingError::SupersededByRelease`], a
/// failed write is a state-write failure.
fn swap_lockdown_record(
    site: RecordSite<'_>,
    expected: &StateFile<lockdown_state::LockdownPfState>,
    new: &lockdown_state::LockdownPfState,
) -> Result<(), RoutingError> {
    match lockdown_state::swap(site.state_dir, expected, new, site.owner, site.watch) {
        Ok(Swap::Applied) => Ok(()),
        Ok(Swap::Superseded) => Err(RoutingError::SupersededByRelease),
        Err(e) => Err(RoutingError::state_write_failed("lockdown-pf-state", &e)),
    }
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
/// On load failure the host is restored (`back_out_engage`) and Err returned;
/// the bridge's fail-FATAL caller aborts the start.
pub fn engage_lockdown(
    server_ip: IpAddr,
    tun_name: &str,
    state_dir: &Path,
    owner: Option<(u32, u32)>,
    watch: &super::release_epoch::ReleaseWatch,
) -> Result<Cover, RoutingError> {
    let token = engage_lockdown_with(
        server_ip,
        tun_name,
        &mut RealLockdownEngageOps {
            state_dir,
            owner,
            watch,
        },
    )?;
    Ok(Cover {
        token,
        state_dir: state_dir.to_owned(),
        kind: CoverKind::Lockdown,
    })
}

/// Seam over the pf and record mutations a lockdown engage performs, so the
/// sequence (including a release landing between any two steps) is drivable
/// without `pfctl`. As with [`PfOps`], the production implementation folds a
/// non-success `pfctl` exit status into `Err`.
pub(crate) trait LockdownEngageOps: CoverRulesetOps {
    /// `pfctl -s info`, parsed: is pf currently enabled?
    fn pf_enabled(&mut self) -> Result<bool, RoutingError>;
    /// `bridge-lockdown-pf.json` as it reads now: the engage's view at entry,
    /// which every later write is a compare-and-set against.
    fn read_record(&mut self) -> StateFile<lockdown_state::LockdownPfState>;
    /// `pfctl -E` (refcounted enable) + capture the enable token.
    fn enable_capture_token(&mut self) -> Result<String, RoutingError>;
    /// Snapshot the host's filter and translation rules and persist them with
    /// `token`, as a compare-and-set against `expected`. Returns the record
    /// written: the engage's baseline.
    fn capture_and_persist(
        &mut self,
        token: &str,
        expected: &StateFile<lockdown_state::LockdownPfState>,
    ) -> Result<lockdown_state::LockdownPfState, RoutingError>;
    /// Persist `fresh` (the same baseline under a fresh token) as a
    /// compare-and-set against `expected`.
    fn persist(
        &mut self,
        expected: &StateFile<lockdown_state::LockdownPfState>,
        fresh: &lockdown_state::LockdownPfState,
    ) -> Result<(), RoutingError>;
    /// `pfctl -X <token>`: drop a pf enable refcount, once per token
    /// ([`dropped_tokens::drop_once`]).
    fn drop_token(&mut self, token: &str) -> Result<(), RoutingError>;
    /// The commit check after the ruleset loads: `Ok` iff the record is still the
    /// live one naming `token`. A release is `SupersededByRelease`; a record that
    /// cannot be read is a failure, not a release.
    fn commit_check(&mut self, token: &str) -> Result<(), RoutingError>;
    /// Delete the record naming `token`, whatever has become of it since the
    /// engage's check: its refcount is gone, so no record may name it.
    fn clear_dropped(&mut self, token: &str) -> Result<(), RoutingError>;
    /// Put `baseline`'s record back after a restore that failed
    /// ([`lockdown_state::reassert`]). Whether it did.
    fn reassert(&mut self, baseline: &lockdown_state::LockdownPfState) -> Result<bool, RoutingError>;
    /// `pfctl -f /etc/pf.conf`.
    fn reload_default(&mut self) -> Result<(), RoutingError>;
}

/// Drop the refcount an engage took when the engage itself is backing out.
fn unwind_refcount(ops: &mut dyn LockdownEngageOps, token: &str, message: &str) {
    if let Err(e) = ops.drop_token(token) {
        tracing::warn!(error = %util::error_chain::error_chain(&e), "{message}");
    }
}

/// Back a failed or superseded engage out: put the host back to `baseline`, the
/// baseline this engage itself holds, then give up what it still owns.
///
/// The baseline comes from memory because a release may have removed the record
/// that names it. The engage's refcount is dropped, whatever became of its record
/// (a token is dropped once however many parties ask: [`dropped_tokens`]), and
/// then every record naming it is cleared, a release's tombstone included: the
/// token is gone. A drop that fails leaves the record for recovery.
///
/// A restore that fails leaves a record behind for recovery: the engage's own, if
/// it is still there, and otherwise the engage's record put back over nothing or
/// over a release's tombstone. Best-effort otherwise; the caller is failing either
/// way.
fn back_out_engage(ops: &mut dyn LockdownEngageOps, token: &str, baseline: &lockdown_state::LockdownPfState) {
    let restored = match baseline_restore_ruleset(baseline) {
        Some(ruleset) => ops.load_ruleset(&ruleset),
        None => ops.reload_default(),
    };
    if let Err(e) = restored {
        tracing::warn!(
            error = %util::error_chain::error_chain(&e),
            "restoring the host baseline failed backing out a lockdown engage; keeping its record for recovery"
        );
        if let Err(e) = ops.reassert(baseline) {
            tracing::warn!(
                error = %util::error_chain::error_chain(&e),
                "putting the lockdown record back failed after a failed back-out; the block may have no record"
            );
        }
        return;
    }
    if let Err(e) = ops.drop_token(token) {
        tracing::warn!(
            error = %util::error_chain::error_chain(&e),
            "pfctl -X failed backing out a lockdown engage; its record is kept for recovery"
        );
        return;
    }
    if let Err(e) = ops.clear_dropped(token) {
        tracing::warn!(
            error = %util::error_chain::error_chain(&e),
            "clearing the lockdown record failed backing out an engage; it is left for recovery"
        );
    }
}

/// `engage_lockdown`'s sequence over the [`LockdownEngageOps`] seam. Returns the
/// pf enable token the caller wraps in a [`Cover`].
///
/// A release (`release_all_with`, `disengage_lockdown`) can run between any two
/// steps. Each record write is therefore a compare-and-set against the record
/// as it read at entry, and the final ruleset load is followed by a commit check
/// that the record is still the live one naming this engage's token. Either
/// failing is [`RoutingError::SupersededByRelease`]; the engage backs out
/// whatever it took ([`back_out_engage`]) and leaves the host as the release left it.
fn engage_lockdown_with(
    server_ip: IpAddr,
    tun_name: &str,
    ops: &mut dyn LockdownEngageOps,
) -> Result<String, RoutingError> {
    // The `pfctl -s info` read is decision-only — `LockdownPfState` records no
    // `pf_was_enabled` bit (unlike the transient `FailClosedState`).
    let pf_enabled = ops.pf_enabled()?;
    // The record as `load_presence` reads it, NOT `load`: `load` collapses an
    // `Unusable` file to `None`, which would make every compare-and-set below
    // expect an absent file over one that is there.
    let mut entry = ops.read_record();
    // A tombstone at entry is a release that failed to restore, and its cover is
    // adopted like any other: the first write takes the claim back. A release
    // that began since the facade's watch opened wrote it instead, and the write
    // is refused.
    if let Some(live) = pf_claim::unclaimed(&entry) {
        ops.persist(&entry, &live)?;
        entry = StateFile::Present(live);
    }
    let persisted = match &entry {
        StateFile::Present(st) => Some(st),
        StateFile::Absent | StateFile::Unusable { .. } => None,
    };

    let (token, baseline) = match (engage_pf_action(pf_enabled, persisted.is_some()), persisted) {
        // Live Adopt re-engage within one boot: pf still enabled and we hold the
        // token+snapshot. Reuse both so the real host policy is preserved for the
        // eventual restore. ReuseToken assumes our refcount is still live (the
        // reboot case is `Reenable`); do not double `-E`. It writes nothing, so
        // the commit check below is its only protection against a release.
        (PfEngageAction::ReuseToken, Some(st)) => (st.pf_token.clone(), st.clone()),
        // Persisted state survived but pf was disabled (reboot reset pf and its
        // refcount). Enable afresh and re-persist the SAME host snapshot under the
        // fresh token — never re-snapshot the live lockdown ruleset. The single
        // `pfctl -X <fresh-token>` on disengage matches this single `-E`.
        (PfEngageAction::Reenable, Some(st)) => {
            let token = ops.enable_capture_token()?;
            let fresh = lockdown_state::LockdownPfState {
                version: lockdown_state::SCHEMA_VERSION,
                pf_token: token.clone(),
                main_snapshot: st.main_snapshot.clone(),
                nat_snapshot: st.nat_snapshot.clone(),
                // Carried, not re-asserted: this re-persists the SAME baseline
                // under a fresh token, so claiming a capture that never
                // happened would restore an empty pass-all ruleset.
                main_snapshot_captured: st.main_snapshot_captured,
                releasing: false,
            };
            if let Err(e) = ops.persist(&entry, &fresh) {
                unwind_refcount(ops, &token, "pfctl -X failed unwinding a failed lockdown re-enable");
                return Err(e);
            }
            drop_displaced(entry.pf_token(), &token, |old| ops.drop_token(old));
            (token, fresh)
        }
        // First engage: enable + snapshot the host.
        (PfEngageAction::FreshEnable, _) => {
            let token = ops.enable_capture_token()?;
            // The refcount is now held. Capture + persist may fail, so undo the
            // `-E` on any error before propagating — else the refcount leaks with
            // no state file to recover it from.
            match ops.capture_and_persist(&token, &entry) {
                Ok(baseline) => {
                    drop_displaced(entry.pf_token(), &token, |old| ops.drop_token(old));
                    (token, baseline)
                }
                Err(e) => {
                    unwind_refcount(ops, &token, "pfctl -X failed unwinding a failed lockdown engage");
                    return Err(e);
                }
            }
        }
        (PfEngageAction::ReuseToken | PfEngageAction::Reenable, None) => {
            unreachable!("engage_pf_action answers ReuseToken/Reenable only for a persisted record")
        }
    };

    let main = build_lockdown_main_ruleset(tun_name, server_ip, &baseline.nat_snapshot);
    // Through the shared loader, so this path's "no state purge" is
    // [`purges_state`]'s decision rather than the absence of a call here.
    if let Err(e) = load_cover_ruleset(CoverKind::Lockdown, &main, ops) {
        // Restore the host before failing, so a partially-loaded ruleset never
        // strands the host.
        back_out_engage(ops, &token, &baseline);
        return Err(e);
    }

    // Commit check: a release that removed or claimed the record restored the
    // host, which the load above re-blocked.
    if let Err(e) = ops.commit_check(&token) {
        tracing::warn!(
            error = %e,
            "the standing cover's record is no longer this engage's; backing the engage out"
        );
        back_out_engage(ops, &token, &baseline);
        return Err(e);
    }

    Ok(token)
}

/// Fail-loud disengage: restore the pre-lockdown ruleset from the snapshot, drop
/// our pf refcount, clear the state. Powers the `bridge unlock` escape hatch.
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
/// rather than reading "disengaged" while the block persists.
///
/// Caveat: pf exposes no dump of prior `set` options, so the restore reloads the
/// host's filter+nat rules under pf defaults (same class of limitation the
/// transient cover documents for its `/etc/pf.conf` reload).
/// The clearance is unconditionally [`Clearance::proven`], for the reason
/// [`release_all`] gives: pf has no boot-time analogue — a ruleset does not
/// survive a reboot at all — so every macOS cover key is
/// [`super::KeyLifetime::Persistent`] and a disengage has nothing to leave
/// unproven.
pub fn disengage_lockdown(state_dir: &Path, _witness: super::ArmingWitness) -> SweepOutcome {
    // `Clearance::proven` on both arms: this platform has no boot-time key
    // class, so a macOS disengage carries nothing for the record to learn
    // from whether it succeeded or failed. The failing arm's clearance is
    // dropped by `sweep_with_witness` in any case — only its
    // `witness_update` is read, and that is `Leave` here.
    //
    // Presence and the record come from ONE read
    // ([`disengage_lockdown_over`]), and the record is passed on as a
    // `StateFile` rather than through `lockdown_state::load`: collapsing
    // `Unusable` to `None` here would hide the salvaged `pf_token` that
    // [`disengage_lockdown_with`] hands `pfctl -X`.
    match disengage_lockdown_over(&mut RealPfOps { state_dir }) {
        Ok(()) => SweepOutcome::completed(Clearance::proven()),
        Err(e) => SweepOutcome::failed(Clearance::proven(), e),
    }
}

/// `disengage_lockdown`'s whole sequence over a [`PfOps`]: pf's label answer,
/// then the claim on the record, then [`disengage_lockdown_with`]. The claim
/// leads every restore, and a presence that could not be established implies an
/// absent record, so nothing is claimed that the disengage then refuses to release.
fn disengage_lockdown_over(ops: &mut dyn PfOps) -> Result<(), RoutingError> {
    let pf_label = ops.lockdown_label();
    let file = ops.claim_standing();
    disengage_lockdown_with(fold_presence(pf_label, &file), file, ops)
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

    // No captured baseline (or no state at all — presence was established by
    // pf's label alone) means there is no snapshot to restore from, so
    // `/etc/pf.conf` IS the restore target — see
    // `LockdownPfState::main_snapshot_captured`.
    let restore = match &st {
        StateFile::Present(st) => baseline_restore_ruleset(st),
        _ => None,
    };
    match restore {
        Some(ruleset) => ops.load_ruleset(&ruleset)?,
        None => ops.reload_default()?,
    }

    // The record settled by this disengage: a tombstone this release claimed, or
    // an unclaimed one (unusable, or a claim that could not be written). An
    // UNUSABLE record still names a token the escape must release. Fail-loud, per
    // this function's contract and unlike `release_all_with`'s warn-only twin: a
    // caller who asked to be let out is told if the refcount could not be
    // released, and the record stays for the retry.
    let (token, claimed) = match &st {
        StateFile::Absent => (None, false),
        StateFile::Present(st) => (Some(st.pf_token.as_str()), st.releasing),
        StateFile::Unusable { pf_token } => (pf_token.as_deref(), false),
    };
    settle(ops, Record::Standing, token, claimed, DropFailure::Propagate)
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
        (_, StateFile::Present(_) | StateFile::Unusable { .. }) => CoverPresence::Recorded,
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
/// ([`disengage_lockdown_over`] reads the same two, claiming the record as it goes.)
fn lockdown_presence_and_state(
    state_dir: &Path,
) -> (
    crate::routing::CoverPresence,
    StateFile<lockdown_state::LockdownPfState>,
) {
    let pf_label = pf_label_answer(pfctl(&["-s", "labels"], None, BestEffortPhase::RecoverCover));
    let file = lockdown_state::load_presence(state_dir);
    (fold_presence(pf_label, &file), file)
}

/// Best-effort wrapper for `Drop` (user-stop): disengage and swallow. Drop has
/// no caller to surface an error to.
fn lockdown_disengage(state_dir: &Path) {
    // `Unset`: this platform arms no boot-time key
    // ([`STANDING_COVER_ARMS_BOOT_TIME`]), so there is never a record to
    // consult and the argument is inert.
    match disengage_lockdown(state_dir, super::ArmingWitness::Unset).into_result() {
        // Always `Clearance::proven` on macOS, and `Drop` has no reader for
        // it either way.
        Ok(_clearance_is_unconditional_here) => {}
        Err(e) => tracing::warn!(error = %util::error_chain::error_chain(&e), "lockdown disengage failed during Drop"),
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
    /// `pfctl -X <token>`: drop a pf enable refcount, once per token
    /// ([`dropped_tokens::drop_once`]). What a failure does is the caller's choice
    /// ([`DropFailure`]); no caller may discard it unlogged.
    fn drop_token(&mut self, token: &str) -> Result<(), RoutingError>;
    /// Clear the transient cover's record that a release (or a disengage) settled
    /// under `token`. `claimed` says whether the caller holds the record's
    /// tombstone: it then clears only that ([`state::clear_released`]); otherwise
    /// any record naming `token` ([`state::clear_if_token`]). What it found is a
    /// [`Cleared`]: a record that is not the caller's is left alone.
    fn clear_transient(&mut self, token: Option<&str>, claimed: bool) -> Result<Cleared, RoutingError>;
    /// The same for the standing lockdown cover's record.
    fn clear_standing(&mut self, token: Option<&str>, claimed: bool) -> Result<Cleared, RoutingError>;
    /// What clearing `record` under `token` would find, without clearing it
    /// ([`pf_claim::would_clear`]).
    fn peek(&mut self, record: Record, token: Option<&str>, claimed: bool) -> Cleared;
    /// Claim the transient record for a release ([`state::claim_for_release`]).
    fn claim_transient(&mut self) -> StateFile<state::FailClosedState>;
    /// The same for the standing record ([`lockdown_state::claim_for_release`]).
    fn claim_standing(&mut self) -> StateFile<lockdown_state::LockdownPfState>;
    /// `pfctl -s labels`, folded: does pf say our lockdown rule label is loaded
    /// ([`pf_label_answer`])?
    fn lockdown_label(&mut self) -> Option<bool>;
}

/// The disclosure for an unusable record that yielded no token at all — the
/// one case where nothing can be done about the refcount. Shared by
/// [`settle`] and by the log lines of the sweeps, so the two do not drift into
/// disclosing the same leak differently.
fn warn_unsalvageable_token(what: &str) {
    tracing::warn!(
        "{what} file is unusable and no pf token could be read out of it — a pf enable refcount \
         may be leaked (pf then stays enabled over the canonical /etc/pf.conf, which blocks \
         nothing, and a reboot resets it)"
    );
}

impl Record {
    fn what(self) -> &'static str {
        match self {
            Record::Transient => "transient failclosed-state",
            Record::Standing => "standing lockdown-pf-state",
        }
    }

    fn clear(self, ops: &mut dyn PfOps, token: Option<&str>, claimed: bool) -> Result<Cleared, RoutingError> {
        match self {
            Record::Transient => ops.clear_transient(token, claimed),
            Record::Standing => ops.clear_standing(token, claimed),
        }
    }
}

/// What a failed `pfctl -X` does to the [`settle`] that issued it. The record
/// stays either way, for a retry; the callers differ in what they report.
enum DropFailure {
    /// Log it under this message and report success: the host is restored, and
    /// a refcount that would not drop is for the next sweep.
    Warn(&'static str),
    /// Report it: a caller who asked to be let out is told the refcount could not
    /// be released.
    Propagate,
}

/// Settle a cover's pf enable token once its host is restored: drop the
/// refcount, then clear the record that names it, in that order, so a drop that
/// fails leaves the record for a retry.
///
/// The token is dropped whatever the record reads now: a token is dropped once
/// however many parties ask ([`dropped_tokens`]), so a record that was replaced or
/// removed by someone who did not drop it cannot strand the refcount, and one that
/// was is no cause to drop it twice. The one record not cleared is a live record
/// standing where a claimed one was (an engage re-asserted it): that is not the
/// caller's, and it is an error, never a false success.
fn settle(
    ops: &mut dyn PfOps,
    record: Record,
    token: Option<&str>,
    claimed: bool,
    on_drop_failure: DropFailure,
) -> Result<(), RoutingError> {
    let Some(token) = token else {
        // An unusable file that named no token: nothing to drop, only a file to clear.
        return match record.clear(ops, None, claimed) {
            Ok(Cleared::Removed) => {
                warn_unsalvageable_token(record.what());
                Ok(())
            }
            Ok(cleared) => cleared.refusal().map_or(Ok(()), Err),
            Err(e) => {
                tracing::warn!(
                    error = %util::error_chain::error_chain(&e),
                    "{} clear failed after its restore; it is left for recovery",
                    record.what()
                );
                Ok(())
            }
        };
    };
    if let replaced @ Cleared::Replaced = ops.peek(record, Some(token), claimed) {
        return replaced.refusal().map_or(Ok(()), Err);
    }
    if let Err(e) = ops.drop_token(token) {
        return match on_drop_failure {
            DropFailure::Warn(message) => {
                tracing::warn!(error = %util::error_chain::error_chain(&e), "{message}");
                Ok(())
            }
            DropFailure::Propagate => Err(e),
        };
    }
    match record.clear(ops, Some(token), claimed) {
        Ok(cleared) => cleared.refusal().map_or(Ok(()), Err),
        Err(e) => {
            tracing::warn!(
                error = %util::error_chain::error_chain(&e),
                "{} clear failed after its token was dropped; it is left for recovery",
                record.what()
            );
            Ok(())
        }
    }
}

/// What a release does once a cover's restore has been attempted: nothing, if the
/// restore failed (the record, a tombstone when claimed, and the token stay for
/// recovery); otherwise [`settle`] the token.
fn finish_release(
    ops: &mut dyn PfOps,
    record: Record,
    token: Option<&str>,
    claimed: bool,
    restored: Result<(), RoutingError>,
) -> Result<(), RoutingError> {
    restored?;
    let message = match record {
        Record::Transient => "pfctl -X failed releasing the transient cover's pf refcount during release_all",
        Record::Standing => "pfctl -X failed releasing the standing cover's pf refcount during release_all",
    };
    settle(ops, record, token, claimed, DropFailure::Warn(message))
}

/// The unconditional two-cover clear, factored as a pure sequencer over an
/// injected [`PfOps`] so it is table-tested without touching pf. See
/// `failclosed::release_all`'s doc for the contract this implements.
///
/// The records arrive claimed ([`release_all_over`]): a `releasing` record is a
/// tombstone this release owns the clear of. Each cover is restored, then
/// cleared, then its token dropped by whichever clear removed the record.
///
/// One `first_err` accumulator, two blocks, no `?` — a `?` would short-circuit
/// the block that had not run yet.
pub(crate) fn release_all_with(
    transient: StateFile<state::FailClosedState>,
    standing: StateFile<lockdown_state::LockdownPfState>,
    ops: &mut dyn PfOps,
) -> Result<(), RoutingError> {
    let mut first_err: Option<RoutingError> = None;

    // Block 1 — transient cover. A reload failure is recorded but does NOT
    // stop block 2: the standing cover is the one that blocks indefinitely
    // and must be attempted regardless.
    let settled = match transient {
        StateFile::Absent => Ok(()),
        StateFile::Present(st) => {
            let restored = ops.reload_default();
            finish_release(ops, Record::Transient, Some(&st.pf_token), st.releasing, restored)
        }
        StateFile::Unusable { pf_token } => {
            let restored = ops.reload_default();
            finish_release(ops, Record::Transient, pf_token.as_deref(), false, restored)
        }
    };
    first_err = first_err.or(settled.err());

    // Block 2 — standing cover.
    let settled = match standing {
        StateFile::Absent => Ok(()),
        StateFile::Present(st) if !st.main_snapshot_captured => {
            // No baseline was captured, so there is no snapshot to load — see
            // `LockdownPfState::main_snapshot_captured`. Loading the empty one
            // would leave a pass-all host.
            let restored = ops.reload_default();
            finish_release(ops, Record::Standing, Some(&st.pf_token), st.releasing, restored)
        }
        StateFile::Present(st) => {
            let restore = build_lockdown_restore_ruleset(&st.nat_snapshot, &st.main_snapshot);
            let restored = match ops.load_ruleset(&restore) {
                Ok(()) => Ok(()),
                Err(snapshot_err) => match ops.reload_default() {
                    Ok(()) => {
                        tracing::warn!(
                            error = %util::error_chain::error_chain(&snapshot_err),
                            "captured pf snapshot could not load; fell back to the default ruleset — \
                             the host's captured pf rules could not be restored"
                        );
                        Ok(())
                    }
                    Err(fallback_err) => Err(RoutingError::RouteSetup(format!(
                        "snapshot restore failed ({snapshot_err}); default-ruleset fallback also failed \
                         ({fallback_err})"
                    ))),
                },
            };
            finish_release(ops, Record::Standing, Some(&st.pf_token), st.releasing, restored)
        }
        StateFile::Unusable { pf_token } => {
            tracing::warn!(
                "standing lockdown-pf-state file is unusable; no snapshot to restore, falling back to \
                 the default ruleset"
            );
            let restored = ops.reload_default();
            finish_release(ops, Record::Standing, pf_token.as_deref(), false, restored)
        }
    };
    first_err = first_err.or(settled.err());

    match first_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// `release_all`'s whole sequence over a [`PfOps`]: claim each record (before any
/// pf call), then settle them with [`release_all_with`].
fn release_all_over(ops: &mut dyn PfOps) -> Result<(), RoutingError> {
    let transient = ops.claim_transient();
    let standing = ops.claim_standing();
    release_all_with(transient, standing, ops)
}

/// A release's clear of the transient record: its own tombstone when it holds a
/// claim, any record naming the token when it does not.
fn clear_transient_record(state_dir: &Path, token: Option<&str>, claimed: bool) -> Result<Cleared, RoutingError> {
    let cleared = if claimed {
        state::clear_released(state_dir, token)
    } else {
        state::clear_if_token(state_dir, token).map(removed_or_gone)
    };
    cleared.map_err(|e| RoutingError::RouteSetup(format!("failclosed-state clear failed: {e}")))
}

/// The same for the standing record.
fn clear_standing_record(state_dir: &Path, token: Option<&str>, claimed: bool) -> Result<Cleared, RoutingError> {
    let cleared = if claimed {
        lockdown_state::clear_released(state_dir, token)
    } else {
        lockdown_state::clear_if_token(state_dir, token).map(removed_or_gone)
    };
    cleared.map_err(|e| RoutingError::RouteSetup(format!("lockdown-pf-state clear failed: {e}")))
}

/// What a clear of `record` under `token` would find, read from the file as it
/// stands.
fn peek_record(state_dir: &Path, record: Record, token: Option<&str>, claimed: bool) -> Cleared {
    match record {
        Record::Transient => pf_claim::would_clear(&state::load_presence(state_dir), token, claimed),
        Record::Standing => pf_claim::would_clear(&lockdown_state::load_presence(state_dir), token, claimed),
    }
}

/// An unclaimed clear cannot tell a re-asserted record from a vanished one, so a
/// record it did not remove is simply not its to drop the token of.
fn removed_or_gone(removed: bool) -> Cleared {
    if removed {
        Cleared::Removed
    } else {
        Cleared::Gone
    }
}

/// Production [`PfOps`]: maps each method onto the existing `pfctl` helper,
/// converting a non-success exit status into `Err`.
struct RealPfOps<'a> {
    state_dir: &'a Path,
}

/// Production [`EngageOps`]: the same mapping for the engage layer, one
/// [`FatalPhase::CoverEngage`] throughout — an engage is fail-fatal in both
/// covers, unlike [`RealPfOps`]'s best-effort recovery phase.
struct RealEngageOps<'a> {
    state_dir: &'a Path,
    owner: Option<(u32, u32)>,
    /// Opened by the facade before this engage began.
    watch: &'a ReleaseWatch,
}

/// `pfctl -f -` with `text` on stdin, one [`FatalPhase::CoverEngage`]
/// implementation shared by [`RealEngageOps`] and [`RealLockdownEngageOps`] so
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
}

impl EngageOps for RealEngageOps<'_> {
    fn pf_enabled(&mut self) -> Result<bool, RoutingError> {
        let info = pfctl_stdout(pfctl(&["-s", "info"], None, FatalPhase::CoverEngage), "pfctl -s info")?;
        Ok(parse_pf_enabled(&info))
    }

    fn enable_capture_token(&mut self) -> Result<String, RoutingError> {
        enable_pf_capture_token(self.state_dir)
    }

    fn read_transient(&mut self) -> StateFile<state::FailClosedState> {
        state::load_presence(self.state_dir)
    }

    fn save_transient(
        &mut self,
        expected: &StateFile<state::FailClosedState>,
        st: &state::FailClosedState,
    ) -> Result<(), RoutingError> {
        match state::swap(self.state_dir, expected, st, self.owner, self.watch) {
            Ok(Swap::Applied) => Ok(()),
            Ok(Swap::Superseded) => Err(RoutingError::SupersededByRelease),
            Err(e) => Err(RoutingError::state_write_failed("failclosed-state", &e)),
        }
    }

    fn transient_commit_check(&mut self, token: &str) -> Result<(), RoutingError> {
        match state::holds(self.state_dir, token).refusal("transient") {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn drop_token(&mut self, token: &str) -> Result<(), RoutingError> {
        real_drop_token(self.state_dir, token, FatalPhase::CoverEngage)
    }

    fn transient_restore(&mut self, token: &str) -> bool {
        disengage(Some(token), self.state_dir, false)
    }

    fn reassert_transient(&mut self, token: &str) {
        // `pf_was_enabled` is diagnostic only (see its doc) and is not known here.
        let record = state::FailClosedState {
            version: state::SCHEMA_VERSION,
            pf_token: token.to_owned(),
            pf_was_enabled: false,
            releasing: false,
        };
        match state::reassert(self.state_dir, &record, self.owner) {
            Ok(_) => {}
            Err(e) => tracing::warn!(
                error = %util::error_chain::error_chain(&e),
                "putting the transient record back failed after a failed back-out; the block may have no record"
            ),
        }
    }
}

/// Production [`LockdownEngageOps`]: the lockdown engage's pf and record
/// mutations, one [`FatalPhase::CoverEngage`] throughout.
struct RealLockdownEngageOps<'a> {
    state_dir: &'a Path,
    owner: Option<(u32, u32)>,
    /// Opened by the facade before this engage began.
    watch: &'a super::release_epoch::ReleaseWatch,
}

impl RealLockdownEngageOps<'_> {
    fn site(&self) -> RecordSite<'_> {
        RecordSite {
            state_dir: self.state_dir,
            owner: self.owner,
            watch: self.watch,
        }
    }
}

impl CoverRulesetOps for RealLockdownEngageOps<'_> {
    fn load_ruleset(&mut self, text: &str) -> Result<(), RoutingError> {
        real_load_ruleset(text)
    }

    fn flush_states(&mut self) -> Result<(), RoutingError> {
        real_flush_states()
    }
}

impl LockdownEngageOps for RealLockdownEngageOps<'_> {
    fn pf_enabled(&mut self) -> Result<bool, RoutingError> {
        let info = pfctl_stdout(pfctl(&["-s", "info"], None, FatalPhase::CoverEngage), "pfctl -s info")?;
        Ok(parse_pf_enabled(&info))
    }

    fn read_record(&mut self) -> StateFile<lockdown_state::LockdownPfState> {
        lockdown_state::load_presence(self.state_dir)
    }

    fn enable_capture_token(&mut self) -> Result<String, RoutingError> {
        enable_pf_capture_token(self.state_dir)
    }

    fn capture_and_persist(
        &mut self,
        token: &str,
        expected: &StateFile<lockdown_state::LockdownPfState>,
    ) -> Result<lockdown_state::LockdownPfState, RoutingError> {
        capture_and_persist(token, self.site(), expected)
    }

    fn persist(
        &mut self,
        expected: &StateFile<lockdown_state::LockdownPfState>,
        fresh: &lockdown_state::LockdownPfState,
    ) -> Result<(), RoutingError> {
        swap_lockdown_record(self.site(), expected, fresh)
    }

    fn drop_token(&mut self, token: &str) -> Result<(), RoutingError> {
        real_drop_token(self.state_dir, token, FatalPhase::CoverEngage)
    }

    fn commit_check(&mut self, token: &str) -> Result<(), RoutingError> {
        match lockdown_state::holds(self.state_dir, token).refusal("standing") {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn clear_dropped(&mut self, token: &str) -> Result<(), RoutingError> {
        lockdown_state::clear_if_token(self.state_dir, Some(token))
            .map(|_removed| ())
            .map_err(|e| RoutingError::RouteSetup(format!("lockdown-pf-state clear failed: {e}")))
    }

    fn reassert(&mut self, baseline: &lockdown_state::LockdownPfState) -> Result<bool, RoutingError> {
        lockdown_state::reassert(self.state_dir, baseline, self.owner)
            .map_err(|e| RoutingError::RouteSetup(format!("lockdown-pf-state write failed: {e}")))
    }

    fn reload_default(&mut self) -> Result<(), RoutingError> {
        pfctl_status(
            pfctl(&["-f", PFCONF], None, FatalPhase::CoverEngage),
            "pf default-ruleset reload",
        )
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
        real_drop_token(self.state_dir, token, BestEffortPhase::RecoverCover)
    }

    fn clear_transient(&mut self, token: Option<&str>, claimed: bool) -> Result<Cleared, RoutingError> {
        clear_transient_record(self.state_dir, token, claimed)
    }

    fn clear_standing(&mut self, token: Option<&str>, claimed: bool) -> Result<Cleared, RoutingError> {
        clear_standing_record(self.state_dir, token, claimed)
    }

    fn peek(&mut self, record: Record, token: Option<&str>, claimed: bool) -> Cleared {
        peek_record(self.state_dir, record, token, claimed)
    }

    fn claim_transient(&mut self) -> StateFile<state::FailClosedState> {
        state::claim_for_release(self.state_dir, None)
    }

    fn claim_standing(&mut self) -> StateFile<lockdown_state::LockdownPfState> {
        lockdown_state::claim_for_release(self.state_dir, None)
    }

    fn lockdown_label(&mut self) -> Option<bool> {
        pf_label_answer(pfctl(&["-s", "labels"], None, BestEffortPhase::RecoverCover))
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
pub fn release_all(state_dir: &Path, _witness: super::ArmingWitness) -> SweepOutcome {
    // Both arms `Clearance::proven`, for the reason `disengage_lockdown`
    // gives: no boot-time key class here, so nothing a failure could have
    // observed and withheld.
    match release_all_over(&mut RealPfOps { state_dir }) {
        Ok(()) => SweepOutcome::completed(Clearance::proven()),
        Err(e) => SweepOutcome::failed(Clearance::proven(), e),
    }
}

#[cfg(test)]
#[path = "macos_tests.rs"]
mod macos_tests;

/// A release landing between the steps of an engage. A descendant of this module
/// because it drives private sequencers.
#[cfg(test)]
#[path = "macos_release_race_tests.rs"]
mod macos_release_race_tests;

/// Every interleaving of two cover parties over the pf records.
#[cfg(test)]
#[path = "macos_interleaving_tests.rs"]
mod macos_interleaving_tests;

/// Privileged-lane real-engage tests. A DESCENDANT of this module, not a
/// sibling of the other `*_privileged_tests.rs` files under `failclosed`,
/// because they reach for [`Cover`]'s private `token` field and the private
/// [`pfctl`] helper — and that is what descendance buys, not sharing a file
/// with [`macos_tests`].
#[cfg(all(test, target_os = "macos"))]
#[path = "macos_transition_tests.rs"]
mod macos_transition_tests;
