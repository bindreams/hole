//! macOS fail-closed cover via pf (`pfctl`). Two layers share the `Cover` guard:
//!
//! - **Transient cover** (`engage`/`disengage`): enables pf (refcounted,
//!   `pfctl -E`) and loads a self-contained ruleset (see `build_pf_ruleset`,
//!   via `pfctl -f -`, NO `-Fa`) blocking everything but loopback, the
//!   server, and the pinned resolver. Disengage restores the canonical
//!   `/etc/pf.conf` and drops the refcount. Dropping `-Fa` (bindreams/hole#997)
//!   is load-bearing: `-Fa` flushes ALL pf state as its own, separately
//!   committed kernel operation, so `-Fa -f -` was two transactions with a
//!   pass-all host briefly live between them — including across a cover
//!   TRANSITION (a second `engage` replacing a still-live one, with no
//!   intervening `disengage`). A bare `pfctl -f -` load is a single pf
//!   transaction FOR THE RULES (DIOCADDRULE stages into an inactive ruleset
//!   under a ticket, DIOCXCOMMIT swaps it in atomically under `pf_lock`), so
//!   the old ruleset stays authoritative right up until the new one is fully
//!   committed. The `set` lines are NOT in that ticket: `pfctl` applies
//!   `set block-policy` / `skip` / `limit` / `timeout` through their own
//!   immediate ioctls as it parses, outside `DIOCXBEGIN`/`DIOCXCOMMIT`. No
//!   hole opens either way — neither `block-policy drop` nor `skip on lo0` is
//!   a permit — but the atomicity claim covers the rules only.
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
//! Documented caveats (pf has no programmatic API — `pfctl` text I/O IS the
//! interface, as `netsh`/`route` are for routing):
//! - The transient restore reloads `/etc/pf.conf`; the lockdown restore reloads
//!   the captured snapshot. Neither can recover prior `set` options (pf exposes
//!   no dump of them), so both restore under pf defaults.
//! - The `pfctl -E` token is parsed from stderr — its only exposure.

use std::net::IpAddr;
use std::path::Path;

use super::super::{run_capturing, BestEffortPhase, FatalPhase, Phase};
use crate::error::RoutingError;
// `macos.rs` is mounted as `mod platform` under `failclosed`, so `super` is the
// `failclosed` module and `failclosed_state` is its sibling child.
use super::failclosed_state as state;
use super::lockdown_pf_state as lockdown_state;
use super::StateFile;
use super::RESOLVER_PERMIT_PORT;

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
/// Loopback is exempted with `set skip on lo0` — the same mechanism
/// [`build_lockdown_main_ruleset`] uses — and NOT with a `pass` rule, because
/// this cover is the one that purges pf state ([`purges_state`]). A `pass`
/// creates state under pf's default `flags S/SA`, so only a SYN matches it;
/// after the purge a mid-stream loopback segment of an ALREADY-ESTABLISHED
/// session matches no state, fails that SYN-only pass, and falls through to
/// `block out all` — silently discarded under `block-policy drop`. Every local
/// TCP session on the host (databases, dev servers, `ssh -L` forwards,
/// IDE↔language-server sockets) would die on every covered start and every
/// covered retry. `set skip` passes lo0 "as if pf was disabled", with no state
/// to lose.
pub fn build_pf_ruleset(server_ip: IpAddr, resolver_ip: Option<IpAddr>) -> String {
    let resolver_pass = resolver_ip
        .map(|ip| format!("pass out quick proto tcp from any to {ip} port {RESOLVER_PERMIT_PORT}\n"))
        .unwrap_or_default();
    format!(
        "set block-policy drop\n\
         set skip on lo0\n\
         block out all\n\
         pass out quick from any to {server_ip}\n\
         {resolver_pass}"
    )
}

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
/// The base rule's [`LOCKDOWN_PF_LABEL`] is **load-bearing**, not decoration:
/// it is the only evidence [`lockdown_cover_presence`] has that does not come
/// from `state_dir`. Dropping it returns macOS to file-only presence, which
/// cannot produce `Live` and therefore can neither repair an intent file nor
/// detect that we are about to snapshot our own cover as the host baseline.
pub fn build_lockdown_main_ruleset(tun_name: &str, server_ip: IpAddr, nat_snapshot: &str) -> String {
    let proto = "tcp"; // +udp once a UDP-transport plugin lands; egress is TCP-only today.
    format!(
        "set block-policy drop\n\
         set skip on lo0\n\
         {nat}\
         pass out quick proto {proto} from any to {ip}\n\
         pass out quick on {tun} all\n\
         block drop out quick inet6 all\n\
         block drop out quick all label \"{label}\"\n",
        nat = ensure_trailing_nl(nat_snapshot),
        proto = proto,
        ip = server_ip,
        tun = tun_name,
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
pub(crate) fn pf_label_answer(out: Result<std::process::Output, RoutingError>) -> Option<bool> {
    let out = out.ok()?;
    if !out.status.success() {
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

/// `pfctl`'s fixed system path. This runs as root — a bare `"pfctl"` would
/// resolve against the caller's `PATH`, letting an earlier, attacker-writable
/// directory on it shadow the real binary. `/sbin/pfctl` is where macOS ships
/// it, unconditionally.
///
/// NOT a closed hardening. Every other root spawn in the tree is still
/// PATH-resolved through `Command::new(&cmd[0])`: `routing.rs`'s bare
/// `"route"`, `device/ipv6_addr/macos.rs`'s `"ifconfig"`, and
/// `bridge/src/dns/system/macos.rs`'s `const NETWORKSETUP: &str =
/// "networksetup"`. A `--service` bridge inherits launchd's fixed `PATH`, but a
/// GUI-elevated one inherits the user's, `/opt/homebrew/bin` included. Pinning
/// this one call site is correct in itself and delivers no net attack-surface
/// reduction while the rest stand; widening it is tracked separately.
const PFCTL: &str = "/sbin/pfctl";

/// Build the argv `pfctl` runs with: [`PFCTL`]'s absolute path followed by
/// `args`. Pure so the hardening in [`PFCTL`]'s doc — the absolute path, not a
/// PATH-resolved bare `"pfctl"` — is unit-tested without spawning anything.
fn pfctl_cmd(args: &[&str]) -> Vec<String> {
    std::iter::once(PFCTL)
        .chain(args.iter().copied())
        .map(str::to_owned)
        .collect()
}

fn pfctl<P: Phase>(args: &[&str], stdin: Option<&[u8]>, phase: P) -> Result<std::process::Output, RoutingError> {
    let cmd = pfctl_cmd(args);
    run_capturing(&cmd, stdin, phase).map_err(|e| RoutingError::RouteSetup(format!("pfctl spawn failed: {e}")))
}

/// `pfctl -E` (refcounted enable) + parse the enable token from its output. The
/// token prints to stderr (or stdout on some hosts), so try both.
fn enable_pf_capture_token() -> Result<String, RoutingError> {
    let en = pfctl(&["-E"], None, FatalPhase::CoverEngage)?;
    parse_enable_token(&String::from_utf8_lossy(&en.stderr))
        .or_else(|| parse_enable_token(&String::from_utf8_lossy(&en.stdout)))
        .ok_or_else(|| RoutingError::RouteSetup("pfctl -E returned no token".into()))
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
/// expires at all. `-Fa` used to purge state as a side effect of flushing
/// everything; the bare `pfctl -f -` that replaced it (bindreams/hole#997)
/// does not (bindreams/hole#1015).
///
/// - [`CoverKind::Transient`] — **purge**. Reachable whenever pf was already
///   enabled ahead of us: Internet Sharing, another VPN, a hand-run
///   `pfctl -e`, or a cross-process transient engage over a still-live
///   standing ruleset left by an outgoing bridge's `CoverGuard::disarm`. There
///   is no tunnel of ours for it to kill — the transient cover is engaged in
///   `hold_pending`, *before* `start_inner`. The flush is nonetheless HOST-WIDE
///   (`DIOCCLRSTATES`, no `psk_ifname`/`psk_ownername`), so what protects the
///   traffic this cover means to PERMIT is not the flush's scope but the
///   ruleset's: loopback is exempted with `set skip on lo0` rather than a
///   state-bearing `pass` ([`build_pf_ruleset`]), so local sessions survive a
///   purge that a `pass` rule would have severed. Egress this cover permits by
///   IP (the server, the resolver) is a fresh connection after the engage, so
///   it re-creates its own state under the new ruleset.
/// - [`CoverKind::Lockdown`] — **do not purge** (bindreams/hole#1015's
///   remaining half, sequenced behind bindreams/hole#1002).
///   `engage_lockdown` runs with the tunnel LIVE, and `pfctl -F states` →
///   `DIOCCLRSTATES` is host-wide with neither `psk_ifname` nor
///   `psk_ownername` set: it would kill the very tunnel the kill switch
///   exists to protect. "Everything except the tunnel" needs
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
/// A failed purge is logged, not propagated. Engage failure is fatal to the
/// start and the transient path unwinds by reloading `/etc/pf.conf` — a fully
/// open host. A live cover whose purge did not land is the pre-existing
/// bindreams/hole#1015 residue; an open host is worse, so the purge never
/// promotes itself into an engage failure.
fn load_cover_ruleset<T: CoverRulesetOps + ?Sized>(
    kind: CoverKind,
    ruleset: &str,
    ops: &mut T,
) -> Result<(), RoutingError> {
    ops.load_ruleset(ruleset)?;
    if purges_state(kind) {
        if let Err(e) = ops.flush_states() {
            tracing::warn!(
                error = %e,
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
    /// Write `bridge-failclosed.json`.
    fn save_transient(&mut self, st: &state::FailClosedState) -> Result<(), RoutingError>;
    /// `pfctl -X <token>`: drop a pf enable refcount.
    fn drop_token(&mut self, token: &str) -> Result<(), RoutingError>;
    /// The transient cover's full restore, `disengage(token, .., false)`.
    fn transient_restore(&mut self, token: &str);
}

pub fn engage(
    server_ip: IpAddr,
    resolver_ip: Option<IpAddr>,
    state_dir: &Path,
    owner: Option<(u32, u32)>,
) -> Result<Cover, RoutingError> {
    let token = engage_with(server_ip, resolver_ip, &mut RealEngageOps { state_dir, owner })?;
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
    // 1. Read current enabled-state (read-only) — DIAGNOSTIC ONLY, so it is
    //    best-effort. `pf_was_enabled`'s single reader is a log field in
    //    `recover_cover`; nothing branches on it. Propagating a failure here
    //    would fail the cover OPEN — `install_failclosed_cover`'s caller logs
    //    "host NOT blocked, proceeding open" and starts the session uncovered —
    //    over a read that none of the cover-establishing steps below needs. A
    //    failure is recorded as `None`, not guessed at.
    let was_enabled = match ops.pf_enabled() {
        Ok(enabled) => Some(enabled),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "could not read whether pf was already enabled; recording it as unknown and \
                 continuing the engage — this read is diagnostic and the cover does not depend on it"
            );
            None
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
    };
    if let Err(e) = ops.save_transient(&st) {
        if let Err(xe) = ops.drop_token(&token) {
            tracing::warn!(error = %xe, "pfctl -X failed unwinding a failed transient engage");
        }
        return Err(e);
    }

    // 4. Load our self-contained blocking ruleset from stdin — NO `-Fa`
    //    (bindreams/hole#997): a bare `pfctl -f -` is one atomic pf
    //    transaction (see this module's doc), so whatever ruleset was already
    //    loaded (the host's own, or a still-live prior cover's) stays
    //    authoritative until this one fully commits. The state purge that
    //    follows it is [`purges_state`]'s call, not this site's.
    let ruleset = build_pf_ruleset(server_ip, resolver_ip);
    if let Err(e) = load_cover_ruleset(CoverKind::Transient, &ruleset, ops) {
        // A *failed engage* is the sole place this module fails OPEN on its own
        // error: we must not leave a half-loaded ruleset blocking traffic. A
        // failed `pfctl -f -` load never committed its RULES (the ticket
        // discipline that makes a successful load atomic also makes a failed
        // one a no-op on the live RULESET), so the host still filters under
        // whatever ruleset was loaded before this call. That is NOT the same
        // as "a no-op on the live config": everything `pfctl` does outside the
        // ticket lands even when the load then fails — the `set block-policy`/
        // `skip`/`limit`/`timeout` ioctls it issues as it parses (module doc),
        // and the interface skip flags it clears before parsing, which is why
        // `set skip` has to be restated by every ruleset. Each of those only
        // ever tightens — none is a permit — so no hole opens either way, but
        // the state is not byte-identical to the pre-call one. Restoring
        // `/etc/pf.conf` here does not "undo a
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
        // parameter today to tell "first engage" from "transition" apart.
        ops.transient_restore(&token);
        return Err(e);
    }

    Ok(token)
}

impl Drop for Cover {
    fn drop(&mut self) {
        match self.kind {
            // A user-stop drop never has a standing cover being adopted.
            CoverKind::Transient => disengage(&self.token, &self.state_dir, false),
            CoverKind::Lockdown => lockdown_disengage(&self.state_dir),
        }
    }
}

/// The single rule for "did the ruleset that replaces a cover actually load".
/// `true` when `adopting` — the reload is deliberately SKIPPED because a
/// standing cover is holding the host, so nothing was attempted and nothing
/// failed. Otherwise `out` must be `Ok` AND its exit status a success: a
/// spawn-result check alone is blind to `pfctl` failing on its exit status,
/// and that is exactly the case that would erase a cover's only evidence out
/// from under a still-blocking ruleset. Shared by `disengage` and
/// `release_all_with` so there is one answer to this question, not two that
/// can drift apart.
fn restore_confirmed(adopting: bool, out: &Result<std::process::Output, RoutingError>) -> bool {
    if adopting {
        return true;
    }
    matches!(out, Ok(o) if o.status.success())
}

/// Drop a pf enable refcount (`pfctl -X token`) best-effort: log-and-swallow
/// on failure rather than propagate, because every call site is already
/// mid-unwind or mid-teardown with its own outcome (an error, or none) to
/// return, and a refcount that fails to drop is a leak the caller has no
/// action left to take beyond logging it. Routed through [`pfctl_status`],
/// NOT a bare `pfctl(...)?`-then-discard: a spawn can succeed while `pfctl`
/// itself exits non-zero (e.g. an already-dropped or unknown token), and
/// reading only the spawn result treats that exit as a silent success — the
/// refcount then leaks with the log claiming nothing went wrong. `message` is
/// the call-site-specific warn text (kept distinct per caller rather than
/// generic, so a `-X` warn in the log still says which of `disengage` /
/// `engage_lockdown`'s two unwind arms it came from).
fn drop_refcount_or_warn<P: Phase>(token: &str, phase: P, message: &str) {
    if let Err(e) = pfctl_status(pfctl(&["-X", token], None, phase), "pfctl -X") {
        tracing::warn!(error = %e, "{message}");
    }
}

/// Drop the transient enable refcount + clear the file. When `adopting` is
/// false, also restore the canonical ruleset — the cover's own block-all
/// ruleset is still live (engage no longer flushes it away), so this reload
/// is what actually returns the host to `/etc/pf.conf` rather than leaving it
/// under our block. When a standing cover is being adopted, skip the reload — it would
/// wipe the standing lockdown ruleset (which is the live main ruleset) before
/// Adopt. The `-X` drop is best-effort regardless; the state-file clear is
/// NOT — it runs only when [`restore_confirmed`] says the replacement ruleset
/// actually loaded, so a failed (but not adopting) restore leaves the file in
/// place rather than erasing the cover's only record over a still-blocked
/// host. Shared by `Drop` and `recover_cover`.
fn disengage(token: &str, state_dir: &Path, adopting: bool) {
    // The placeholder `Err` in the `adopting` branch is never read:
    // `restore_confirmed(true, _)` returns `true` unconditionally, since
    // nothing was attempted to confirm.
    let reload: Result<std::process::Output, RoutingError> = if adopting {
        tracing::info!("standing lockdown cover being adopted; skipping /etc/pf.conf reload during transient sweep");
        Err(RoutingError::RouteSetup(
            "reload skipped: standing cover is being adopted".into(),
        ))
    } else {
        let out = pfctl(&["-f", PFCONF], None, BestEffortPhase::RecoverCover);
        if let Err(ref e) = out {
            tracing::warn!(error = %e, "pf ruleset restore failed during cover disengage");
        }
        out
    };
    drop_refcount_or_warn(
        token,
        BestEffortPhase::RecoverCover,
        "pfctl -X failed during cover disengage",
    );
    if restore_confirmed(adopting, &reload) {
        if let Err(e) = state::clear(state_dir) {
            tracing::warn!(error = %e, "failclosed-state clear failed during cover disengage");
        }
    } else {
        tracing::warn!(
            "leaving failclosed-state file in place: the /etc/pf.conf restore did not confirm — clearing it \
             now would make the next sweep read a clean host while the block persists"
        );
    }
}

pub fn recover_cover(state_dir: &Path, adopting: bool) {
    let Some(st) = state::load(state_dir) else {
        tracing::debug!("no failclosed-state file, nothing to recover");
        return;
    };
    tracing::info!(
        was_enabled = ?st.pf_was_enabled,
        "recovering fail-closed cover from crashed run"
    );
    disengage(&st.pf_token, state_dir, adopting);
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
fn capture_and_persist(token: &str, state_dir: &Path, owner: Option<(u32, u32)>) -> Result<String, RoutingError> {
    let presence = lockdown_cover_presence(state_dir);
    let main_snapshot = pfctl_stdout(pfctl(&["-sr"], None, FatalPhase::CoverEngage), "pfctl -sr")?;
    let nat_snapshot = pfctl_stdout(pfctl(&["-sn"], None, FatalPhase::CoverEngage), "pfctl -sn")?;
    persist_baseline(token, state_dir, owner, presence, main_snapshot, nat_snapshot)
}

/// Persist the engage-time baseline. Pure over its inputs — the snapshots and
/// the measured `presence` come from the caller — so the self-capture guard is
/// table-tested without touching pf. Returns the nat snapshot for the engage
/// ruleset.
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
    state_dir: &Path,
    owner: Option<(u32, u32)>,
    presence: crate::routing::CoverPresence,
    main_snapshot: String,
    nat_snapshot: String,
) -> Result<String, RoutingError> {
    let captured = presence != crate::routing::CoverPresence::Live;
    if !captured {
        tracing::warn!(
            "a lockdown cover is already loaded, so there is no pre-lockdown host ruleset to capture; \
             recording no baseline (a restore will reload /etc/pf.conf)"
        );
    }
    lockdown_state::save(
        state_dir,
        &lockdown_state::LockdownPfState {
            version: lockdown_state::SCHEMA_VERSION,
            pf_token: token.to_owned(),
            main_snapshot: if captured { main_snapshot } else { String::new() },
            nat_snapshot: nat_snapshot.clone(),
            main_snapshot_captured: captured,
        },
        owner,
    )
    .map_err(|e| RoutingError::RouteSetup(format!("failed to persist lockdown-pf-state: {e}")))?;
    Ok(nat_snapshot)
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
/// On load failure the host is restored (`lockdown_disengage`) and Err returned;
/// the bridge's fail-FATAL caller aborts the start.
pub fn engage_lockdown(
    server_ip: IpAddr,
    tun_name: &str,
    state_dir: &Path,
    owner: Option<(u32, u32)>,
) -> Result<Cover, RoutingError> {
    // The `pfctl -s info` read is decision-only — `LockdownPfState` records no
    // `pf_was_enabled` bit (unlike the transient `FailClosedState`).
    let info = pfctl_stdout(pfctl(&["-s", "info"], None, FatalPhase::CoverEngage), "pfctl -s info")?;
    let pf_enabled = parse_pf_enabled(&info);
    let persisted = lockdown_state::load(state_dir);

    let (token, nat_snapshot) = match engage_pf_action(pf_enabled, persisted.is_some()) {
        // Live Adopt re-engage within one boot: pf still enabled and we hold the
        // token+snapshot. Reuse both so the real host policy is preserved for the
        // eventual restore. ReuseToken assumes our refcount is still live (the
        // reboot case is `Reenable`); do not double `-E`.
        PfEngageAction::ReuseToken => {
            let st = persisted.expect("ReuseToken implies persisted state");
            (st.pf_token, st.nat_snapshot)
        }
        // Persisted state survived but pf was disabled (reboot reset pf and its
        // refcount). Enable afresh and re-persist the SAME host snapshot under the
        // fresh token — never re-snapshot the live lockdown ruleset. The single
        // `pfctl -X <fresh-token>` on disengage matches this single `-E`.
        PfEngageAction::Reenable => {
            let st = persisted.expect("Reenable implies persisted state");
            let token = enable_pf_capture_token()?;
            let fresh = lockdown_state::LockdownPfState {
                version: lockdown_state::SCHEMA_VERSION,
                pf_token: token.clone(),
                main_snapshot: st.main_snapshot,
                nat_snapshot: st.nat_snapshot.clone(),
                // Carried, not re-asserted: this re-persists the SAME baseline
                // under a fresh token, so claiming a capture that never
                // happened would restore an empty pass-all ruleset.
                main_snapshot_captured: st.main_snapshot_captured,
            };
            if let Err(e) = lockdown_state::save(state_dir, &fresh, owner) {
                drop_refcount_or_warn(
                    &token,
                    FatalPhase::CoverEngage,
                    "pfctl -X failed unwinding a failed lockdown re-enable",
                );
                return Err(RoutingError::RouteSetup(format!(
                    "failed to re-persist lockdown-pf-state: {e}"
                )));
            }
            (token, st.nat_snapshot)
        }
        // First engage: enable + snapshot the host.
        PfEngageAction::FreshEnable => {
            let token = enable_pf_capture_token()?;
            // The refcount is now held. Capture + persist may fail, so undo the
            // `-E` on any error before propagating — else the refcount leaks with
            // no state file to recover it from.
            match capture_and_persist(&token, state_dir, owner) {
                Ok(nat_snapshot) => (token, nat_snapshot),
                Err(e) => {
                    drop_refcount_or_warn(
                        &token,
                        FatalPhase::CoverEngage,
                        "pfctl -X failed unwinding a failed lockdown engage",
                    );
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
    // standing up a full `RealEngageOps` with a `state_dir`/`owner` this call
    // never reads.
    if let Err(e) = load_cover_ruleset(CoverKind::Lockdown, &main, &mut RealCoverRulesetOps) {
        // Restore the host (snapshot reload + drop refcount) before failing, so
        // a partially-loaded ruleset never strands the host.
        lockdown_disengage(state_dir);
        return Err(e);
    }

    Ok(Cover {
        token,
        state_dir: state_dir.to_owned(),
        kind: CoverKind::Lockdown,
    })
}

/// Fail-loud disengage: restore the pre-lockdown ruleset from the snapshot, drop
/// our pf refcount, clear the state. Powers the `bridge unlock` escape hatch.
///
/// Gates on [`lockdown_cover_presence`] — pf's own answer folded with the
/// state file — not on the file alone (#882): a state file that is absent or
/// unusable is not proof pf was never engaged, since pf's label can outlive a
/// lost or corrupted file. Only a presence [`CoverPresence::Absent`] (both
/// sources agree there is nothing) is a silent `Ok`; a presence that could not
/// be established at all ([`CoverPresence::Unreachable`]/
/// [`CoverPresence::Indeterminate`]) refuses rather than claim success having
/// done nothing. A restore that fails propagates the error and LEAVES the
/// state file in place, so a retry (or the next start) still sees the cover
/// rather than reading "disengaged" while the block persists.
///
/// Caveat: pf exposes no dump of prior `set` options, so the restore reloads the
/// host's filter+nat rules under pf defaults (same class of limitation the
/// transient cover documents for its `/etc/pf.conf` reload).
pub fn disengage_lockdown(state_dir: &Path) -> Result<(), RoutingError> {
    disengage_lockdown_with(
        lockdown_cover_presence(state_dir),
        lockdown_state::load(state_dir),
        &mut RealPfOps { state_dir },
    )
}

/// `disengage_lockdown`'s sequencing, with presence and the [`PfOps`] seam
/// injected so the gate (and the "nothing to restore from" fallback) is
/// table-tested without shelling out to `pfctl`.
fn disengage_lockdown_with(
    presence: crate::routing::CoverPresence,
    st: Option<lockdown_state::LockdownPfState>,
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
    match &st {
        Some(st) if st.main_snapshot_captured => {
            ops.load_ruleset(&build_lockdown_restore_ruleset(&st.nat_snapshot, &st.main_snapshot))?
        }
        _ => ops.reload_default()?,
    }

    // Only release a pf refcount token we actually hold on record.
    if let Some(st) = &st {
        ops.drop_token(&st.pf_token)?;
    }

    // State cleared only after a confirmed restore — a failed clear is the only
    // remaining best-effort step (the cover is already down).
    if let Err(e) = ops.clear_standing() {
        tracing::warn!(error = %e, "lockdown-pf-state clear failed after disengage");
    }
    Ok(())
}

/// Fold the two independent presence sources into one answer. `pf_label` is
/// what pf said (`Some(true)`: our own rule label is loaded; `Some(false)`: it
/// is not; `None`: pf could not be asked); `file` is Hole's own
/// `bridge-lockdown-pf.json`.
///
/// pf's own confirmation wins outright. Failing that, a state file — readable
/// or not — is Hole's unreconciled record that a cover was engaged and never
/// confirmed released, which is [`CoverPresence::Recorded`]. Only a pf that
/// answered "no" with nothing on disk contradicting it is `Absent`; a pf that
/// could not answer at all, with no file either, is `Unreachable`.
pub(crate) fn fold_presence(
    pf_label: Option<bool>,
    file: &super::StateFile<lockdown_state::LockdownPfState>,
) -> crate::routing::CoverPresence {
    use crate::routing::CoverPresence;
    match (pf_label, file) {
        (Some(true), _) => CoverPresence::Live,
        (_, StateFile::Present(_) | StateFile::Unusable) => CoverPresence::Recorded,
        (Some(false), StateFile::Absent) => CoverPresence::Absent,
        (None, StateFile::Absent) => CoverPresence::Unreachable,
    }
}

/// Whether a standing lockdown cover is present, per pf and per Hole's own
/// state file. The pf half asks `pfctl -s labels` for [`LOCKDOWN_PF_LABEL`],
/// which is the only evidence here independent of `state_dir`.
pub fn lockdown_cover_presence(state_dir: &Path) -> crate::routing::CoverPresence {
    let pf_label = pf_label_answer(pfctl(&["-s", "labels"], None, BestEffortPhase::RecoverCover));
    fold_presence(pf_label, &lockdown_state::load_presence(state_dir))
}

/// Best-effort wrapper for `Drop` (user-stop): disengage and swallow. Drop has
/// no caller to surface an error to.
fn lockdown_disengage(state_dir: &Path) {
    if let Err(e) = disengage_lockdown(state_dir) {
        tracing::warn!(error = %e, "lockdown disengage failed during Drop");
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
    /// `pfctl -X <token>`: drop a pf enable refcount. Whether a failure here
    /// propagates is the caller's choice: `release_all_with` swallows it
    /// (best-effort, never propagated, via [`drop_token_or_warn`]);
    /// `disengage_lockdown_with` — the single-cover fail-loud escape —
    /// propagates it, per its own doc. Swallowing is never DISCARDING: no
    /// caller may drop this `Result` without at least logging it.
    fn drop_token(&mut self, token: &str) -> Result<(), RoutingError>;
    /// Delete the transient cover's state file.
    fn clear_transient(&mut self) -> Result<(), RoutingError>;
    /// Delete the standing lockdown cover's state file.
    fn clear_standing(&mut self) -> Result<(), RoutingError>;
}

/// [`drop_refcount_or_warn`]'s counterpart for the [`PfOps`] seam, and for the
/// same reason: `drop_token`'s failure is not propagated here (that IS the
/// contract — see [`PfOps::drop_token`]), but not propagating it is no licence
/// to discard it. A `let _ =` leaves a leaked pf enable refcount with nothing
/// in the log saying so, on the one path (`bridge unlock`, the crash-recovery
/// sweep) whose whole job is to leave no cover behind. A separate function
/// rather than a call to [`drop_refcount_or_warn`] because this layer reaches
/// pf through the injected seam, not through the free `pfctl` helper. `message`
/// is per-call-site, so a warn still names which of the three drops it was.
fn drop_token_or_warn(ops: &mut dyn PfOps, token: &str, message: &str) {
    if let Err(e) = ops.drop_token(token) {
        tracing::warn!(error = %e, "{message}");
    }
}

/// The unconditional two-cover clear, factored as a pure sequencer over an
/// injected [`PfOps`] so it is table-tested without touching pf. See
/// `failclosed::release_all`'s doc for the contract this implements.
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
    match transient {
        StateFile::Absent => {}
        StateFile::Present(st) => {
            let reload = ops.reload_default();
            drop_token_or_warn(
                ops,
                &st.pf_token,
                "pfctl -X failed releasing the transient cover's pf refcount during release_all",
            );
            match reload {
                Ok(()) => {
                    if let Err(e) = ops.clear_transient() {
                        tracing::warn!(error = %e, "failclosed-state clear failed during release_all");
                    }
                }
                Err(e) => first_err = Some(e),
            }
        }
        StateFile::Unusable => {
            tracing::warn!(
                "transient failclosed-state file is unusable; no pf token to drop — a pf enable \
                 refcount may be leaked (pf then stays enabled over the canonical /etc/pf.conf, \
                 which blocks nothing, and a reboot resets it)"
            );
            match ops.reload_default() {
                Ok(()) => {
                    if let Err(e) = ops.clear_transient() {
                        tracing::warn!(error = %e, "failclosed-state clear failed during release_all");
                    }
                }
                Err(e) => first_err = Some(e),
            }
        }
    }

    // Block 2 — standing cover.
    match standing {
        StateFile::Absent => {}
        StateFile::Present(st) if !st.main_snapshot_captured => {
            // No baseline was captured, so there is no snapshot to load — see
            // `LockdownPfState::main_snapshot_captured`. Loading the empty one
            // would leave a pass-all host.
            let outcome = ops.reload_default();
            drop_token_or_warn(
                ops,
                &st.pf_token,
                "pfctl -X failed releasing the standing cover's pf refcount during release_all after a \
                 default-ruleset restore",
            );
            match outcome {
                Ok(()) => {
                    if let Err(e) = ops.clear_standing() {
                        tracing::warn!(error = %e, "lockdown-pf-state clear failed during release_all");
                    }
                }
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }
        StateFile::Present(st) => {
            let restore = build_lockdown_restore_ruleset(&st.nat_snapshot, &st.main_snapshot);
            let outcome = match ops.load_ruleset(&restore) {
                Ok(()) => Ok(()),
                Err(snapshot_err) => match ops.reload_default() {
                    Ok(()) => {
                        tracing::warn!(
                            error = %snapshot_err,
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
            drop_token_or_warn(
                ops,
                &st.pf_token,
                "pfctl -X failed releasing the standing cover's pf refcount during release_all after a \
                 snapshot restore",
            );
            match outcome {
                Ok(()) => {
                    if let Err(e) = ops.clear_standing() {
                        tracing::warn!(error = %e, "lockdown-pf-state clear failed during release_all");
                    }
                }
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }
        StateFile::Unusable => {
            tracing::warn!(
                "standing lockdown-pf-state file is unusable; no snapshot to restore, falling back to \
                 the default ruleset"
            );
            match ops.reload_default() {
                Ok(()) => {
                    if let Err(e) = ops.clear_standing() {
                        tracing::warn!(error = %e, "lockdown-pf-state clear failed during release_all");
                    }
                }
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }
    }

    match first_err {
        Some(e) => Err(e),
        None => Ok(()),
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
}

/// `pfctl -f -` with `text` on stdin, one [`FatalPhase::CoverEngage`]
/// implementation shared by [`RealEngageOps`] and [`RealCoverRulesetOps`] so
/// the narrower seam is not a second copy of the shell-out.
fn real_load_ruleset(text: &str) -> Result<(), RoutingError> {
    pfctl_status(
        pfctl(&["-f", "-"], Some(text.as_bytes()), FatalPhase::CoverEngage),
        "pfctl load",
    )
}

/// `pfctl -F states`, same sharing rationale as [`real_load_ruleset`].
fn real_flush_states() -> Result<(), RoutingError> {
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
        enable_pf_capture_token()
    }

    fn save_transient(&mut self, st: &state::FailClosedState) -> Result<(), RoutingError> {
        state::save(self.state_dir, st, self.owner)
            .map_err(|e| RoutingError::RouteSetup(format!("failed to persist failclosed-state: {e}")))
    }

    fn drop_token(&mut self, token: &str) -> Result<(), RoutingError> {
        pfctl_status(pfctl(&["-X", token], None, FatalPhase::CoverEngage), "pfctl -X")
    }

    fn transient_restore(&mut self, token: &str) {
        disengage(token, self.state_dir, false);
    }
}

/// Production [`CoverRulesetOps`] for a bare ruleset-load-and-purge, with no
/// `state_dir`/`owner` — unlike [`RealEngageOps`], which the `Lockdown` engage
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
        pfctl_status(pfctl(&["-X", token], None, BestEffortPhase::RecoverCover), "pfctl -X")
    }

    fn clear_transient(&mut self) -> Result<(), RoutingError> {
        state::clear(self.state_dir)
            .map_err(|e| RoutingError::RouteSetup(format!("failclosed-state clear failed: {e}")))
    }

    fn clear_standing(&mut self) -> Result<(), RoutingError> {
        lockdown_state::clear(self.state_dir)
            .map_err(|e| RoutingError::RouteSetup(format!("lockdown-pf-state clear failed: {e}")))
    }
}

/// Clear every fail-closed cover macOS can install — both the transient
/// block-until-connected cover and the standing lockdown cover — without
/// asking whether either is present. See `failclosed::release_all` for the
/// full contract; this loads both state-file presences and delegates the
/// sequencing to [`release_all_with`].
pub fn release_all(state_dir: &Path) -> Result<(), RoutingError> {
    let transient = state::load_presence(state_dir);
    let standing = lockdown_state::load_presence(state_dir);
    release_all_with(transient, standing, &mut RealPfOps { state_dir })
}

#[cfg(test)]
#[path = "macos_tests.rs"]
mod macos_tests;

/// Privileged-lane real-engage tests. A DESCENDANT of this module, not a
/// sibling of the other `*_privileged_tests.rs` files under `failclosed`,
/// because they reach for [`Cover`]'s private `token` field and the private
/// [`pfctl`] helper — and that is what descendance buys, not sharing a file
/// with [`macos_tests`].
#[cfg(test)]
#[path = "macos_transition_tests.rs"]
mod macos_transition_tests;
