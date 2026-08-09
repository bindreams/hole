//! macOS fail-closed cover via pf (`pfctl`). Two layers share the `Cover` guard:
//!
//! - **Transient cover** (`engage`/`disengage`): enables pf (refcounted,
//!   `pfctl -E`), flushes all state (`-Fa`), and loads a self-contained
//!   ruleset (see `build_pf_ruleset`) blocking everything but loopback, the
//!   server, and the pinned resolver. Disengage restores the canonical
//!   `/etc/pf.conf` and drops the refcount.
//! - **Standing lockdown** (`engage_lockdown`/`lockdown_disengage`): loads a
//!   self-contained MAIN ruleset (NO `-Fa`) that carries the host's translation
//!   rules forward and blocks all egress except the TUN, the server IP, and
//!   (when a plugin needs it) the pinned resolver. Disengage
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

use super::super::{run_capturing, PHASE_COVER, PHASE_RECOVER_COVER};
use crate::error::RoutingError;
// `macos.rs` is mounted as `mod platform` under `failclosed`, so `super` is the
// `failclosed` module and `failclosed_state` is its sibling child.
use super::failclosed_state as state;
use super::lockdown_pf_state as lockdown_state;
use super::RESOLVER_PERMIT_PORT;

/// Build the self-contained pf ruleset (loaded via `pfctl -f -`).
///
/// `set block-policy drop` silently drops blocked packets (no RST/ICMP).
/// `block out all` is the fail-closed default; the `quick` pass rules for
/// loopback, the server IP, and (when given) the resolver the caller's own
/// `ech-doh` URL names win without depending on pf's last-match rule. The
/// `to {ip}` form carries a v6 address as written. `resolver_ip` is `None`
/// whenever nothing should be permitted — see
/// `Routing::install_failclosed_cover`'s doc for the exact conditions. The
/// resolver pass is scoped to `proto tcp port` [`RESOLVER_PERMIT_PORT`] (see
/// that const's doc for why this is the only port this fetch can need) — NOT
/// the server permit's unrestricted shape.
pub fn build_pf_ruleset(server_ip: IpAddr, resolver_ip: Option<IpAddr>) -> String {
    format!(
        "set block-policy drop\n\
         block out all\n\
         pass out quick on lo0 all\n\
         pass in quick on lo0 all\n\
         pass out quick from any to {server_ip}\n\
         {resolver_pass}",
        resolver_pass = resolver_pass_line(resolver_ip),
    )
}

/// The optional resolver-permit pf line for `resolver_ip`, scoped to
/// `proto tcp port` [`RESOLVER_PERMIT_PORT`] — shared by `build_pf_ruleset`
/// (transient) and `build_lockdown_main_ruleset` (standing): both covers
/// permit the identical resolver address under the identical scope (see
/// [`crate::routing::Routing::install_failclosed_cover`]'s doc for the trust
/// condition). Empty string when `resolver_ip` is `None` — omitted whenever
/// nothing should be permitted.
fn resolver_pass_line(resolver_ip: Option<IpAddr>) -> String {
    resolver_ip
        .map(|ip| format!("pass out quick proto tcp from any to {ip} port {RESOLVER_PERMIT_PORT}\n"))
        .unwrap_or_default()
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

/// Build the self-contained MAIN ruleset for the standing lockdown, loaded via
/// `pfctl -f -` (NO `-Fa`). It IS the host's egress policy while engaged:
/// `block drop out quick all` is the fail-closed base, with earlier `quick`
/// permits for the TUN (when `tun_name` is `Some` — see [`tun_pass_line`]'s
/// doc for why the pre-Phase-1 engage omits it), the server IP, and (when
/// `Some`) the resolver Hole's own `ech-doh` URL names, scoped to
/// `proto tcp port` [`RESOLVER_PERMIT_PORT`] — the same trust condition and
/// port scope as the transient cover's `build_pf_ruleset` (see
/// [`crate::routing::Routing::install_lockdown_permits`]'s doc). pf has no
/// per-process matching, so an App-ID-style permit isn't an option here even
/// in principle — the address permit is the only way this fetch (which may
/// run in a plugin's separately-spawned child process, e.g. galoshes'
/// embedded ex-ray) is ever reachable under the cover.
///
/// `set` lives here (main-ruleset-only — it is a parse error inside an anchor),
/// and the host's translation rules (`nat_snapshot`, from `pfctl -sn`) are
/// carried forward so the session does not flush NAT. Ordering is
/// `require-order`-enforced: Options -> Translation (nat) -> Filter. The server
/// (and resolver) permits precede `block drop out quick inet6 all` so a v6
/// server/resolver is not killed. pf has no per-process matching, so the
/// server permit is IP-based.
pub fn build_lockdown_main_ruleset(
    tun_name: Option<&str>,
    server_ip: IpAddr,
    resolver_ip: Option<IpAddr>,
    nat_snapshot: &str,
) -> String {
    let proto = "tcp"; // +udp once a UDP-transport plugin lands; egress is TCP-only today.
    format!(
        "set block-policy drop\n\
         set skip on lo0\n\
         {nat}\
         pass out quick proto {proto} from any to {ip}\n\
         {resolver}\
         {tun}\
         block drop out quick inet6 all\n\
         block drop out quick all\n",
        nat = ensure_trailing_nl(nat_snapshot),
        proto = proto,
        ip = server_ip,
        resolver = resolver_pass_line(resolver_ip),
        tun = tun_pass_line(tun_name),
    )
}

/// The optional TUN-interface pf line for `tun_name` — `None` for the
/// pre-Phase-1 permits-only engage (see
/// [`crate::routing::Routing::install_lockdown_permits`]'s doc): app traffic
/// has nowhere to flow before `routing.install` creates the adapter, so the
/// permit is omitted entirely rather than naming an interface that cannot yet
/// exist.
fn tun_pass_line(tun_name: Option<&str>) -> String {
    tun_name
        .map(|t| format!("pass out quick on {t} all\n"))
        .unwrap_or_default()
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

fn pfctl(args: &[&str], stdin: Option<&[u8]>, phase: &str) -> Result<std::process::Output, RoutingError> {
    let cmd: Vec<String> = std::iter::once("pfctl")
        .chain(args.iter().copied())
        .map(str::to_owned)
        .collect();
    run_capturing(&cmd, stdin, phase).map_err(|e| RoutingError::RouteSetup(format!("pfctl spawn failed: {e}")))
}

/// `pfctl -E` (refcounted enable) + parse the enable token from its output. The
/// token prints to stderr (or stdout on some hosts), so try both.
fn enable_pf_capture_token() -> Result<String, RoutingError> {
    let en = pfctl(&["-E"], None, PHASE_COVER)?;
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

/// Whether THIS `engage_lockdown` call created the standing cover from
/// nothing, or found one already live (adopted from a prior bridge process
/// that crashed or cutover, `CoverRecovery::Adopt`). Consulted ONLY by
/// `Drop` — see there for why. Meaningless for `CoverKind::Transient` (the
/// transient cover has no adoption concept; every engage is fresh), always
/// `Fresh` in that case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ownership {
    Fresh,
    Adopted,
}

/// pf-backed cover guard. Drop disengages per [`CoverKind`]: the transient
/// cover restores `/etc/pf.conf`; the lockdown cover restores the snapshot —
/// UNLESS `ownership` is `Adopted`, in which case Drop leaves pf exactly as
/// this attempt's own engage left it; see `Drop for Cover`.
pub struct Cover {
    token: String,
    state_dir: std::path::PathBuf,
    kind: CoverKind,
    ownership: Ownership,
}

impl Cover {
    /// See [`crate::routing::CoverGuard::mark_owned`].
    pub fn mark_owned(&mut self) {
        self.ownership = Ownership::Fresh;
    }
}

pub fn engage(
    server_ip: IpAddr,
    resolver_ip: Option<IpAddr>,
    state_dir: &Path,
    owner: Option<(u32, u32)>,
) -> Result<Cover, RoutingError> {
    // 1. Read current enabled-state (read-only).
    let info = pfctl(&["-s", "info"], None, PHASE_COVER)?;
    let was_enabled = parse_pf_enabled(&String::from_utf8_lossy(&info.stdout));

    // 2. Enable pf (refcounted) and capture the token.
    let token = enable_pf_capture_token()?;

    // 3. Persist BEFORE loading the blocking ruleset (persist-before-mutate),
    //    so a crash after this point is recoverable (`pfctl -X <token>`).
    state::save(
        state_dir,
        &state::FailClosedState {
            version: state::SCHEMA_VERSION,
            pf_token: token.clone(),
            pf_was_enabled: was_enabled,
        },
        owner,
    )
    .map_err(|e| RoutingError::RouteSetup(format!("failed to persist failclosed-state: {e}")))?;

    // 4. Flush all + load our self-contained blocking ruleset from stdin.
    let ruleset = build_pf_ruleset(server_ip, resolver_ip);
    let out = pfctl(&["-Fa", "-f", "-"], Some(ruleset.as_bytes()), PHASE_COVER)?;
    if !out.status.success() {
        // A *failed engage* is the sole place this module fails OPEN on its own
        // error: we must not leave a half-loaded ruleset blocking traffic. Note
        // `-Fa` already flushed the host's prior rules, so a full `disengage`
        // (restore `/etc/pf.conf` + drop our refcount + clear the state file) is
        // required to undo the flush — dropping only the refcount would strand
        // the host with an empty pass-all ruleset. The PR3 cutover treats an
        // engage error as fatal and aborts before stopping the old bridge, so
        // the tunnel is never torn down uncovered. No standing cover is being
        // adopted on this engage-failure path, so the `/etc/pf.conf` restore
        // (undoing the `-Fa` flush) must run.
        disengage(&token, state_dir, false);
        return Err(RoutingError::RouteSetup(format!(
            "pfctl load failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }

    Ok(Cover {
        token,
        state_dir: state_dir.to_owned(),
        kind: CoverKind::Transient,
        ownership: Ownership::Fresh,
    })
}

impl Drop for Cover {
    fn drop(&mut self) {
        match (self.kind, self.ownership) {
            // A user-stop drop never has a standing cover being adopted.
            (CoverKind::Transient, _) => disengage(&self.token, &self.state_dir, false),
            // Lockdown, Fresh: THIS call created the cover from nothing --
            // restore the pre-lockdown snapshot and drop the refcount, same
            // as always.
            (CoverKind::Lockdown, Ownership::Fresh) => lockdown_disengage(&self.state_dir),
            // Lockdown, Adopted: ordinary RAII ownership -- Drop must not
            // destroy a cover this attempt did not create. Leaves pf
            // exactly as this attempt's own engage left it (untouched, or
            // its own rewritten ruleset if the engage succeeded before a
            // later phase failed). See CONTRIBUTING.md's "Lockdown mode"
            // for why no restore-to-before-this-attempt snapshot exists.
            (CoverKind::Lockdown, Ownership::Adopted) => {}
        }
    }
}

/// Drop the transient enable refcount + clear the file. When `adopting` is
/// false, also restore the canonical ruleset (the transient engage did `-Fa`,
/// flushing host rules, so the restore is mandatory to undo the flush). When a
/// standing cover is being adopted, skip the `/etc/pf.conf` reload — it would
/// wipe the standing lockdown ruleset (which is the live main ruleset) before
/// Adopt. Best-effort; logs on failure. Shared by `Drop` and `recover_cover`.
fn disengage(token: &str, state_dir: &Path, adopting: bool) {
    if adopting {
        tracing::info!("standing lockdown cover being adopted; skipping /etc/pf.conf reload during transient sweep");
    } else if let Err(e) = pfctl(&["-f", PFCONF], None, PHASE_RECOVER_COVER) {
        tracing::warn!(error = %e, "pf ruleset restore failed during cover disengage");
    }
    if let Err(e) = pfctl(&["-X", token], None, PHASE_RECOVER_COVER) {
        tracing::warn!(error = %e, "pfctl -X failed during cover disengage");
    }
    if let Err(e) = state::clear(state_dir) {
        tracing::warn!(error = %e, "failclosed-state clear failed during cover disengage");
    }
}

pub fn recover_cover(state_dir: &Path, adopting: bool) {
    let Some(st) = state::load(state_dir) else {
        tracing::debug!("no failclosed-state file, nothing to recover");
        return;
    };
    tracing::info!(
        was_enabled = st.pf_was_enabled,
        "recovering fail-closed cover from crashed run"
    );
    disengage(&st.pf_token, state_dir, adopting);
}

// --- lockdown layer ---

/// Snapshot the host's filter (`-sr`) and translation (`-sn`) rules and persist
/// them with `token` (persist-before-mutate). Returns the nat snapshot for the
/// engage ruleset. Separated so its `?`-error path can be unwound (drop the pf
/// refcount) by the caller without leaking the `-E` enable.
fn capture_and_persist(token: &str, state_dir: &Path, owner: Option<(u32, u32)>) -> Result<String, RoutingError> {
    let sr = pfctl(&["-sr"], None, PHASE_COVER)?;
    let main_snapshot = String::from_utf8_lossy(&sr.stdout).into_owned();
    let sn = pfctl(&["-sn"], None, PHASE_COVER)?;
    let nat_snapshot = String::from_utf8_lossy(&sn.stdout).into_owned();

    lockdown_state::save(
        state_dir,
        &lockdown_state::LockdownPfState {
            version: lockdown_state::SCHEMA_VERSION,
            pf_token: token.to_owned(),
            main_snapshot,
            nat_snapshot: nat_snapshot.clone(),
        },
        owner,
    )
    .map_err(|e| RoutingError::RouteSetup(format!("failed to persist lockdown-pf-state: {e}")))?;
    Ok(nat_snapshot)
}

/// Reconcile pf's enabled state against an ALREADY-PERSISTED lockdown token,
/// for a caller that never takes `FreshEnable` (Phase-6's TUN-add — an
/// absent state file is already a hard error there, checked before this
/// runs). `pfctl -f -` into a DISABLED pf exits 0 while enforcing nothing
/// (`engage_pf_action`'s own doc: "always load the ruleset into an ENABLED
/// pf, never an inert one") — this is the SAME reconciliation
/// [`engage_lockdown`] performs for its own `ReuseToken`/`Reenable` arms,
/// factored out here so the Phase-6 TUN-add reload cannot load straight
/// into whatever pf's live state happens to be, with no check.
///
/// Whether pf was found already enabled and enforcing going into a
/// [`reconcile_pf_enabled`] call, or had to be freshly re-enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PfReconciled {
    /// pf was already enabled: whatever ruleset was loaded under the
    /// persisted token is genuinely live and has been continuously
    /// enforcing.
    AlreadyEnabled,
    /// pf was DISABLED (e.g. a reboot reset its refcount and cleared its
    /// in-memory loaded rules) and has just been freshly re-enabled under a
    /// NEW refcount token. Nothing was being enforced immediately before
    /// this call, regardless of what the state file claims was loaded --
    /// `-E` alone does not reload any specific ruleset.
    JustReenabled,
}

/// Returns the token to load the ruleset with (reused unchanged, or freshly
/// re-enabled and re-persisted under the SAME host snapshot if pf had been
/// disabled since the state file was written) alongside which of those two
/// happened — callers need this to decide whether a SUBSEQUENT `pfctl -f -`
/// failure leaves a genuinely-enforcing prior ruleset in place
/// (`AlreadyEnabled`) or strands the host with nothing actually enforced
/// (`JustReenabled`, where `-E` re-enabled filtering but loaded no ruleset
/// of its own).
fn reconcile_pf_enabled(
    persisted: &lockdown_state::LockdownPfState,
    state_dir: &Path,
    owner: Option<(u32, u32)>,
) -> Result<(String, PfReconciled), RoutingError> {
    let info = pfctl(&["-s", "info"], None, PHASE_COVER)?;
    let pf_enabled = parse_pf_enabled(&String::from_utf8_lossy(&info.stdout));
    match engage_pf_action(pf_enabled, true) {
        PfEngageAction::ReuseToken => Ok((persisted.pf_token.clone(), PfReconciled::AlreadyEnabled)),
        PfEngageAction::Reenable => {
            let token = enable_pf_capture_token()?;
            let fresh = lockdown_state::LockdownPfState {
                version: lockdown_state::SCHEMA_VERSION,
                pf_token: token.clone(),
                main_snapshot: persisted.main_snapshot.clone(),
                nat_snapshot: persisted.nat_snapshot.clone(),
            };
            if let Err(e) = lockdown_state::save(state_dir, &fresh, owner) {
                if let Err(xe) = pfctl(&["-X", &token], None, PHASE_COVER) {
                    tracing::warn!(error = %xe, "pfctl -X failed unwinding a failed lockdown re-enable");
                }
                return Err(RoutingError::RouteSetup(format!(
                    "failed to re-persist lockdown-pf-state: {e}"
                )));
            }
            Ok((token, PfReconciled::JustReenabled))
        }
        // `has_persisted=true` (a `&LockdownPfState` was passed in) forces
        // `engage_pf_action`'s match into ReuseToken or Reenable -- see its
        // own `(false, _) => FreshEnable` arm, unreachable with `true` fixed.
        PfEngageAction::FreshEnable => {
            unreachable!("reconcile_pf_enabled is only ever called with a persisted state already in hand")
        }
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
/// block takes effect while host translation is carried forward.
///
/// On load failure Err is always returned (the bridge's fail-FATAL caller
/// aborts the start). The host is actively restored (`lockdown_disengage`)
/// whenever nothing was GENUINELY enforcing immediately before this call:
/// either a FIRST-ever engage (`persisted` was `None`), or a re-engage where
/// [`reconcile_pf_enabled`] had to freshly re-enable a DISABLED pf
/// (`PfReconciled::JustReenabled` — `-E` alone loads no ruleset, so nothing
/// was actually being enforced despite the state file's claim). Only a
/// re-engage that found pf ALREADY enabled (`PfReconciled::AlreadyEnabled`)
/// skips the restore: `pfctl -f -`'s atomicity means a rejected reload there
/// leaves that previously-loaded ruleset unchanged and still fully
/// enforced, so disengaging would destroy a cover that is still live and
/// correct.
pub fn engage_lockdown(
    server_ip: IpAddr,
    resolver_ip: Option<IpAddr>,
    tun_name: Option<&str>,
    state_dir: &Path,
    owner: Option<(u32, u32)>,
) -> Result<Cover, RoutingError> {
    let persisted = lockdown_state::load(state_dir);
    // Ownership (see `Ownership`'s own doc and `Drop for Cover`): a
    // persisted state file means SOME cover already existed when this call
    // started -- either adopted from a prior bridge process, or (within
    // this SAME process) a previous attempt's own Adopted cover that a
    // still-earlier failure already declined to tear down. Either way,
    // THIS attempt did not create it from nothing, so it must not be the
    // one to destroy it either.
    let ownership = if persisted.is_some() {
        Ownership::Adopted
    } else {
        Ownership::Fresh
    };

    // `resave_after_success` carries the main_snapshot for a `Some(st)`
    // re-engage ONLY -- see the self-healing re-persist below for why.
    let (token, main_snapshot_for_resave, nat_snapshot, restore_on_failure) = match &persisted {
        // Live Adopt re-engage, or a repair/TUN-add on an already-engaged
        // session: reconcile pf's enabled state against the persisted token
        // (reused unchanged if pf is still enabled, or freshly re-enabled
        // and re-persisted if a reboot reset it) — see `reconcile_pf_enabled`.
        // `restore_on_failure` is false ONLY when pf was found genuinely
        // already enabled -- a `JustReenabled` re-engage restores on failure
        // exactly like a first-ever engage, since nothing was actually being
        // enforced going in.
        Some(st) => {
            let (token, reconciled) = reconcile_pf_enabled(st, state_dir, owner)?;
            (
                token,
                Some(st.main_snapshot.clone()),
                st.nat_snapshot.clone(),
                reconciled != PfReconciled::AlreadyEnabled,
            )
        }
        // First engage: enable + snapshot the host. Nothing was live before
        // this call, so a load failure always restores. `capture_and_persist`
        // already persists before this function's own `pfctl -f -` mutates
        // (persist-before-mutate, its own doc), so this branch does not need
        // the `Some(st)` branch's post-success re-persist below.
        None => {
            let token = enable_pf_capture_token()?;
            // The refcount is now held. Capture + persist may fail, so undo the
            // `-E` on any error before propagating — else the refcount leaks with
            // no state file to recover it from.
            match capture_and_persist(&token, state_dir, owner) {
                Ok(nat_snapshot) => (token, None, nat_snapshot, true),
                Err(e) => {
                    if let Err(xe) = pfctl(&["-X", &token], None, PHASE_COVER) {
                        tracing::warn!(error = %xe, "pfctl -X failed unwinding a failed lockdown engage");
                    }
                    return Err(e);
                }
            }
        }
    };

    let main = build_lockdown_main_ruleset(tun_name, server_ip, resolver_ip, &nat_snapshot);
    let out = pfctl(&["-f", "-"], Some(main.as_bytes()), PHASE_COVER)?;
    if !out.status.success() {
        if restore_on_failure {
            // Nothing was genuinely enforcing before this call (first-ever
            // engage, or a JustReenabled re-engage) -- a partially-loaded
            // ruleset would strand the host mid-lockdown. Restore the
            // pre-lockdown host state (snapshot reload + drop refcount)
            // before failing.
            lockdown_disengage(state_dir);
        }
        // Otherwise this was a re-engage over pf that was ALREADY enabled
        // and enforcing: `pfctl -f -` is atomic, so this rejected reload
        // left the PREVIOUSLY loaded ruleset (still fully enforced, still
        // correct) untouched -- restoring the pre-lockdown snapshot would
        // destroy a live, correct standing cover instead of merely failing
        // this one call. Mirrors `engage_lockdown_tun`'s identical
        // disposition for the same atomicity guarantee.
        return Err(RoutingError::RouteSetup(format!(
            "pfctl lockdown load failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }

    if let Some(main_snapshot) = main_snapshot_for_resave {
        // Self-healing re-persist, "ask forgiveness" rather than atomic
        // check-then-act -- see `engage_lockdown_tun`'s identical rationale:
        // this function's initial `load` above and this successful reload
        // are not one atomic operation with a concurrent `hole bridge
        // unlock` (`disengage_lockdown` clears the state file with no "only
        // when no bridge is alive" enforcement). Without this, a clear
        // racing in between would leave this just-reloaded ruleset live
        // with NO state file to disengage it later. Only for the `Some(st)`
        // (re-engage) case -- a first-ever engage already persisted before
        // its own mutate, above.
        let fresh = lockdown_state::LockdownPfState {
            version: lockdown_state::SCHEMA_VERSION,
            pf_token: token.clone(),
            main_snapshot,
            nat_snapshot: nat_snapshot.clone(),
        };
        if let Err(e) = lockdown_state::save(state_dir, &fresh, owner) {
            return Err(RoutingError::RouteSetup(format!(
                "engage_lockdown: failed to re-persist lockdown state after a successful reload: {e}"
            )));
        }
    }

    Ok(Cover {
        token,
        state_dir: state_dir.to_owned(),
        kind: CoverKind::Lockdown,
        ownership,
    })
}

/// Add the TUN pass line to an already-engaged standing lockdown cover
/// (Phase 6, once `routing.install` has resolved the adapter), by reloading
/// the FULL ruleset — pf has no incremental update — reusing the SAME
/// persisted token/nat_snapshot [`engage_lockdown`] (Phase 0) already wrote.
/// Returns no guard: the [`Cover`] Phase 0 already returned still owns the
/// whole standing cover.
///
/// Unlike [`engage_lockdown`]'s own load-failure branch, a failed reload
/// here does NOT call [`lockdown_disengage`]: `pfctl -f -` is atomic — a
/// rejected ruleset leaves the PREVIOUSLY LOADED one (Phase 0's, permitting
/// loopback/server/resolver/App-ID, minus only the TUN line this call was
/// trying to add) unchanged and still fully enforced -- true whenever
/// [`reconcile_pf_enabled`] found pf already enabled. This function never
/// restores on failure itself either way: within the full bridge flow, the
/// caller (`start_cancellable`) holds the Phase-0 `Cover` as a plain local
/// and it drops via ordinary RAII on ANY `start_inner` failure (this one
/// included) — a `Fresh`-owned guard disengages there; an `Adopted` one
/// (Phase 0 found a standing cover already live, from a prior bridge
/// process) does not, by design (see `Ownership` and `Drop for Cover`), so
/// the aggregate outcome depends on ownership, not solely on what this
/// function does internally. Restoring here too would double a `Fresh`
/// disengage and would be wrong outright for an `Adopted` one. A STANDALONE
/// call (e.g. a test driving this function directly, with no such caller)
/// has no such backstop; see [`reconcile_pf_enabled`]'s
/// `PfReconciled::JustReenabled` case for when "still fully enforced" does
/// NOT hold even for an atomic reload (pf had nothing loaded going in).
///
/// Reconciles pf's enabled state via [`reconcile_pf_enabled`] before the
/// reload — `pfctl -f -` into a DISABLED pf exits 0 while enforcing nothing,
/// so skipping this would report a connected session as covered while pf
/// enforces nothing at all.
///
/// The initial state-file `load` and the final reload+re-save are NOT one
/// atomic operation — a concurrent `hole bridge unlock` can clear the state
/// file in between. On success this function re-persists the state it just
/// reloaded with ("ask forgiveness" rather than a lock), so that race leaves
/// a live ruleset WITH a state file to recover it (self-healing on the next
/// `unlock`/crash-recovery sweep) instead of a live ruleset with none (an
/// unrecoverable, manually-`pfctl`-only stranding).
pub fn engage_lockdown_tun(
    tun_name: &str,
    server_ip: IpAddr,
    resolver_ip: Option<IpAddr>,
    state_dir: &Path,
    owner: Option<(u32, u32)>,
) -> Result<(), RoutingError> {
    let persisted = lockdown_state::load(state_dir).ok_or_else(|| {
        RoutingError::RouteSetup(
            "engage_lockdown_tun: no lockdown state on disk -- called before the Phase-0 engage".into(),
        )
    })?;
    let (token, _reconciled) = reconcile_pf_enabled(&persisted, state_dir, owner)?;
    let main = build_lockdown_main_ruleset(Some(tun_name), server_ip, resolver_ip, &persisted.nat_snapshot);
    let out = pfctl(&["-f", "-"], Some(main.as_bytes()), PHASE_COVER)?;
    if !out.status.success() {
        return Err(RoutingError::RouteSetup(format!(
            "pfctl lockdown TUN-add load failed (the Phase-0 cover is unaffected -- pfctl's reload is atomic): {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    // Self-healing re-persist, "ask forgiveness" rather than atomic
    // check-then-act: this call's own initial `load` above and this final
    // `save` are not one indivisible operation with a concurrent
    // `hole bridge unlock` (`disengage_lockdown` deletes the state file
    // with no "only when no bridge is alive" enforcement). Without this
    // save, a clear racing between the load and the reload above would
    // leave the just-loaded lockdown ruleset live with NO state file to
    // disengage it later -- a silent no-op for both this attempt's own
    // `Cover::drop` and any subsequent `unlock`, stranding pf permanently
    // locked down. Re-saving the SAME already-known snapshots under
    // `reconcile_pf_enabled`'s current token (idempotent when nothing
    // raced) makes this successful reload authoritative over a racing
    // clear instead of the reverse.
    let fresh = lockdown_state::LockdownPfState {
        version: lockdown_state::SCHEMA_VERSION,
        pf_token: token,
        main_snapshot: persisted.main_snapshot.clone(),
        nat_snapshot: persisted.nat_snapshot.clone(),
    };
    lockdown_state::save(state_dir, &fresh, owner).map_err(|e| {
        RoutingError::RouteSetup(format!(
            "engage_lockdown_tun: failed to re-persist lockdown state after a successful reload: {e}"
        ))
    })?;
    Ok(())
}

/// Fail-loud disengage: restore the pre-lockdown ruleset from the snapshot, drop
/// our pf refcount, clear the state. An ABSENT cover (no state file) is `Ok` —
/// nothing to disengage, so no pfctl is spawned. A PRESENT cover that fails to
/// restore propagates the error and LEAVES the state file in place, so a retry
/// (or the next start) still sees the cover rather than reading "disengaged"
/// while the block persists. Powers the `bridge unlock` escape hatch.
///
/// Caveat: pf exposes no dump of prior `set` options, so the restore reloads the
/// host's filter+nat rules under pf defaults (same class of limitation the
/// transient cover documents for its `/etc/pf.conf` reload).
pub fn disengage_lockdown(state_dir: &Path) -> Result<(), RoutingError> {
    let Some(st) = lockdown_state::load(state_dir) else {
        return Ok(()); // No cover engaged — nothing to disengage.
    };
    let restore = build_lockdown_restore_ruleset(&st.nat_snapshot, &st.main_snapshot);
    let out = pfctl(&["-f", "-"], Some(restore.as_bytes()), PHASE_RECOVER_COVER)?;
    if !out.status.success() {
        return Err(RoutingError::RouteSetup(format!(
            "pfctl lockdown restore failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let xout = pfctl(&["-X", &st.pf_token], None, PHASE_RECOVER_COVER)?;
    if !xout.status.success() {
        return Err(RoutingError::RouteSetup(format!(
            "pfctl -X (drop pf refcount) failed: {}",
            String::from_utf8_lossy(&xout.stderr).trim()
        )));
    }
    // State cleared only after a confirmed restore — a failed clear is the only
    // remaining best-effort step (the cover is already down).
    if let Err(e) = lockdown_state::clear(state_dir) {
        tracing::warn!(error = %e, "lockdown-pf-state clear failed after disengage");
    }
    Ok(())
}

/// Best-effort wrapper for `Drop` (user-stop): disengage and swallow. Drop has
/// no caller to surface an error to.
fn lockdown_disengage(state_dir: &Path) {
    if let Err(e) = disengage_lockdown(state_dir) {
        tracing::warn!(error = %e, "lockdown disengage failed during Drop");
    }
}

/// Act on a recovery decision for the lockdown cover (the facade routes `Sweep`
/// through the fail-loud `disengage_lockdown`; this best-effort path remains
/// correct if called directly). `Adopt` (intent ON): KEEP the host fail-closed —
/// leave the lockdown ruleset + state file in force. The dead utun name in the
/// `pass out quick on <tun>` line is harmless (matches no live interface); the
/// next connect's `engage_lockdown` reuses the persisted snapshot and reloads
/// with the fresh utun name. `Sweep` (intent OFF): best-effort restore. `Noop`:
/// nothing.
pub fn recover_lockdown(decision: crate::routing::CoverRecovery, state_dir: &Path) {
    use crate::routing::CoverRecovery::*;
    match decision {
        Noop => {}
        Adopt => {
            tracing::info!("lockdown recovery: adopting persistent cover (host stays fail-closed)");
            // Intentionally NOTHING removed: the block must survive the
            // restart (this IS the crash-leak fix). macOS pf rules + enable
            // state do NOT survive a reboot, but the persisted state file does:
            // the next reconnect's `engage_lockdown` idempotently re-enables pf
            // and reloads a live ruleset (so a connected session no longer fails
            // open). Residual: the boot->first-connect interval is unprotected
            // (no early-boot block) until that first reconnect re-arms the host.
        }
        Sweep => {
            tracing::info!("lockdown recovery: sweeping leftover cover (intent off)");
            lockdown_disengage(state_dir);
        }
    }
}

#[cfg(test)]
#[path = "macos_tests.rs"]
mod macos_tests;
