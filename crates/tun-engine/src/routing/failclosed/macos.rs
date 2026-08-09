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

/// pf-backed cover guard. Drop disengages per [`CoverKind`]: the transient
/// cover restores `/etc/pf.conf`; the lockdown cover restores the snapshot.
pub struct Cover {
    token: String,
    state_dir: std::path::PathBuf,
    kind: CoverKind,
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
    })
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
/// for a caller that never takes `FreshEnable` (Phase-6 TUN-add, or a Phase-0
/// repair — an absent state file is already a hard error for both, checked
/// before this runs). `pfctl -f -` into a DISABLED pf exits 0 while enforcing
/// nothing (`engage_pf_action`'s own doc: "always load the ruleset into an
/// ENABLED pf, never an inert one") — this is the SAME reconciliation
/// [`engage_lockdown`] performs for its own `ReuseToken`/`Reenable` arms,
/// factored out here so a TUN-add or a repair reload cannot load straight
/// into whatever pf's live state happens to be, with no check.
///
/// Returns the token to load the ruleset with: reused unchanged, or freshly
/// re-enabled and re-persisted under the SAME host snapshot if pf had been
/// disabled since the state file was written.
fn reconcile_pf_enabled(
    persisted: &lockdown_state::LockdownPfState,
    state_dir: &Path,
    owner: Option<(u32, u32)>,
) -> Result<String, RoutingError> {
    let info = pfctl(&["-s", "info"], None, PHASE_COVER)?;
    let pf_enabled = parse_pf_enabled(&String::from_utf8_lossy(&info.stdout));
    match engage_pf_action(pf_enabled, true) {
        PfEngageAction::ReuseToken => Ok(persisted.pf_token.clone()),
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
            Ok(token)
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
/// On load failure the host is restored (`lockdown_disengage`) and Err returned;
/// the bridge's fail-FATAL caller aborts the start.
pub fn engage_lockdown(
    server_ip: IpAddr,
    resolver_ip: Option<IpAddr>,
    tun_name: Option<&str>,
    state_dir: &Path,
    owner: Option<(u32, u32)>,
) -> Result<Cover, RoutingError> {
    let persisted = lockdown_state::load(state_dir);

    let (token, nat_snapshot) = match &persisted {
        // Live Adopt re-engage, or a repair/TUN-add on an already-engaged
        // session: reconcile pf's enabled state against the persisted token
        // (reused unchanged if pf is still enabled, or freshly re-enabled
        // and re-persisted if a reboot reset it) — see `reconcile_pf_enabled`.
        Some(st) => (reconcile_pf_enabled(st, state_dir, owner)?, st.nat_snapshot.clone()),
        // First engage: enable + snapshot the host.
        None => {
            let token = enable_pf_capture_token()?;
            // The refcount is now held. Capture + persist may fail, so undo the
            // `-E` on any error before propagating — else the refcount leaks with
            // no state file to recover it from.
            match capture_and_persist(&token, state_dir, owner) {
                Ok(nat_snapshot) => (token, nat_snapshot),
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
        // Restore the host (snapshot reload + drop refcount) before failing, so
        // a partially-loaded ruleset never strands the host.
        lockdown_disengage(state_dir);
        return Err(RoutingError::RouteSetup(format!(
            "pfctl lockdown load failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }

    Ok(Cover {
        token,
        state_dir: state_dir.to_owned(),
        kind: CoverKind::Lockdown,
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
/// trying to add) unchanged and still fully enforced. Restoring the
/// pre-lockdown snapshot here would destroy a cover that is still live and
/// correct, just missing one permit — the exact mistake `engage_lockdown`'s
/// own restore-on-failure is right to make for a FIRST-EVER engage (nothing
/// was live yet), but wrong for this add-on-top call.
///
/// Reconciles pf's enabled state via [`reconcile_pf_enabled`] before the
/// reload — `pfctl -f -` into a DISABLED pf exits 0 while enforcing nothing,
/// so skipping this would report a connected session as covered while pf
/// enforces nothing at all.
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
    // `reconcile_pf_enabled`'s return value (the token) is not needed here —
    // Phase 0's `Cover` already carries whichever token this call's own
    // reconciliation may have refreshed (both write to the SAME state file,
    // read by any later `disengage_lockdown`/Drop, which reload it instead
    // of trusting an in-memory copy) — calling it purely for the "ensure pf
    // is enabled before this load" side effect.
    reconcile_pf_enabled(&persisted, state_dir, owner)?;
    let main = build_lockdown_main_ruleset(Some(tun_name), server_ip, resolver_ip, &persisted.nat_snapshot);
    let out = pfctl(&["-f", "-"], Some(main.as_bytes()), PHASE_COVER)?;
    if !out.status.success() {
        return Err(RoutingError::RouteSetup(format!(
            "pfctl lockdown TUN-add load failed (the Phase-0 cover is unaffected -- pfctl's reload is atomic): {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// Release an already-engaged Phase-0 guard and re-engage fresh with
/// corrected values, reloading the FULL ruleset (pf has no incremental
/// update) — reusing the SAME persisted token/nat_snapshot [`engage_lockdown`]
/// (Phase 0) already wrote, exactly like [`engage_lockdown_tun`]'s Phase-6
/// add. This deliberately does NOT reuse [`engage_lockdown`] itself: that
/// function's OWN load-failure branch calls [`lockdown_disengage`] — correct
/// for a FIRST-EVER engage (nothing valid was live before a failed load),
/// but wrong for a repair, where the OLD ruleset (this guard's pre-repair
/// permits) is still live and correct. `pfctl -f -` is atomic — a rejected
/// reload leaves that OLD ruleset unchanged and still fully enforced — so
/// calling `lockdown_disengage` here would OPEN THE HOST, destroying a cover
/// that is still live and correct just because the correction didn't land
/// (mirrors `engage_lockdown_tun`'s own reasoning for the identical
/// atomicity property).
///
/// `old` is consumed either way: on success its `token`/`state_dir` carry
/// forward unchanged (only the loaded ruleset content changed, the pf
/// enable-refcount session persists across a repair); on failure the SAME
/// `old` is handed back in the `Err` so the caller does not lose track of
/// the still-live guard.
pub fn reengage_lockdown(
    old: Cover,
    server_ip: IpAddr,
    resolver_ip: Option<IpAddr>,
    owner: Option<(u32, u32)>,
) -> Result<Cover, (RoutingError, Cover)> {
    debug_assert_eq!(
        old.kind,
        CoverKind::Lockdown,
        "reengage_lockdown only ever repairs a standing lockdown cover"
    );
    let Some(persisted) = lockdown_state::load(&old.state_dir) else {
        return Err((
            RoutingError::RouteSetup(
                "reengage_lockdown: no lockdown state on disk -- called before the Phase-0 engage".into(),
            ),
            old,
        ));
    };
    // Reconcile pf's enabled state BEFORE the reload, same as
    // `engage_lockdown_tun` -- see `reconcile_pf_enabled`'s doc. Its return
    // value (the token) is not needed here for the same reason: it already
    // wrote any refreshed token to the state file, which `lockdown_disengage`
    // and every later reconciliation read fresh from disk, never from a
    // `Cover.token` field (this cover's own `token` field is unused for the
    // Lockdown kind — see `Drop`).
    if let Err(e) = reconcile_pf_enabled(&persisted, &old.state_dir, owner) {
        return Err((e, old));
    }
    let main = build_lockdown_main_ruleset(None, server_ip, resolver_ip, &persisted.nat_snapshot);
    let out = match pfctl(&["-f", "-"], Some(main.as_bytes()), PHASE_COVER) {
        Ok(o) => o,
        Err(e) => return Err((e, old)),
    };
    if !out.status.success() {
        return Err((
            RoutingError::RouteSetup(format!(
                "pfctl lockdown repair load failed (the OLD ruleset is unaffected -- pfctl's reload is atomic): {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )),
            old,
        ));
    }
    Ok(old) // token/state_dir/kind unchanged -- only the loaded ruleset content changed
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
