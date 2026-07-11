//! Route table management — platform-specific split routing.

pub mod failclosed;
pub mod state;

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use tracing::{debug, info, warn};

use crate::error::RoutingError;
use crate::gateway::{get_default_gateway_info, GatewayInfo};

/// Total number of routing subprocess spawns this process has performed.
/// Incremented once per command in [`run_commands`]. Exposed so
/// `diagnostics` handlers and tests can assert the no-routing-subprocess
/// invariant. The one-instruction `fetch_add` has negligible production
/// cost — far below the millisecond-scale subprocess itself.
pub static ROUTING_SUBPROCESS_SPAWN_COUNT: AtomicU32 = AtomicU32::new(0);

// Command builders ====================================================================================================

/// Build the shell commands to set up split routing.
///
/// Creates four or five routes:
/// 1. `0.0.0.0/1` via TUN — captures first half of IPv4 space
/// 2. `128.0.0.0/1` via TUN — captures second half of IPv4 space
/// 3. `::/1` via TUN — captures first half of IPv6 space
/// 4. `8000::/1` via TUN — captures second half of IPv6 space
/// 5. Server bypass — `<server_ip>` via `original_gateway` (IPv4 server) or `interface_name` (IPv6 server)
///
/// The server bypass (#5) is omitted when `server_ip` is loopback (checked in
/// canonical form, so an IPv4-mapped `::ffff:127.0.0.1` counts too): a loopback
/// destination is reached via the kernel's on-link `127.0.0.0/8` route, which is
/// more specific than the `/1` splits, so it needs no bypass — and a `/32` (or
/// `/128`) gateway bypass for loopback would hijack all loopback traffic to a
/// gateway that cannot reach it.
///
/// When `server_ip` is IPv6, `original_gateway` is unused — the bypass route is interface-based
/// because reliable IPv6 gateway detection is not available on all platforms.
pub fn build_setup_commands(
    tun_name: &str,
    server_ip: IpAddr,
    original_gateway: IpAddr,
    interface_name: &str,
) -> Vec<Vec<String>> {
    platform_setup_commands(tun_name, server_ip, original_gateway, interface_name)
}

/// Build the shell commands to tear down split routing (IPv4 + IPv6 splits and server bypass).
pub fn build_teardown_commands(tun_name: &str, server_ip: IpAddr, interface_name: &str) -> Vec<Vec<String>> {
    platform_teardown_commands(tun_name, server_ip, interface_name)
}

// Execution ===========================================================================================================

// Phase tags used for structured logging and to classify expected failures.
// `is_recovery_phase` is the single source of truth for which phases are
// best-effort cleanup; adding a new `PHASE_RECOVER_*` here MUST be paired
// with a matching arm in `is_recovery_phase`.
pub(crate) const PHASE_SETUP: &str = "setup";
pub(crate) const PHASE_TEARDOWN: &str = "teardown";
pub(crate) const PHASE_RECOVER_SPLIT: &str = "recover-split";
pub(crate) const PHASE_RECOVER_BYPASS: &str = "recover-bypass";
pub(crate) const PHASE_RECOVER_COVER: &str = "recover-cover";
// macOS-only: the pf cover engages via `pfctl` subprocesses (Windows engages
// via FWPM FFI — no subprocess phase). Gated so it is not dead code on a
// non-test Windows lib build under `-D warnings`. `PHASE_RECOVER_COVER` stays
// all-targets because `is_recovery_phase` references it on every platform.
#[cfg(target_os = "macos")]
pub(crate) const PHASE_COVER: &str = "cover-engage";

/// Execute route setup commands. Logs each command and its result.
pub fn setup_routes(
    tun_name: &str,
    server_ip: IpAddr,
    original_gateway: IpAddr,
    interface_name: &str,
) -> std::io::Result<()> {
    let commands = build_setup_commands(tun_name, server_ip, original_gateway, interface_name);
    run_commands(&commands, PHASE_SETUP)
}

/// Execute route teardown commands. Idempotent — safe to call even if routes don't exist.
pub fn teardown_routes(tun_name: &str, server_ip: IpAddr, interface_name: &str) -> std::io::Result<()> {
    let commands = build_teardown_commands(tun_name, server_ip, interface_name);
    run_commands(&commands, PHASE_TEARDOWN)
}

pub(crate) fn build_split_route_teardown_commands(tun_name: &str) -> Vec<Vec<String>> {
    platform_split_route_teardown_commands(tun_name)
}

/// Returns true if route command failures during this phase are *expected*
/// idempotent-cleanup behavior and should be logged at debug, not warn.
///
/// **Recovery** is best-effort: every clean startup tries to delete the four
/// fixed split routes, and on a healthy system all four of those calls fail
/// because nothing leaked.
///
/// **Teardown** is *also* best-effort because [`setup_routes`] is NOT
/// transactional — when a setup command fails midway, the defensive
/// [`teardown_routes`] call deletes routes that were never installed
/// (empirically `netsh interface ip delete route 0.0.0.0/1 <adapter>`
/// exits non-zero when the route is absent, and the bare `route delete
/// <ip>` does the same). Real teardown failures (e.g. "adapter
/// unavailable") surface via the bridge's post-teardown
/// `Remove-NetAdapter` reporting and via state-file persistence failures.
///
/// Adding a new `PHASE_*` constant that should silently tolerate non-zero
/// exit codes MUST be paired with a matching arm here.
fn is_recovery_phase(phase: &str) -> bool {
    matches!(
        phase,
        PHASE_RECOVER_SPLIT | PHASE_RECOVER_BYPASS | PHASE_TEARDOWN | PHASE_RECOVER_COVER
    )
}

fn run_commands(commands: &[Vec<String>], phase: &str) -> std::io::Result<()> {
    let recovery = is_recovery_phase(phase);
    for cmd in commands {
        debug_assert!(!cmd.is_empty(), "route command must not be empty");
        ROUTING_SUBPROCESS_SPAWN_COUNT.fetch_add(1, Ordering::SeqCst);
        info!(phase, cmd = cmd.join(" "), "running route command");
        let output = Command::new(&cmd[0]).args(&cmd[1..]).output()?;
        let exit_code = output.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        if output.status.success() {
            // Success log at debug level. Kept out of info to avoid
            // drowning the per-run log in route noise, but visible when
            // an investigation turns on hole_bridge=debug.
            // stdout/stderr included because netsh sometimes prints a
            // non-empty stdout on success (e.g. "Ok.") that is still
            // worth having in the trace.
            debug!(phase, cmd = cmd.join(" "), exit_code,
                   stdout = %stdout.trim(), stderr = %stderr.trim(),
                   "route command succeeded");
        } else if recovery {
            // Recovery and teardown phases — see is_recovery_phase
            // doc-comment. Non-zero exits here are the unavoidable consequence
            // of non-transactional install + best-effort cleanup; warning would
            // drown legitimate signal.
            debug!(phase, cmd = cmd.join(" "), exit_code, stderr = %stderr,
                   "best-effort command failed (expected if route absent)");
        } else {
            // PHASE_SETUP only. A non-zero exit during initial route install
            // IS a real anomaly — investigate.
            warn!(phase, cmd = cmd.join(" "), exit_code,
                  stdout = %stdout.trim(), stderr = %stderr.trim(),
                  "route command failed — investigate (setup phase only)");
        }
    }
    Ok(())
}

/// Run a single command, feeding `stdin` if present and returning the full
/// `Output` so callers can parse stdout/stderr. Increments
/// [`ROUTING_SUBPROCESS_SPAWN_COUNT`] (the no-spawn invariant covers cover
/// engage too). Used by the macOS pf cover; not for route commands.
#[cfg(target_os = "macos")]
pub(crate) fn run_capturing(
    cmd: &[String],
    stdin: Option<&[u8]>,
    phase: &str,
) -> std::io::Result<std::process::Output> {
    use std::io::Write;
    use std::process::Stdio;
    debug_assert!(!cmd.is_empty(), "command must not be empty");
    ROUTING_SUBPROCESS_SPAWN_COUNT.fetch_add(1, Ordering::SeqCst);
    info!(phase, cmd = cmd.join(" "), "running cover command");
    let mut child = Command::new(&cmd[0])
        .args(&cmd[1..])
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(bytes) = stdin {
        child.stdin.take().expect("piped stdin").write_all(bytes)?;
        // stdin dropped here -> EOF to the child.
    }
    child.wait_with_output()
}

// Crash recovery ======================================================================================================

/// Clean up routes left behind by a previous run.
///
/// Called at startup **after** the IPC socket bind succeeds (so a second
/// instance can't damage the first's routing state). Removes the fixed-CIDR
/// split routes (idempotent — harmless if absent); if a [`state::RouteState`]
/// file is present in `state_dir`, also removes the server bypass route
/// described by it; finally deletes the state file. Best-effort — all errors
/// are logged at `warn` level and the function returns `()` (there is no
/// meaningful caller recovery).
pub fn recover_routes(state_dir: &Path) {
    let intent = failclosed::lockdown_state::load_enabled(state_dir);
    recover_routes_with(
        state_dir,
        run_commands,
        failclosed::recover_cover,
        intent,
        || failclosed::lockdown_cover_present(state_dir),
        |decision| failclosed::recover_lockdown(decision, state_dir),
    );
}

/// What crash-recovery should do with a possibly-present standing lockdown
/// cover, given the persisted lockdown intent and whether a cover is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverRecovery {
    /// Intent ON + cover present: KEEP the host fail-closed across the restart.
    /// The fail-closed floor (block-all + loopback + App-ID) stays in force; the
    /// volatile permits — the stale TUN-interface permit (dead LUID/utun after
    /// teardown) and the server-IP permit (the server may change before the next
    /// connect) — are refreshed by the next connect's `install_lockdown`. Windows
    /// drops the volatile GUIDs at recovery so the re-add isn't a fixed-key
    /// no-op; macOS reloads the whole pf ruleset, refreshing them implicitly.
    /// This is the crash-leak fix: a crash never runs `stop()`, so the persistent
    /// cover survives and Adopt holds it.
    Adopt,
    /// Intent OFF + cover present: fully disengage the leftover cover (Windows:
    /// delete all lockdown GUIDs; macOS: restore the pre-lockdown snapshot +
    /// drop the pf token).
    Sweep,
    /// No cover present: nothing to do.
    Noop,
}

/// Pure recovery decision. `intent` is the persisted lockdown-enabled bool
/// (`bridge-lockdown.json`); `prior_present` is whether a lockdown cover from a
/// prior run is present, keyed on the cover's OWN evidence (NOT
/// `bridge-routes.json` — the cover's lifetime is independent of routes). See
/// `recover_routes_with` for how `prior_present` is derived per platform.
pub fn decide_cover_recovery(intent: bool, prior_present: bool) -> CoverRecovery {
    match (intent, prior_present) {
        (_, false) => CoverRecovery::Noop,
        (true, true) => CoverRecovery::Adopt,
        (false, true) => CoverRecovery::Sweep,
    }
}

/// Test seam for [`recover_routes`]: accepts an injected command runner, an
/// injected transient-cover sweep, and the standing-lockdown reconciliation
/// inputs (intent + presence probe + recover action) so unit tests can assert
/// behavior without shelling out to `netsh`/`route` or touching the host
/// firewall. Production passes `run_commands`, [`failclosed::recover_cover`],
/// the persisted lockdown intent, [`failclosed::lockdown_cover_present`], and
/// [`failclosed::recover_lockdown`].
pub(crate) fn recover_routes_with<R, S, P, L>(
    state_dir: &Path,
    runner: R,
    sweep_cover: S,
    lockdown_intent: bool,
    lockdown_present: P,
    lockdown_recover: L,
) where
    R: Fn(&[Vec<String>], &str) -> std::io::Result<()>,
    S: FnOnce(&Path, bool),
    P: FnOnce() -> bool,
    L: FnOnce(CoverRecovery),
{
    info!(state_dir = %state_dir.display(), "starting route recovery");

    // Route recovery is guarded by the route-state file. Its absence means the
    // previous run installed no routes (the write-ordering contract persists
    // state BEFORE any route mutation), so we skip route teardown.
    //
    // State-file-driven recovery (not unconditional split-route teardown)
    // is required so concurrent bridge subprocesses don't rip routes out
    // from under each other: a SOCKS5-only bridge unconditionally issuing
    // `netsh delete route ... hole-tun` on startup would tear down the
    // routes of a concurrent TUN bridge mid-flight.
    if let Some(st) = state::load(state_dir) {
        info!(
            tun = %st.tun_name,
            server_ip = %st.server_ip,
            iface = %st.interface_name,
            "recovering routes from crashed run"
        );

        // 1. Split routes (IPv4 + IPv6 halves). Idempotent — harmless if
        //    absent. Runs under state-file guard so this only fires when we
        //    have positive evidence of a prior route install. Uses the TUN
        //    name persisted in the state file (the caller controls this —
        //    tun-engine has no opinion on naming).
        let split_cmds = build_split_route_teardown_commands(&st.tun_name);
        if let Err(e) = runner(&split_cmds, PHASE_RECOVER_SPLIT) {
            warn!(error = %e, "split-route teardown failed during recovery");
        }

        // 2. Per-server bypass route recorded in the state file.
        let bypass_cmds = build_teardown_commands(&st.tun_name, st.server_ip, &st.interface_name);
        if let Err(e) = runner(&bypass_cmds, PHASE_RECOVER_BYPASS) {
            warn!(error = %e, "bypass-route teardown failed during recovery");
        }

        // 3. Delete the state file regardless of command outcomes. Next
        //    startup re-runs the idempotent teardown if anything leaked
        //    past a failure.
        if let Err(e) = state::clear(state_dir) {
            warn!(error = %e, "failed to clear route-state file during recovery");
        }
    } else {
        debug!("no route-state file found, nothing to recover");
    }

    // Reconcile the standing lockdown cover FIRST. `standing_held` is the
    // lockdown cover's OWN evidence (injected probe), NOT the route-state file,
    // whose lifetime is independent of the cover. Deciding/adopting before the
    // transient sweep means the subsequent sweep can be told a standing cover is
    // held and must not clobber it. The recover action keeps the host fail-closed
    // (Adopt) or disengages (Sweep).
    let standing_held = lockdown_present();
    let decision = decide_cover_recovery(lockdown_intent, standing_held);
    let adopt = matches!(decision, CoverRecovery::Adopt);
    lockdown_recover(decision);

    // Sweep any transient fail-closed cover left by a crashed update cutover.
    // Runs UNCONDITIONALLY (outside the route-state guard above): a crash can
    // leave a cover engaged with the routes already torn down, so there is no
    // bridge-routes.json, yet the cover persists. The cover is keyed
    // independently — Windows by fixed WFP GUIDs, macOS by bridge-failclosed.json
    // — and the sweep is idempotent when no cover is present. When a standing
    // lockdown cover is being adopted, the sweep must leave the lockdown ruleset
    // untouched (macOS: skip the `pfctl -f /etc/pf.conf` reload that would wipe
    // it) — passed as `adopt`. Note this is `adopt`, NOT `standing_held`: on a
    // Sweep (intent off, cover present) the standing ruleset is being torn down,
    // so the transient restore SHOULD run.
    sweep_cover(state_dir, adopt);
}

// Routing trait =======================================================================================================

/// A cover RAII guard that can be DISARMED — consumed without disengaging — so
/// the persistent WFP/pf filters survive a cutover restart; the new bridge
/// re-adopts them via `decide_cover_recovery == Adopt`. A trait (not an inherent
/// method) because `RunningState.lockdown` holds the cover behind the
/// `Routing::Cover` associated type, and an inherent method is not callable
/// through that type parameter.
pub trait CoverGuard {
    /// Persist the underlying filters without disengaging: consume the guard so
    /// its `Drop` (the disengage) never runs.
    ///
    /// PRECONDITION: call only immediately before process exit. Skipping `Drop`
    /// also skips releasing the guard's other resources (e.g. the Windows WFP
    /// engine handle), which the kernel reclaims on exit but which a long-lived
    /// caller would leak per call.
    fn disarm(self);
}

/// OS routing: install split-tunnel routes and query routing state.
///
/// # Test-isolation contract
///
/// **All production I/O that mutates or queries the host's routing tables
/// MUST route through this trait.** Helper types whose `Drop` impls tear
/// down routes must do so through the associated [`Installed`](Self::Installed)
/// type's Drop, not by calling [`teardown_routes`] directly. The only
/// legitimate call sites of the free functions are inside this module:
/// [`SystemRouting::install`] and [`SystemRoutes::drop`] for the
/// install/teardown path, and [`recover_routes`] / [`recover_routes_with`]
/// for crash recovery.
///
/// The motivation is test isolation. Consumers (e.g. `hole_bridge::ProxyManager`)
/// are generic over `R: Routing` so unit tests can substitute a mock whose
/// `Installed` type counts teardown invocations. A helper that bypasses the
/// trait cannot be intercepted by the mock and will exercise real production
/// code from unit tests. See the bindreams/hole#165 incident.
pub trait Routing: Send + Sync {
    /// RAII guard returned by [`install`](Self::install). Dropping this
    /// value tears down the routes and clears the crash-recovery state
    /// file. The real implementation ([`SystemRoutes`]) calls
    /// [`teardown_routes`]; a mock implementation increments a counter.
    /// No production code outside `SystemRoutes` calls the free teardown
    /// function.
    type Installed: Send;

    /// Install the split routes for the given TUN device and upstream
    /// gateway. On success, returns an RAII guard whose Drop tears down
    /// the routes and clears the recovery state file. On failure, the
    /// implementation must leave the host in the pre-install state
    /// (no stale state file, no partially-installed routes).
    fn install(
        &self,
        tun_name: &str,
        server_ip: IpAddr,
        gateway: IpAddr,
        interface_name: &str,
    ) -> Result<Self::Installed, RoutingError>;

    /// Returns the current default gateway that the *next* call to
    /// [`install`](Self::install) will bypass the tunnel through.
    /// Lives on the trait (not as a free function) so mocks can stub a
    /// predictable gateway without calling the real OS — without this
    /// seam, every consumer unit test would depend on the host having a
    /// route to the Internet.
    fn default_gateway(&self) -> Result<GatewayInfo, RoutingError>;

    /// RAII guard returned by [`install_failclosed_cover`](Self::install_failclosed_cover).
    /// Dropping it disengages the fail-closed cover. `Send` so a cutover
    /// coordinator can hold it across `.await`; [`CoverGuard`] so a cutover stop
    /// can disarm it (persist-without-disengage).
    type Cover: Send + CoverGuard;

    /// Engage a fail-closed cover: block all egress except loopback, `server_ip`,
    /// and the DoH `resolver_ips`. Returns an RAII guard whose Drop disengages it.
    /// The cover survives a process crash (Windows: persistent WFP filters keyed
    /// by fixed GUID; macOS: pf enable token persisted to `bridge-failclosed.json`)
    /// and is swept by [`recover_routes`] on the next start. Does NOT permit the
    /// TUN interface — its production caller is the #553 block-until-connected
    /// connect gate, which holds it only until the tunnel comes up. The resolver
    /// permits let the connect's DoH bootstrap (and a stay-blocked retry's
    /// re-resolve) reach the configured resolvers while the cover holds.
    fn install_failclosed_cover(&self, server_ip: IpAddr, resolver_ips: &[IpAddr])
        -> Result<Self::Cover, RoutingError>;

    /// Engage the STANDING lockdown cover for this connected session: permit
    /// loopback + the `tun_name` interface + the onward server connection (and,
    /// on Windows, the `app_ids` binaries by App-ID), block all else. Returns
    /// the SAME [`Cover`](Self::Cover) RAII guard
    /// [`install_failclosed_cover`](Self::install_failclosed_cover) returns —
    /// the platform guard is kind-aware, so its Drop disengages whichever cover
    /// it holds. Distinct from `install_failclosed_cover`, which does NOT permit
    /// the TUN. The LUID is re-resolved on every call (never persisted).
    /// Fail-FATAL: the bridge aborts the start on Err.
    fn install_lockdown(
        &self,
        server_ip: IpAddr,
        tun_name: &str,
        app_ids: &[PathBuf],
    ) -> Result<Self::Cover, RoutingError>;
}

// System (production) routing =========================================================================================

/// Production implementation of [`Routing`]. Calls `setup_routes` /
/// `teardown_routes` (which shell out to `netsh`/`route`) and owns the
/// `state_dir` where `bridge-routes.json` lives for crash recovery.
pub struct SystemRouting {
    state_dir: PathBuf,
    /// uid/gid to chown persisted state files to (an elevated user-scoped run
    /// hands the real user here); `None` leaves ownership as-is.
    owner: Option<(u32, u32)>,
}

impl SystemRouting {
    pub fn new(state_dir: PathBuf, owner: Option<(u32, u32)>) -> Self {
        Self { state_dir, owner }
    }
}

impl Routing for SystemRouting {
    type Installed = SystemRoutes;
    type Cover = failclosed::Cover;

    fn install(
        &self,
        tun_name: &str,
        server_ip: IpAddr,
        gateway: IpAddr,
        interface_name: &str,
    ) -> Result<Self::Installed, RoutingError> {
        // CRITICAL ORDERING: persist the route-recovery state BEFORE any
        // routing mutation. A panic or SIGKILL between `setup_routes` and
        // `SystemRoutes` construction would otherwise leak routes with no
        // on-disk record, defeating crash recovery on next startup.
        let persisted = state::RouteState {
            version: state::SCHEMA_VERSION,
            tun_name: tun_name.to_owned(),
            server_ip,
            interface_name: interface_name.to_owned(),
        };
        state::save(&self.state_dir, &persisted, self.owner)
            .map_err(|e| RoutingError::RouteSetup(format!("failed to persist route-state: {e}")))?;

        // Install the routes. On failure, defensively tear down whatever
        // may have been partially installed and clear the stale state
        // file before returning. Defensive rollback: `run_commands`
        // currently returns `Err` only on process-spawn failure, but a
        // future early-exit-on-non-zero change would otherwise leak
        // partial routes.
        #[allow(clippy::disallowed_methods)] // we ARE the Routing impl
        if let Err(e) = setup_routes(tun_name, server_ip, gateway, interface_name) {
            #[allow(clippy::disallowed_methods)] // defensive rollback inside install
            let _ = teardown_routes(tun_name, server_ip, interface_name);
            let _ = state::clear(&self.state_dir);
            return Err(RoutingError::RouteSetup(e.to_string()));
        }

        Ok(SystemRoutes {
            tun_name: tun_name.to_owned(),
            server_ip,
            interface_name: interface_name.to_owned(),
            state_dir: self.state_dir.clone(),
        })
    }

    fn default_gateway(&self) -> Result<GatewayInfo, RoutingError> {
        get_default_gateway_info().map_err(|e| RoutingError::Gateway(e.to_string()))
    }

    fn install_failclosed_cover(
        &self,
        server_ip: IpAddr,
        resolver_ips: &[IpAddr],
    ) -> Result<Self::Cover, RoutingError> {
        failclosed::engage(server_ip, resolver_ips, &self.state_dir, self.owner)
    }

    fn install_lockdown(
        &self,
        server_ip: IpAddr,
        tun_name: &str,
        app_ids: &[PathBuf],
    ) -> Result<Self::Cover, RoutingError> {
        let resolver = failclosed::SystemLuidResolver;
        failclosed::engage_lockdown(server_ip, tun_name, &resolver, app_ids, &self.state_dir, self.owner)
    }
}

/// RAII guard returned by [`SystemRouting::install`]. Dropping this value
/// tears down the installed routes and clears the crash-recovery state
/// file. Teardown routes through the `Routing` trait, never a raw
/// free-function `netsh` call.
pub struct SystemRoutes {
    tun_name: String,
    server_ip: IpAddr,
    interface_name: String,
    state_dir: PathBuf,
}

impl Drop for SystemRoutes {
    fn drop(&mut self) {
        // Unconditional entry log so a reader can confirm this Drop
        // actually ran on Stop (teardown-skipped diagnosis).
        info!(
            tun = %self.tun_name,
            server_ip = %self.server_ip,
            iface = %self.interface_name,
            "SystemRoutes::drop entered — tearing down routes"
        );
        #[allow(clippy::disallowed_methods)] // SystemRoutes IS Routing::Installed
        if let Err(e) = teardown_routes(&self.tun_name, self.server_ip, &self.interface_name) {
            warn!(error = %e, "route teardown failed in SystemRoutes::drop");
        }
        // Always clear the state file — we only need it for *crash*
        // recovery, and reaching Drop means we took the normal shutdown
        // path. Per-command failures above are already logged; a stale
        // state file on the next run would just trigger an idempotent
        // no-op teardown during recover_routes, so clearing is safe.
        if let Err(e) = state::clear(&self.state_dir) {
            warn!(error = %e, "state-file clear failed in SystemRoutes::drop");
        }
        // Belt-and-suspenders post-teardown wintun adapter cleanup.
        // `bridge::Dispatcher::drop` synchronously drains the engine task
        // so wintun's own Drop runs; this is the safety net for paths that
        // bypass it (panic, current-thread runtime tests, Drop 2s-timeout
        // fallback). PowerShell `Remove-NetAdapter` is idempotent on
        // missing adapters. See adapter_cleanup docs.
        crate::adapter_cleanup::remove_adapter(&self.tun_name);
        // Note: WFP/NDIS post-teardown snapshots live in bridge's Stop
        // path, not here — tun-engine can't depend on the bridge's
        // diagnostics module.

        info!("SystemRoutes::drop completed");
    }
}

// Platform-specific command builders ==================================================================================

#[cfg(target_os = "windows")]
fn platform_setup_commands(
    tun_name: &str,
    server_ip: IpAddr,
    original_gateway: IpAddr,
    interface_name: &str,
) -> Vec<Vec<String>> {
    let mut cmds = vec![
        // IPv4 low half: 0.0.0.0/1 via TUN
        vec![
            "netsh".into(),
            "interface".into(),
            "ip".into(),
            "add".into(),
            "route".into(),
            "0.0.0.0/1".into(),
            tun_name.into(),
        ],
        // IPv4 high half: 128.0.0.0/1 via TUN
        vec![
            "netsh".into(),
            "interface".into(),
            "ip".into(),
            "add".into(),
            "route".into(),
            "128.0.0.0/1".into(),
            tun_name.into(),
        ],
        // IPv6 low half: ::/1 via TUN
        vec![
            "netsh".into(),
            "interface".into(),
            "ipv6".into(),
            "add".into(),
            "route".into(),
            "::/1".into(),
            tun_name.into(),
        ],
        // IPv6 high half: 8000::/1 via TUN
        vec![
            "netsh".into(),
            "interface".into(),
            "ipv6".into(),
            "add".into(),
            "route".into(),
            "8000::/1".into(),
            tun_name.into(),
        ],
    ];

    // Bypass: server IP via original gateway/interface. Skipped for loopback —
    // see `build_setup_commands` (loopback is on-link, a gateway bypass would
    // hijack it).
    if !server_ip.to_canonical().is_loopback() {
        match server_ip {
            IpAddr::V4(_) => cmds.push(vec![
                "route".into(),
                "add".into(),
                format!("{server_ip}"),
                "mask".into(),
                "255.255.255.255".into(),
                format!("{original_gateway}"),
            ]),
            IpAddr::V6(_) => cmds.push(vec![
                "netsh".into(),
                "interface".into(),
                "ipv6".into(),
                "add".into(),
                "route".into(),
                format!("{server_ip}/128"),
                interface_name.into(),
            ]),
        }
    }

    cmds
}

#[cfg(target_os = "windows")]
fn platform_teardown_commands(tun_name: &str, server_ip: IpAddr, interface_name: &str) -> Vec<Vec<String>> {
    let mut cmds = vec![
        vec![
            "netsh".into(),
            "interface".into(),
            "ip".into(),
            "delete".into(),
            "route".into(),
            "0.0.0.0/1".into(),
            tun_name.into(),
        ],
        vec![
            "netsh".into(),
            "interface".into(),
            "ip".into(),
            "delete".into(),
            "route".into(),
            "128.0.0.0/1".into(),
            tun_name.into(),
        ],
        vec![
            "netsh".into(),
            "interface".into(),
            "ipv6".into(),
            "delete".into(),
            "route".into(),
            "::/1".into(),
            tun_name.into(),
        ],
        vec![
            "netsh".into(),
            "interface".into(),
            "ipv6".into(),
            "delete".into(),
            "route".into(),
            "8000::/1".into(),
            tun_name.into(),
        ],
    ];

    // No bypass was installed for a loopback server, so none to delete.
    if !server_ip.to_canonical().is_loopback() {
        match server_ip {
            IpAddr::V4(_) => cmds.push(vec![
                "route".into(),
                "delete".into(),
                format!("{server_ip}"),
                "mask".into(),
                "255.255.255.255".into(),
            ]),
            IpAddr::V6(_) => cmds.push(vec![
                "netsh".into(),
                "interface".into(),
                "ipv6".into(),
                "delete".into(),
                "route".into(),
                format!("{server_ip}/128"),
                interface_name.into(),
            ]),
        }
    }

    cmds
}

#[cfg(target_os = "macos")]
fn platform_setup_commands(
    tun_name: &str,
    server_ip: IpAddr,
    original_gateway: IpAddr,
    interface_name: &str,
) -> Vec<Vec<String>> {
    let mut cmds = vec![
        // IPv4 low half: 0.0.0.0/1 via TUN
        vec![
            "route".into(),
            "-n".into(),
            "add".into(),
            "-net".into(),
            "0.0.0.0/1".into(),
            "-interface".into(),
            tun_name.into(),
        ],
        // IPv4 high half: 128.0.0.0/1 via TUN
        vec![
            "route".into(),
            "-n".into(),
            "add".into(),
            "-net".into(),
            "128.0.0.0/1".into(),
            "-interface".into(),
            tun_name.into(),
        ],
        // IPv6 low half: ::/1 via TUN
        vec![
            "route".into(),
            "-n".into(),
            "add".into(),
            "-inet6".into(),
            "::/1".into(),
            "-interface".into(),
            tun_name.into(),
        ],
        // IPv6 high half: 8000::/1 via TUN
        vec![
            "route".into(),
            "-n".into(),
            "add".into(),
            "-inet6".into(),
            "8000::/1".into(),
            "-interface".into(),
            tun_name.into(),
        ],
    ];

    // Bypass: server IP via original gateway/interface. Skipped for loopback —
    // see `build_setup_commands` (loopback is on-link, a gateway bypass would
    // hijack it).
    if !server_ip.to_canonical().is_loopback() {
        match server_ip {
            IpAddr::V4(_) => cmds.push(vec![
                "route".into(),
                "-n".into(),
                "add".into(),
                "-host".into(),
                format!("{server_ip}"),
                format!("{original_gateway}"),
            ]),
            IpAddr::V6(_) => cmds.push(vec![
                "route".into(),
                "-n".into(),
                "add".into(),
                "-inet6".into(),
                "-host".into(),
                format!("{server_ip}"),
                "-interface".into(),
                interface_name.into(),
            ]),
        }
    }

    cmds
}

#[cfg(target_os = "macos")]
fn platform_teardown_commands(_tun_name: &str, server_ip: IpAddr, _interface_name: &str) -> Vec<Vec<String>> {
    let mut cmds = vec![
        vec![
            "route".into(),
            "-n".into(),
            "delete".into(),
            "-net".into(),
            "0.0.0.0/1".into(),
        ],
        vec![
            "route".into(),
            "-n".into(),
            "delete".into(),
            "-net".into(),
            "128.0.0.0/1".into(),
        ],
        vec![
            "route".into(),
            "-n".into(),
            "delete".into(),
            "-inet6".into(),
            "::/1".into(),
        ],
        vec![
            "route".into(),
            "-n".into(),
            "delete".into(),
            "-inet6".into(),
            "8000::/1".into(),
        ],
    ];

    // No bypass was installed for a loopback server, so none to delete.
    if !server_ip.to_canonical().is_loopback() {
        match server_ip {
            IpAddr::V4(_) => cmds.push(vec![
                "route".into(),
                "-n".into(),
                "delete".into(),
                "-host".into(),
                format!("{server_ip}"),
            ]),
            IpAddr::V6(_) => cmds.push(vec![
                "route".into(),
                "-n".into(),
                "delete".into(),
                "-inet6".into(),
                "-host".into(),
                format!("{server_ip}"),
            ]),
        }
    }

    cmds
}

#[cfg(target_os = "windows")]
fn platform_split_route_teardown_commands(tun_name: &str) -> Vec<Vec<String>> {
    vec![
        vec![
            "netsh".into(),
            "interface".into(),
            "ip".into(),
            "delete".into(),
            "route".into(),
            "0.0.0.0/1".into(),
            tun_name.into(),
        ],
        vec![
            "netsh".into(),
            "interface".into(),
            "ip".into(),
            "delete".into(),
            "route".into(),
            "128.0.0.0/1".into(),
            tun_name.into(),
        ],
        vec![
            "netsh".into(),
            "interface".into(),
            "ipv6".into(),
            "delete".into(),
            "route".into(),
            "::/1".into(),
            tun_name.into(),
        ],
        vec![
            "netsh".into(),
            "interface".into(),
            "ipv6".into(),
            "delete".into(),
            "route".into(),
            "8000::/1".into(),
            tun_name.into(),
        ],
    ]
}

#[cfg(target_os = "macos")]
fn platform_split_route_teardown_commands(_tun_name: &str) -> Vec<Vec<String>> {
    vec![
        vec![
            "route".into(),
            "-n".into(),
            "delete".into(),
            "-net".into(),
            "0.0.0.0/1".into(),
        ],
        vec![
            "route".into(),
            "-n".into(),
            "delete".into(),
            "-net".into(),
            "128.0.0.0/1".into(),
        ],
        vec![
            "route".into(),
            "-n".into(),
            "delete".into(),
            "-inet6".into(),
            "::/1".into(),
        ],
        vec![
            "route".into(),
            "-n".into(),
            "delete".into(),
            "-inet6".into(),
            "8000::/1".into(),
        ],
    ]
}

#[cfg(test)]
#[path = "routing_tests.rs"]
mod routing_tests;
