//! Route table management — platform-specific split routing.

pub mod failclosed;
pub mod state;

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use tracing::{debug, info, warn};

use crate::error::{CommandFailure, RouteCommandError, RoutingError};
use crate::gateway::{get_default_gateway_info, GatewayInfo};

/// Total number of routing subprocess spawns this process has performed.
/// Incremented once per command executed. Exposed so
/// `diagnostics` handlers and tests can assert the no-routing-subprocess
/// invariant. The one-instruction `fetch_add` has negligible production
/// cost — far below the millisecond-scale subprocess itself.
pub static ROUTING_SUBPROCESS_SPAWN_COUNT: AtomicU32 = AtomicU32::new(0);

// Command builders ====================================================================================================

/// One route-install command plus whether its failure aborts the install.
///
/// Fatality is per command, not per phase. The IPv4 splits and the server
/// bypass are always fatal — a missing one of those sends traffic outside the
/// tunnel. The two IPv6 splits are fatal only when the upstream interface can
/// actually reach IPv6 ([`GatewayInfo::ipv6_available`]): where it cannot,
/// `netsh interface ipv6 add route` / `route add -inet6` can outright fail
/// (the adapter has no IPv6 binding — `DisabledComponents`, or an EDR policy
/// that unbinds IPv6), and a host with no IPv6 stack emits no IPv6 traffic to
/// leak. Where IPv6 IS reachable every command is fatal, because there a
/// missing `::/1` route is exactly the #901 leak.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupCommand {
    /// Program plus arguments.
    pub argv: Vec<String>,
    /// `false` means a non-zero exit is logged and the phase continues.
    pub fatal: bool,
}

impl SetupCommand {
    /// A command whose failure aborts the install.
    fn fatal(argv: Vec<String>) -> Self {
        Self { argv, fatal: true }
    }
}

/// Build the shell commands to set up split routing.
///
/// Creates four or five routes:
/// 1. `0.0.0.0/1` via TUN — captures first half of IPv4 space
/// 2. `128.0.0.0/1` via TUN — captures second half of IPv4 space
/// 3. `::/1` via TUN — captures first half of IPv6 space
/// 4. `8000::/1` via TUN — captures second half of IPv6 space
/// 5. Server bypass — `<server_ip>` via `gateway.gateway_ip` (IPv4 server) or
///    `gateway.interface_name` (IPv6 server)
///
/// Routes 3 and 4 are non-fatal when `gateway.ipv6_available` is false — see
/// [`SetupCommand`].
///
/// The server bypass (#5) is omitted when `server_ip` is loopback (checked in
/// canonical form, so an IPv4-mapped `::ffff:127.0.0.1` counts too): a loopback
/// destination is reached via the kernel's on-link `127.0.0.0/8` route, which is
/// more specific than the `/1` splits, so it needs no bypass — and a `/32` (or
/// `/128`) gateway bypass for loopback would hijack all loopback traffic to a
/// gateway that cannot reach it.
///
/// When `server_ip` is IPv6, `gateway.gateway_ip` is unused — the bypass route is
/// interface-based because reliable IPv6 gateway detection is not available on all
/// platforms.
pub fn build_setup_commands(tun_name: &str, server_ip: IpAddr, gateway: &GatewayInfo) -> Vec<SetupCommand> {
    platform_setup_commands(tun_name, server_ip, gateway)
}

/// Build the shell commands to tear down split routing (IPv4 + IPv6 splits and server bypass).
pub fn build_teardown_commands(tun_name: &str, server_ip: IpAddr, interface_name: &str) -> Vec<Vec<String>> {
    platform_teardown_commands(tun_name, server_ip, interface_name)
}

// Execution ===========================================================================================================
//
// Two phase runners with different return types: `setup_routes` below can fail
// install outright; `teardown_routes`/`recover_routes` cannot — see their doc
// comments.

mod phase_sealed {
    pub trait Sealed {}
}

/// A route-command phase. Classification is a property of the phase **type**,
/// and each runner accepts only its own type, so pairing a phase with the wrong
/// runner is a compile error rather than a convention. Sealed: the two families
/// below are the only ones.
pub(crate) trait Phase: phase_sealed::Sealed + Copy {
    /// Whether a non-zero exit in this phase is expected behavior rather than
    /// an anomaly. Picks the log level.
    const BEST_EFFORT: bool;
    /// Phase tag for structured logging.
    fn name(self) -> &'static str;
}

/// Phases whose command failures are ANOMALIES. Only [`run_setup_with`] takes
/// one; a failure aborts (unless the individual [`SetupCommand`] says
/// otherwise), because reporting routes that were never installed sends traffic
/// outside the tunnel while the UI says "protected".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FatalPhase {
    /// Initial split-route install.
    Setup,
    /// macOS pf cover engage. Runs through [`run_capturing`], not a route-command
    /// runner (Windows engages via FWPM FFI — no subprocess phase); gated so it is
    /// not dead code on a non-test Windows lib build under `-D warnings`.
    #[cfg(target_os = "macos")]
    CoverEngage,
}

/// Phases whose command failures are EXPECTED. Only [`run_cleanup_with`] takes
/// one; every command is issued and none can abort the rest, because stopping
/// at the first failure would strand routes and leave the user worse off than
/// if Hole had never run.
///
/// **Teardown** is here — not just crash recovery — because [`setup_routes`] is
/// NOT transactional: when a setup command fails midway, the defensive
/// [`teardown_routes`] call deletes routes that were never installed
/// (empirically `netsh interface ip delete route 0.0.0.0/1 <adapter>` exits
/// non-zero when the route is absent, and the bare `route delete <ip>` does the
/// same). Real teardown failures (e.g. "adapter unavailable") surface via the
/// bridge's post-teardown `Remove-NetAdapter` reporting and via state-file
/// persistence failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BestEffortPhase {
    Teardown,
    RecoverSplit,
    RecoverBypass,
    /// macOS-only, for the same reason as [`FatalPhase::CoverEngage`].
    #[cfg(target_os = "macos")]
    RecoverCover,
}

impl phase_sealed::Sealed for FatalPhase {}
impl Phase for FatalPhase {
    const BEST_EFFORT: bool = false;

    fn name(self) -> &'static str {
        match self {
            Self::Setup => "setup",
            #[cfg(target_os = "macos")]
            Self::CoverEngage => "cover-engage",
        }
    }
}

impl phase_sealed::Sealed for BestEffortPhase {}
impl Phase for BestEffortPhase {
    const BEST_EFFORT: bool = true;

    fn name(self) -> &'static str {
        match self {
            Self::Teardown => "teardown",
            Self::RecoverSplit => "recover-split",
            Self::RecoverBypass => "recover-bypass",
            #[cfg(target_os = "macos")]
            Self::RecoverCover => "recover-cover",
        }
    }
}

// Classification is fixed per type, so a runtime test of it would be vacuous.
// Pinned here instead, which also stops a copy-paste of one `impl` block onto
// the other from landing.
const _: () = assert!(!<FatalPhase as Phase>::BEST_EFFORT);
const _: () = assert!(<BestEffortPhase as Phase>::BEST_EFFORT);

/// Execute route setup commands — the FATAL phase. Stops at the first command
/// that does not exit zero and is marked fatal, and returns it; the caller must
/// not treat the split routes as installed.
pub fn setup_routes(tun_name: &str, server_ip: IpAddr, gateway: &GatewayInfo) -> Result<(), RouteCommandError> {
    let commands = build_setup_commands(tun_name, server_ip, gateway);
    run_setup_commands(&commands, FatalPhase::Setup)
}

/// Execute route teardown commands — the BEST-EFFORT phase. Idempotent, and
/// safe to call even if routes don't exist: every command is issued, and a
/// failure (routinely, "route not found") neither stops the rest nor is
/// returned.
pub fn teardown_routes(tun_name: &str, server_ip: IpAddr, interface_name: &str) -> CleanupReport {
    let commands = build_teardown_commands(tun_name, server_ip, interface_name);
    run_cleanup_commands(&commands, BestEffortPhase::Teardown)
}

pub(crate) fn build_split_route_teardown_commands(tun_name: &str) -> Vec<Vec<String>> {
    platform_split_route_teardown_commands(tun_name)
}

/// What a best-effort phase did. Deliberately NOT a `Result`: cleanup has no
/// error channel, so no caller can `?` one command's failure into skipping the
/// deletions after it. The counts are for logging and tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CleanupReport {
    /// Commands issued — always the full list the phase was handed.
    pub attempted: usize,
    /// How many did not exit zero. Routinely non-zero: a cleanup phase deletes
    /// routes that a healthy system never had.
    pub failed: usize,
}

/// Spawn one command, log it, and report whether it exited zero. The unit both
/// phase runners are built from; injected in tests so each loop's failure
/// policy is assertable without spawning.
fn exec_one<P: Phase>(cmd: &[String], phase: P) -> Result<(), CommandFailure> {
    debug_assert!(!cmd.is_empty(), "route command must not be empty");
    let phase = phase.name();
    ROUTING_SUBPROCESS_SPAWN_COUNT.fetch_add(1, Ordering::SeqCst);
    info!(phase, cmd = cmd.join(" "), "running route command");

    let output = match Command::new(&cmd[0]).args(&cmd[1..]).output() {
        Ok(output) => output,
        Err(e) => {
            // A missing `netsh`/`route` is never expected, in any phase.
            warn!(phase, cmd = cmd.join(" "), error = %e, "route command failed to spawn");
            return Err(CommandFailure::Spawn(e));
        }
    };
    let exit_code = output.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    if output.status.success() {
        // Success log at debug level. Kept out of info to avoid drowning the
        // per-run log in route noise, but visible when an investigation turns
        // on hole_bridge=debug. stdout/stderr included because netsh sometimes
        // prints a non-empty stdout on success (e.g. "Ok.") that is still
        // worth having in the trace.
        debug!(phase, cmd = cmd.join(" "), exit_code,
               stdout = %stdout.trim(), stderr = %stderr.trim(),
               "route command succeeded");
        return Ok(());
    }

    if P::BEST_EFFORT {
        // Non-zero exits here are the unavoidable consequence of
        // non-transactional install + best-effort cleanup; warning would drown
        // legitimate signal.
        debug!(phase, cmd = cmd.join(" "), exit_code, stderr = %stderr,
               "best-effort command failed (expected if route absent)");
    } else {
        // A non-zero exit during initial route install IS a real anomaly. The
        // full argv and child output land here because the returned error's
        // `Display` is deliberately PII-free. Whether it aborts the start is
        // the caller's per-command call (`SetupCommand::fatal`).
        warn!(phase, cmd = cmd.join(" "), exit_code,
              stdout = %stdout.trim(), stderr = %stderr.trim(),
              "route command failed");
    }
    Err(CommandFailure::Exit(exit_code))
}

/// FATAL phase runner. Stops at the first fatal command that does not exit
/// zero, so no further route mutation is issued after it, and returns it.
fn run_setup_commands(commands: &[SetupCommand], phase: FatalPhase) -> Result<(), RouteCommandError> {
    run_setup_with(commands, phase, exec_one::<FatalPhase>)
}

/// BEST-EFFORT phase runner. Issues EVERY command it is handed; a failure
/// neither short-circuits the rest nor is returned.
fn run_cleanup_commands(commands: &[Vec<String>], phase: BestEffortPhase) -> CleanupReport {
    run_cleanup_with(commands, phase, exec_one::<BestEffortPhase>)
}

/// Test seam for [`run_setup_commands`] — injectable per-command executor.
fn run_setup_with<F>(commands: &[SetupCommand], phase: FatalPhase, mut exec: F) -> Result<(), RouteCommandError>
where
    F: FnMut(&[String], FatalPhase) -> Result<(), CommandFailure>,
{
    for (index, cmd) in commands.iter().enumerate() {
        let Err(failure) = exec(&cmd.argv, phase) else {
            continue;
        };
        if !cmd.fatal {
            warn!(
                phase = phase.name(),
                cmd = cmd.argv.join(" "),
                %failure,
                "route command failed but is not fatal on this host — continuing"
            );
            continue;
        }
        return Err(RouteCommandError {
            program: cmd.argv.first().cloned().unwrap_or_default(),
            index,
            total: commands.len(),
            failure,
        });
    }
    Ok(())
}

/// Test seam for [`run_cleanup_commands`] — injectable per-command executor.
fn run_cleanup_with<F>(commands: &[Vec<String>], phase: BestEffortPhase, mut exec: F) -> CleanupReport
where
    F: FnMut(&[String], BestEffortPhase) -> Result<(), CommandFailure>,
{
    let mut report = CleanupReport::default();
    for cmd in commands {
        report.attempted += 1;
        if exec(cmd, phase).is_err() {
            report.failed += 1;
        }
    }
    debug!(
        phase = phase.name(),
        attempted = report.attempted,
        failed = report.failed,
        "best-effort phase complete"
    );
    report
}

/// Run a single command, feeding `stdin` if present and returning the full
/// `Output` so callers can parse stdout/stderr. Increments
/// [`ROUTING_SUBPROCESS_SPAWN_COUNT`] (the no-spawn invariant covers cover
/// engage too). Used by the macOS pf cover; not for route commands.
#[cfg(target_os = "macos")]
pub(crate) fn run_capturing<P: Phase>(
    cmd: &[String],
    stdin: Option<&[u8]>,
    phase: P,
) -> std::io::Result<std::process::Output> {
    use std::io::Write;
    use std::process::Stdio;
    debug_assert!(!cmd.is_empty(), "command must not be empty");
    ROUTING_SUBPROCESS_SPAWN_COUNT.fetch_add(1, Ordering::SeqCst);
    info!(phase = phase.name(), cmd = cmd.join(" "), "running cover command");
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
        run_cleanup_commands,
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
/// firewall. Production passes [`run_cleanup_commands`], [`failclosed::recover_cover`],
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
    R: Fn(&[Vec<String>], BestEffortPhase) -> CleanupReport,
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
        let split = runner(&split_cmds, BestEffortPhase::RecoverSplit);

        // 2. Per-server bypass route recorded in the state file.
        let bypass_cmds = build_teardown_commands(&st.tun_name, st.server_ip, &st.interface_name);
        let bypass = runner(&bypass_cmds, BestEffortPhase::RecoverBypass);
        info!(?split, ?bypass, "route recovery command phases complete");

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
    ///
    /// Takes the whole [`GatewayInfo`] that [`default_gateway`](Self::default_gateway)
    /// returned rather than destructured fields: `ipv6_available` decides which
    /// setup commands are fatal (see [`SetupCommand`]), and splitting the struct
    /// at the call site is how it got dropped on this path in the first place.
    fn install(
        &self,
        tun_name: &str,
        server_ip: IpAddr,
        gateway: &GatewayInfo,
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
    /// and (when `Some`) `resolver_ip` — the address the caller's own
    /// `ech-doh` URL names (`hole_bridge::dns::ech::EchDoh::resolver`), scoped
    /// to TCP/443 (see `crate::dns::ech::DOH_PORT`). The caller authors that
    /// URL from its own configured resolver set, so config-authorship trust
    /// alone is judged sufficient — permitting it is never a claim that this
    /// exact attempt personally dialed the address (see `EchDoh`'s doc: that
    /// additionally holds for some `PinSource` variants but not all). `None`
    /// covers every case where nothing should be permitted: no plugin
    /// configured, a non-ECH-capable plugin, malformed plugin options, or an
    /// OPERATOR's own `ech-doh` winning instead of Hole's (an address Hole
    /// did not author, so the config-authorship trust does not extend to it
    /// — a disclosed residual, see CONTRIBUTING.md). `None` is never
    /// permitted as "no restriction". See CONTRIBUTING.md's "Transient
    /// cutover cover" section for the full retry-repair state machine (a
    /// resolver drift releases and re-engages the cover with the corrected
    /// value) and the disclosed residuals this trait's caller does not
    /// close.
    ///
    /// The cover survives a process crash (Windows: persistent WFP filters keyed by fixed
    /// GUID; macOS: pf enable token persisted to `bridge-failclosed.json`) and is
    /// swept by [`recover_routes`] on the next start. Does NOT permit the TUN
    /// interface — the block-until-connected connect gate holds it only until the
    /// tunnel comes up.
    fn install_failclosed_cover(
        &self,
        server_ip: IpAddr,
        resolver_ip: Option<IpAddr>,
    ) -> Result<Self::Cover, RoutingError>;

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

    /// Clear every fail-closed cover this provider can install — both the
    /// transient block-until-connected cover and the standing lockdown cover
    /// — without asking whether either is present. See
    /// [`failclosed::release_all`] for the full contract. This is the escape
    /// from a stranded cover; a required method (no default) so every
    /// `Routing` implementation, including every test mock, commits to one.
    fn release_all_covers(&self) -> Result<(), RoutingError>;
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

    /// Test seam for [`Routing::install`]: injectable setup and teardown so unit
    /// tests can drive the failure path without issuing real route commands
    /// (#165). Production passes [`setup_routes`] / [`teardown_routes`].
    ///
    /// # What the failure path does
    ///
    /// A partially-installed route set is a real state — `setup` is not
    /// transactional. When it reports a failed command this does exactly four
    /// things, and nothing else:
    ///
    /// 1. issues no further setup commands (`setup` already stopped at the
    ///    first failure, so route mutation ends there);
    /// 2. runs the COMPLETE teardown command set, every command attempted
    ///    regardless of the others' outcomes, deleting whatever did install —
    ///    most of those deletes are expected to exit non-zero, because the
    ///    route they name was never added;
    /// 3. clears the persisted route-state file, so the next start's
    ///    crash-recovery sweep is not handed a run that left nothing behind;
    /// 4. returns `Err(RoutingError::RouteSetup)`. No [`SystemRoutes`] guard is
    ///    constructed, so no caller can report the tunnel up.
    fn install_with<S, T>(
        &self,
        tun_name: &str,
        server_ip: IpAddr,
        gateway: &GatewayInfo,
        setup: S,
        teardown: T,
    ) -> Result<SystemRoutes, RoutingError>
    where
        S: FnOnce(&str, IpAddr, &GatewayInfo) -> Result<(), RouteCommandError>,
        T: FnOnce(&str, IpAddr, &str) -> CleanupReport,
    {
        let interface_name = gateway.interface_name.as_str();
        // CRITICAL ORDERING: persist the route-recovery state BEFORE any
        // routing mutation. A panic or SIGKILL between the setup phase and
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

        if let Err(e) = setup(tun_name, server_ip, gateway) {
            warn!(error = %e, "route setup failed — rolling back");
            let rollback = teardown(tun_name, server_ip, interface_name);
            if let Err(ce) = state::clear(&self.state_dir) {
                warn!(error = %ce, "state-file clear failed during setup rollback");
            }
            info!(?rollback, "route setup rolled back — reporting the tunnel DOWN");
            return Err(RoutingError::RouteSetup(e.to_string()));
        }

        Ok(SystemRoutes {
            tun_name: tun_name.to_owned(),
            server_ip,
            interface_name: interface_name.to_owned(),
            state_dir: self.state_dir.clone(),
        })
    }
}

impl Routing for SystemRouting {
    type Installed = SystemRoutes;
    type Cover = failclosed::Cover;

    // `setup_routes`/`teardown_routes` are handed to `install_with` as the
    // production runners: this IS the `Routing` impl (#165).
    #[allow(clippy::disallowed_methods)]
    fn install(
        &self,
        tun_name: &str,
        server_ip: IpAddr,
        gateway: &GatewayInfo,
    ) -> Result<Self::Installed, RoutingError> {
        self.install_with(tun_name, server_ip, gateway, setup_routes, teardown_routes)
    }

    fn default_gateway(&self) -> Result<GatewayInfo, RoutingError> {
        get_default_gateway_info().map_err(|e| RoutingError::Gateway(e.to_string()))
    }

    fn install_failclosed_cover(
        &self,
        server_ip: IpAddr,
        resolver_ip: Option<IpAddr>,
    ) -> Result<Self::Cover, RoutingError> {
        failclosed::engage(server_ip, resolver_ip, &self.state_dir, self.owner)
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

    fn release_all_covers(&self) -> Result<(), RoutingError> {
        failclosed::release_all(&self.state_dir)
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
        let report = teardown_routes(&self.tun_name, self.server_ip, &self.interface_name);
        info!(?report, "route teardown complete");
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
fn platform_setup_commands(tun_name: &str, server_ip: IpAddr, gateway: &GatewayInfo) -> Vec<SetupCommand> {
    let ipv6 = gateway.ipv6_available;
    let mut cmds = vec![
        // IPv4 low half: 0.0.0.0/1 via TUN
        SetupCommand::fatal(vec![
            "netsh".into(),
            "interface".into(),
            "ip".into(),
            "add".into(),
            "route".into(),
            "0.0.0.0/1".into(),
            tun_name.into(),
        ]),
        // IPv4 high half: 128.0.0.0/1 via TUN
        SetupCommand::fatal(vec![
            "netsh".into(),
            "interface".into(),
            "ip".into(),
            "add".into(),
            "route".into(),
            "128.0.0.0/1".into(),
            tun_name.into(),
        ]),
        // IPv6 low half: ::/1 via TUN
        SetupCommand {
            argv: vec![
                "netsh".into(),
                "interface".into(),
                "ipv6".into(),
                "add".into(),
                "route".into(),
                "::/1".into(),
                tun_name.into(),
            ],
            fatal: ipv6,
        },
        // IPv6 high half: 8000::/1 via TUN
        SetupCommand {
            argv: vec![
                "netsh".into(),
                "interface".into(),
                "ipv6".into(),
                "add".into(),
                "route".into(),
                "8000::/1".into(),
                tun_name.into(),
            ],
            fatal: ipv6,
        },
    ];

    // Bypass: server IP via original gateway/interface. Skipped for loopback —
    // see `build_setup_commands` (loopback is on-link, a gateway bypass would
    // hijack it).
    if !server_ip.to_canonical().is_loopback() {
        let original_gateway = gateway.gateway_ip;
        match server_ip {
            IpAddr::V4(_) => cmds.push(SetupCommand::fatal(vec![
                "route".into(),
                "add".into(),
                format!("{server_ip}"),
                "mask".into(),
                "255.255.255.255".into(),
                format!("{original_gateway}"),
            ])),
            IpAddr::V6(_) => cmds.push(SetupCommand::fatal(vec![
                "netsh".into(),
                "interface".into(),
                "ipv6".into(),
                "add".into(),
                "route".into(),
                format!("{server_ip}/128"),
                gateway.interface_name.clone(),
            ])),
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
fn platform_setup_commands(tun_name: &str, server_ip: IpAddr, gateway: &GatewayInfo) -> Vec<SetupCommand> {
    let ipv6 = gateway.ipv6_available;
    let mut cmds = vec![
        // IPv4 low half: 0.0.0.0/1 via TUN
        SetupCommand::fatal(vec![
            "route".into(),
            "-n".into(),
            "add".into(),
            "-net".into(),
            "0.0.0.0/1".into(),
            "-interface".into(),
            tun_name.into(),
        ]),
        // IPv4 high half: 128.0.0.0/1 via TUN
        SetupCommand::fatal(vec![
            "route".into(),
            "-n".into(),
            "add".into(),
            "-net".into(),
            "128.0.0.0/1".into(),
            "-interface".into(),
            tun_name.into(),
        ]),
        // IPv6 low half: ::/1 via TUN
        SetupCommand {
            argv: vec![
                "route".into(),
                "-n".into(),
                "add".into(),
                "-inet6".into(),
                "::/1".into(),
                "-interface".into(),
                tun_name.into(),
            ],
            fatal: ipv6,
        },
        // IPv6 high half: 8000::/1 via TUN
        SetupCommand {
            argv: vec![
                "route".into(),
                "-n".into(),
                "add".into(),
                "-inet6".into(),
                "8000::/1".into(),
                "-interface".into(),
                tun_name.into(),
            ],
            fatal: ipv6,
        },
    ];

    // Bypass: server IP via original gateway/interface. Skipped for loopback —
    // see `build_setup_commands` (loopback is on-link, a gateway bypass would
    // hijack it).
    if !server_ip.to_canonical().is_loopback() {
        let original_gateway = gateway.gateway_ip;
        match server_ip {
            IpAddr::V4(_) => cmds.push(SetupCommand::fatal(vec![
                "route".into(),
                "-n".into(),
                "add".into(),
                "-host".into(),
                format!("{server_ip}"),
                format!("{original_gateway}"),
            ])),
            IpAddr::V6(_) => cmds.push(SetupCommand::fatal(vec![
                "route".into(),
                "-n".into(),
                "add".into(),
                "-inet6".into(),
                "-host".into(),
                format!("{server_ip}"),
                "-interface".into(),
                gateway.interface_name.clone(),
            ])),
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
