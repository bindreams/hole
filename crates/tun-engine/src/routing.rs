//! Route table management — platform-specific split routing.

pub mod failclosed;
pub mod state;

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::error::{CommandFailure, RouteCommandError, RoutingError};
use crate::gateway::{get_default_gateway_info, tun_ipv6_available, GatewayInfo};

/// Total number of routing subprocess spawns this process has performed.
/// Incremented once per command executed. Exposed so
/// `diagnostics` handlers and tests can assert the no-routing-subprocess
/// invariant. The one-instruction `fetch_add` has negligible production
/// cost — far below the millisecond-scale subprocess itself.
pub static ROUTING_SUBPROCESS_SPAWN_COUNT: AtomicU32 = AtomicU32::new(0);

// Route identity ======================================================================================================

/// One of the routes an install creates. Recorded in [`state::RouteState`] so
/// teardown and crash recovery delete only the routes this run actually
/// installed. Provenance is the only selectivity handle for the split
/// routes on both platforms and for the bypass route on macOS — no
/// delete-side qualifier can express "only if it is ours" there (see
/// CONTRIBUTING's [Route ownership](../../../CONTRIBUTING.md#route-ownership)
/// section); the Windows bypass delete can additionally be scoped by gateway
/// when one is known. Provenance is also the only handle that outlives the
/// interface a crashed or stopped run's utun took with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RouteId {
    /// `0.0.0.0/1` via the TUN — first half of IPv4 space.
    SplitV4Low,
    /// `128.0.0.0/1` via the TUN — second half of IPv4 space.
    SplitV4High,
    /// `::/1` via the TUN — first half of IPv6 space.
    SplitV6Low,
    /// `8000::/1` via the TUN — second half of IPv6 space.
    SplitV6High,
    /// Host route reaching the proxy server outside the tunnel.
    ServerBypass,
}

/// The four fixed split routes, in install order.
pub const SPLIT_ROUTES: [RouteId; 4] = [
    RouteId::SplitV4Low,
    RouteId::SplitV4High,
    RouteId::SplitV6Low,
    RouteId::SplitV6High,
];

/// `a` with every id from `b` not already present appended, preserving `a`'s
/// order. Used to keep a persisted `installed` set naming the union of "safe
/// to attempt deleting" and "fate unknown, must stay recorded" ids at every
/// checkpoint — see `rollback_and_record`.
fn union_ids(a: &[RouteId], b: &[RouteId]) -> Vec<RouteId> {
    let mut v = a.to_vec();
    for id in b {
        if !v.contains(id) {
            v.push(*id);
        }
    }
    v
}

/// The routes an install for `server_ip` attempts, in command order. The
/// server bypass is omitted for a loopback server — see
/// [`build_setup_commands`].
pub fn planned_routes(server_ip: IpAddr) -> Vec<RouteId> {
    let mut ids = SPLIT_ROUTES.to_vec();
    if !server_ip.to_canonical().is_loopback() {
        ids.push(RouteId::ServerBypass);
    }
    ids
}

// Command builders ====================================================================================================

/// One route-install command, tagged with the route it acts on (so a setup
/// command's outcome can be checkpointed against [`RouteId`]) and whether its
/// failure aborts the install.
///
/// Fatality is per command, not per phase. The IPv4 splits and the server
/// bypass are always fatal — a missing one of those sends traffic outside the
/// tunnel. The two IPv6 splits are fatal only when the TUN interface they
/// target has an IPv6 binding ([`tun_ipv6_available`]):
/// where it does not, `netsh interface ipv6 add route` / `route add -inet6`
/// on the TUN can outright fail (`DisabledComponents`, or an EDR policy that
/// unbinds IPv6 from new adapters), and a host with no IPv6 stack emits no
/// IPv6 traffic to leak. Where the TUN's IPv6 IS bound every command is
/// fatal, because there a missing `::/1` route is exactly the #901 leak.
///
/// Non-fatal means *issued and tolerated*, never omitted. A bound TUN always
/// accepts the route regardless of upstream connectivity (it is a virtual
/// device), so an unbound TUN is the only case where the command can fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupCommand {
    pub id: RouteId,
    /// Program plus arguments.
    pub argv: Vec<String>,
    /// `false` means a non-zero exit is logged and the phase continues.
    pub fatal: bool,
}

impl SetupCommand {
    /// A command whose failure aborts the install.
    fn fatal(id: RouteId, argv: Vec<String>) -> Self {
        Self { id, argv, fatal: true }
    }
}

/// A route teardown/recovery command, tagged with the route it acts on so a
/// delete's confirmation can narrow a persisted [`RouteId`] set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteCommand {
    pub id: RouteId,
    pub argv: Vec<String>,
}

impl RouteCommand {
    fn new(id: RouteId, argv: Vec<String>) -> Self {
        Self { id, argv }
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
/// Routes 3 and 4 are non-fatal when `tun_ipv6_available` is false — see
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
pub fn build_setup_commands(
    tun_name: &str,
    server_ip: IpAddr,
    gateway: &GatewayInfo,
    tun_ipv6_available: bool,
) -> Vec<SetupCommand> {
    let cmds = platform_setup_commands(tun_name, server_ip, gateway, tun_ipv6_available);
    debug_assert_eq!(
        cmds.iter().map(|c| c.id).collect::<Vec<_>>(),
        planned_routes(server_ip),
        "setup commands must match planned_routes — the state file records the latter before the former runs"
    );
    cmds
}

/// Build the shell commands to tear down split routing (IPv4 + IPv6 splits and
/// server bypass). `original_gateway`, when known, scopes the Windows IPv4
/// bypass delete — see [`platform_bypass_teardown_command`].
pub(crate) fn build_teardown_commands(
    tun_name: &str,
    server_ip: IpAddr,
    interface_name: &str,
    original_gateway: Option<IpAddr>,
) -> Vec<RouteCommand> {
    let mut cmds = platform_split_teardown_commands(tun_name);
    cmds.extend(platform_bypass_teardown_command(
        server_ip,
        interface_name,
        original_gateway,
    ));
    cmds
}

/// The split-route half of [`build_teardown_commands`] — crash recovery runs
/// it separately from the bypass so the two get distinct phase tags.
pub(crate) fn build_split_route_teardown_commands(tun_name: &str) -> Vec<RouteCommand> {
    platform_split_teardown_commands(tun_name)
}

// Execution ===========================================================================================================
//
// Two phase families with different failure semantics: FATAL (setup, macOS
// cover engage) can abort the phase outright; BEST_EFFORT (teardown, crash
// recovery) cannot — every command is attempted regardless of an earlier
// one's outcome, since a cleanup path that stops halfway is worse than one
// that reports poorly.

mod phase_sealed {
    pub trait Sealed {}
}

/// A route-command phase. Classification is a property of the phase **type**,
/// so pairing a phase with the wrong runner is a compile error rather than a
/// convention. Sealed: the two families below are the only ones.
pub(crate) trait Phase: phase_sealed::Sealed + Copy {
    /// Whether a non-zero exit in this phase is expected behavior rather than
    /// an anomaly. Picks the log level.
    const BEST_EFFORT: bool;
    /// Phase tag for structured logging.
    fn name(self) -> &'static str;
}

/// Phases whose command failures are ANOMALIES. A failure aborts the phase
/// (unless the individual [`SetupCommand`] says otherwise), because reporting
/// routes that were never installed sends traffic outside the tunnel while
/// the UI says "protected".
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

/// Phases whose command failures are EXPECTED. Every command is issued and
/// none can abort the rest — stopping at the first failure would strand
/// routes and leave the user worse off than if Hole had never run.
///
/// **Teardown** is here — not just crash recovery — because setup is NOT
/// transactional: when a setup command fails midway, the defensive teardown
/// call may be asked to delete routes that were never installed (empirically
/// `netsh interface ip delete route 0.0.0.0/1 <adapter>` exits non-zero when
/// the route is absent, and the bare `route delete <ip>` does the same).
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

// Success oracle ======================================================================================================
//
// route(8) exits 0 unconditionally even on a routing-socket failure; the
// only reliable signal is the stderr text `rtmsg()` prints. See CONTRIBUTING's
// Route ownership section for the verified mechanism. Windows' `route.exe`/
// `netsh` exit non-zero on failure, so no parsing is needed there.

/// True if macOS `route(8)`'s own text confirms the mutation went through —
/// used by [`exec_one`] to decide whether a route actually went into the
/// table, and by `test_utils::route::OwnedRoute` (same route(8) exit-0
/// problem applies to the test harness's own probe routes). Compiled outside
/// macOS too — under `cfg(test)` so the parsing logic is unit-testable on
/// every host, and under `feature = "test-utils"` for `OwnedRoute`'s
/// cross-platform `cfg!()` branch — not only where it is actually wired up.
#[cfg(any(target_os = "macos", test, feature = "test-utils"))]
pub(crate) fn macos_route_command_succeeded(output: &std::process::Output) -> bool {
    output.status.success() && !String::from_utf8_lossy(&output.stderr).contains("writing to routing socket")
}

/// True if macOS `route(8)`'s own text confirms the route is now gone — used
/// by [`exec_one`] to decide whether a delete may be dropped from the
/// persisted record, and by `test_utils::route::OwnedRoute`'s `Drop`.
/// Distinct from [`macos_route_command_succeeded`]: a delete that failed
/// because there was nothing to delete (`ESRCH`, printed as `"not in
/// table"`) still means the route is gone and may be dropped: any OTHER
/// failure text means the route is still there and must stay recorded.
///
/// `status.success()` is checked but NOT used to short-circuit to `true`:
/// route(8) exits 0 for K_DELETE whenever `newroute()` returns at all
/// (`rtmsg()`'s failure text still prints), so treating a bare exit-0 as
/// proof of absence would defeat the whole point of this function.
#[cfg(any(target_os = "macos", test, feature = "test-utils"))]
pub(crate) fn macos_route_confirmed_absent(output: &std::process::Output) -> bool {
    if !output.status.success() {
        // getaddr() aborted before rtmsg() ever ran — the command never
        // reached the kernel, so the route's fate is unchanged.
        return false;
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.contains("writing to routing socket") {
        return true; // no failure signal at all -> genuinely deleted
    }
    stderr.contains("writing to routing socket: not in table")
}

#[cfg(target_os = "macos")]
fn route_command_installed(output: &std::process::Output) -> bool {
    macos_route_command_succeeded(output)
}
#[cfg(not(target_os = "macos"))]
fn route_command_installed(output: &std::process::Output) -> bool {
    output.status.success()
}

#[cfg(target_os = "macos")]
fn route_confirmed_absent(output: &std::process::Output) -> bool {
    macos_route_confirmed_absent(output)
}
/// Windows has no text-based oracle: `route.exe`/`netsh` give no signal
/// beyond the exit code, and unlike macOS, a non-zero exit does NOT
/// unambiguously mean "already gone" — verified empirically on this box,
/// `netsh ... delete route` on an absent route and on a route requiring
/// elevation both exit 1 with no distinguishing text. Only exit 0 (a
/// definite, successful delete) confirms the route gone; a non-zero exit
/// conservatively keeps it recorded rather than risk silently dropping a
/// route that is still there — a disclosed residual, see CONTRIBUTING's
/// Route ownership section.
#[cfg(not(target_os = "macos"))]
fn route_confirmed_absent(output: &std::process::Output) -> bool {
    output.status.success()
}

/// The one site that logs a route command's argv.
///
/// Deliberately **not** hand-redacted: the argv carries the server IP and the
/// redacting log sink covers it, along with every other producer this crate
/// does not author. Extracted so recovery tests can drive the real log site
/// without spawning a subprocess.
pub(crate) fn log_route_command(phase: &str, cmd: &[String]) {
    info!(phase, cmd = cmd.join(" "), "running route command");
}

/// Spawn one command, log it, and report whether the route's state is now
/// CONFIRMED for this phase's own question — "did it go in" for the FATAL
/// install phase, "is it now gone" for every BEST_EFFORT phase (see the
/// Success-oracle section above). The unit both phase runners are built
/// from.
fn exec_one<P: Phase>(cmd: &[String], phase: P) -> Result<(), CommandFailure> {
    debug_assert!(!cmd.is_empty(), "route command must not be empty");
    let phase_name = phase.name();
    ROUTING_SUBPROCESS_SPAWN_COUNT.fetch_add(1, Ordering::SeqCst);
    log_route_command(phase_name, cmd);

    let output = match Command::new(&cmd[0]).args(&cmd[1..]).output() {
        Ok(output) => output,
        Err(e) => {
            // A missing `netsh`/`route` is never expected, in any phase.
            warn!(phase = phase_name, cmd = cmd.join(" "), error = %e, "route command failed to spawn");
            return Err(CommandFailure::Spawn(e));
        }
    };
    let exit_code = output.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    let confirmed = if P::BEST_EFFORT {
        route_confirmed_absent(&output)
    } else {
        route_command_installed(&output)
    };

    if confirmed {
        // Success log at debug level. Kept out of info to avoid drowning the
        // per-run log in route noise, but visible when an investigation turns
        // on hole_bridge=debug. stdout/stderr included because netsh sometimes
        // prints a non-empty stdout on success (e.g. "Ok.") that is still
        // worth having in the trace.
        debug!(phase = phase_name, cmd = cmd.join(" "), exit_code,
               stdout = %stdout.trim(), stderr = %stderr.trim(),
               "route command confirmed");
        return Ok(());
    }

    if P::BEST_EFFORT {
        // Non-zero exits here are the unavoidable consequence of
        // non-transactional install + best-effort cleanup; warning would drown
        // legitimate signal.
        debug!(phase = phase_name, cmd = cmd.join(" "), exit_code, stderr = %stderr,
               "best-effort command not confirmed (expected if route absent)");
    } else {
        // An unconfirmed outcome during initial route install IS a real
        // anomaly. The full argv and child output land here because the
        // returned error's `Display` is deliberately PII-free. Whether it
        // aborts the start is the caller's per-command call
        // (`SetupCommand::fatal`).
        warn!(phase = phase_name, cmd = cmd.join(" "), exit_code,
              stdout = %stdout.trim(), stderr = %stderr.trim(),
              "route command not confirmed — investigate (setup phase only)");
    }
    Err(CommandFailure::Exit(exit_code))
}

// Execute (checkpointed) ==============================================================================================
//
// Both loops below persist `installed`/`still_installed` after EVERY command,
// not once per phase or once per install — see CONTRIBUTING's
// [Route ownership](../../../CONTRIBUTING.md#route-ownership) section. The
// on-disk record is therefore never a prediction (superset or otherwise): at
// any instant, including mid-loop, it names exactly what the accumulator in
// memory names, so a crash or a later command's spawn failure narrows the
// leak window to at most the single command in flight.

/// Execute route setup commands one at a time via `runner` (production:
/// [`exec_one::<FatalPhase>`]; tests inject a scripted closure so they can
/// simulate a specific command failing without touching the host, matching
/// [`Routing`]'s test-isolation contract). `installed` accumulates the
/// [`RouteId`]s confirmed in the table; `checkpoint` is called with it
/// before AND after every command. Stops at the first FATAL command whose
/// runner call does not confirm — a non-fatal one (an IPv6 split on a TUN
/// with no IPv6 binding, see [`SetupCommand`]) is popped and skipped instead.
///
/// A pre-command checkpoint failure aborts immediately (mirrors the
/// write-before-mutate ordering contract: this codebase must not run a
/// mutation it failed to record first) and its `Err` propagates; the id is
/// popped back out first — the write never durably happened, so the command
/// is treated exactly like one that never ran. A post-command checkpoint
/// failure does not abort — the record it failed to write is a narrowing,
/// and the last successful checkpoint (naming a superset of at most one
/// extra route) still stands — so the caller is expected to log it.
///
/// On a runner `Err` for a FATAL command, the in-flight command's id is
/// likewise popped back out of `installed` before the error propagates: the
/// caller uses `installed` to decide what to roll back, and a command that
/// never confirmed must not be rolled back as if it had. The ON-DISK
/// checkpoint from just before the failed command is deliberately NOT
/// corrected to match — it still names the speculative id, which is the safe
/// superset-of-one this design accepts (see CONTRIBUTING).
pub(crate) fn setup_routes<R>(
    tun_name: &str,
    server_ip: IpAddr,
    gateway: &GatewayInfo,
    installed: &mut Vec<RouteId>,
    runner: R,
    checkpoint: impl FnMut(&[RouteId]) -> std::io::Result<()>,
) -> Result<(), RouteCommandError>
where
    R: Fn(&[String], FatalPhase) -> Result<(), CommandFailure>,
{
    let ipv6 = tun_ipv6_available(tun_name);
    let commands = build_setup_commands(tun_name, server_ip, gateway, ipv6);
    run_setup_commands(&commands, installed, runner, checkpoint)
}

/// The command-list-driven half of [`setup_routes`], split out so tests can
/// script an arbitrary [`SetupCommand`] list (real subprocess argv that never
/// touches the routing table, or a scripted per-command outcome) without
/// going through [`tun_ipv6_available`]'s real OS probe — which, against a
/// TUN name no test process ever creates, always reads "unavailable" and
/// would make the IPv6 splits silently non-fatal for every test.
fn run_setup_commands<R>(
    commands: &[SetupCommand],
    installed: &mut Vec<RouteId>,
    runner: R,
    mut checkpoint: impl FnMut(&[RouteId]) -> std::io::Result<()>,
) -> Result<(), RouteCommandError>
where
    R: Fn(&[String], FatalPhase) -> Result<(), CommandFailure>,
{
    let total = commands.len();
    for (index, cmd) in commands.iter().enumerate() {
        installed.push(cmd.id);
        if let Err(e) = checkpoint(installed) {
            installed.pop();
            return Err(RouteCommandError {
                program: cmd.argv.first().cloned().unwrap_or_default(),
                index,
                total,
                failure: CommandFailure::Spawn(e),
            });
        }
        if let Err(failure) = runner(&cmd.argv, FatalPhase::Setup) {
            installed.pop();
            if !cmd.fatal {
                // The runner already logged the exit code and child output.
                warn!(
                    cmd = cmd.argv.join(" "),
                    "route command failed but is not fatal on this host — continuing"
                );
                if let Err(e) = checkpoint(installed) {
                    warn!(error = %e, id = ?cmd.id, "failed to checkpoint route-state after non-fatal setup command");
                }
                continue;
            }
            // The phase aborts either way, but the checkpoint narrowing
            // differs by *why* the command failed. `CommandFailure::Exit`
            // means it genuinely spawned and the OS gave a confident
            // negative — narrow the checkpoint like any other
            // confirmed-not-installed route, so `install`'s `uncertain` calc
            // does not also treat it as fate-unknown. `CommandFailure::Spawn`
            // means the command never ran at all — its fate is genuinely
            // unknown, so the pre-command checkpoint's speculative superset
            // is deliberately left uncorrected (see this function's doc).
            if !matches!(failure, CommandFailure::Spawn(_)) {
                if let Err(e) = checkpoint(installed) {
                    warn!(error = %e, id = ?cmd.id, "failed to checkpoint route-state after fatal setup command");
                }
            }
            return Err(RouteCommandError {
                program: cmd.argv.first().cloned().unwrap_or_default(),
                index,
                total,
                failure,
            });
        }
        if let Err(e) = checkpoint(installed) {
            warn!(error = %e, id = ?cmd.id, "failed to checkpoint route-state after install command");
        }
    }
    Ok(())
}

/// Run one teardown/recovery command via `runner` (production:
/// [`exec_one::<BestEffortPhase>`]) and report whether the route is now
/// confirmed gone, logging the outcome either way. Shared by
/// [`run_teardown_commands`] (single-group narrowing) and [`recover_groups`]
/// (multi-group narrowing, which needs to apply one command's outcome to
/// more than one group at once and so cannot use `run_teardown_commands`'s
/// own single-`Vec` narrowing).
fn run_teardown_command<R>(cmd: &RouteCommand, phase: BestEffortPhase, runner: &R) -> bool
where
    R: Fn(&[String], BestEffortPhase) -> Result<(), CommandFailure>,
{
    match runner(&cmd.argv, phase) {
        Ok(()) => true,
        Err(e) => {
            warn!(
                phase = phase.name(),
                id = ?cmd.id,
                error = %e,
                "route-teardown command did not confirm the route is gone — keeping it recorded"
            );
            false
        }
    }
}

/// Execute route teardown/recovery commands one at a time via `runner`
/// (production: [`exec_one::<BestEffortPhase>`]; tests inject a scripted
/// closure — same test-isolation rationale as [`setup_routes`]).
/// `still_installed` starts as the ids believed installed and is narrowed as
/// each command confirms its route gone; `checkpoint` is called with the
/// narrowed value after every command. Best-effort: every command in `cmds`
/// is attempted regardless of an earlier one's outcome — there is no error
/// channel to abort through. An empty `cmds` is a plain no-op — `runner` (the
/// real subprocess spawner in production) is never called with a synthetic
/// empty argv to signal that; doing so previously panicked on the
/// unconditional `Command::new(&cmd[0])` index, reachable from crash
/// recovery on every loopback-server deployment.
fn run_teardown_commands<R>(
    cmds: &[RouteCommand],
    phase: BestEffortPhase,
    still_installed: &mut Vec<RouteId>,
    runner: R,
    mut checkpoint: impl FnMut(&[RouteId]),
) where
    R: Fn(&[String], BestEffortPhase) -> Result<(), CommandFailure>,
{
    for cmd in cmds {
        if run_teardown_command(cmd, phase, &runner) {
            still_installed.retain(|id| *id != cmd.id);
        }
        checkpoint(still_installed);
    }
}

/// Execute route teardown commands for the routes `installed` records via
/// `runner` (production: [`exec_one::<BestEffortPhase>`]), checkpointing the
/// persisted record after every command through `checkpoint`. Idempotent —
/// safe to call even if those routes are already gone. `original_gateway`
/// scopes the Windows IPv4 bypass delete to the gateway it was installed
/// under (`None` for a record migrated from schema 1/2, which never
/// persisted it — falls back to the old unscoped delete). Returns the ids
/// still believed installed when done (empty on full success) — the caller
/// decides whether to clear or keep the state file from that.
pub(crate) fn teardown_routes<R>(
    tun_name: &str,
    server_ip: IpAddr,
    interface_name: &str,
    original_gateway: Option<IpAddr>,
    installed: &[RouteId],
    runner: R,
    checkpoint: impl FnMut(&[RouteId]),
) -> Vec<RouteId>
where
    R: Fn(&[String], BestEffortPhase) -> Result<(), CommandFailure>,
{
    let cmds: Vec<RouteCommand> = build_teardown_commands(tun_name, server_ip, interface_name, original_gateway)
        .into_iter()
        .filter(|c| installed.contains(&c.id))
        .collect();
    let mut still_installed = installed.to_vec();
    run_teardown_commands(
        &cmds,
        BestEffortPhase::Teardown,
        &mut still_installed,
        runner,
        checkpoint,
    );
    still_installed
}

/// Tear down every route-provenance group in `groups` — already reduced to
/// canonical form by [`state::coalesce`] — running every group's split
/// deletes before any group's bypass delete. A split-route delete command's
/// argv is a function of `tun_name` alone, not a group's full identity, so
/// two distinct groups (e.g. carrying different `server_ip`s from different
/// sessions) can legitimately name the identical command; issuing it twice
/// would re-delete whatever claimed the freed prefix in the interim (see
/// CONTRIBUTING's Route ownership section), so each distinct split argv runs
/// at most once here and its confirmation narrows every group that named it.
/// Bypass commands embed `server_ip`, so no analogous collision is possible
/// there. `checkpoint` receives the full narrowed group list after every
/// command. Shared by [`recover_routes_with`] (primary record + `stale`) and
/// [`sweep_leftover_before_install`] (`stale` alone) — the sole place either
/// path actually spawns/scripts a teardown command.
fn recover_groups<R>(
    mut groups: Vec<state::StaleRecord>,
    runner: &R,
    mut checkpoint: impl FnMut(&[state::StaleRecord]),
) -> Vec<state::StaleRecord>
where
    R: Fn(&[String], BestEffortPhase) -> Result<(), CommandFailure>,
{
    let mut issued_split_argv: Vec<Vec<String>> = Vec::new();
    for i in 0..groups.len() {
        let cmds: Vec<RouteCommand> = build_split_route_teardown_commands(&groups[i].tun_name)
            .into_iter()
            .filter(|c| groups[i].installed.contains(&c.id) && !issued_split_argv.contains(&c.argv))
            .collect();
        for cmd in cmds {
            issued_split_argv.push(cmd.argv.clone());
            if run_teardown_command(&cmd, BestEffortPhase::RecoverSplit, runner) {
                // The command's argv is keyed on tun_name alone, so narrow
                // every group whose own split command for this id would be
                // the identical argv — not just group `i`.
                for g in &mut groups {
                    if g.installed.contains(&cmd.id) {
                        let same_route = build_split_route_teardown_commands(&g.tun_name)
                            .into_iter()
                            .any(|c| c.id == cmd.id && c.argv == cmd.argv);
                        if same_route {
                            g.installed.retain(|id| *id != cmd.id);
                        }
                    }
                }
            }
            checkpoint(&groups);
        }
    }

    for i in 0..groups.len() {
        let cmds: Vec<RouteCommand> = platform_bypass_teardown_command(
            groups[i].server_ip,
            &groups[i].interface_name,
            groups[i].original_gateway,
        )
        .into_iter()
        .filter(|c| groups[i].installed.contains(&c.id))
        .collect();
        for cmd in cmds {
            if run_teardown_command(&cmd, BestEffortPhase::RecoverBypass, runner) {
                groups[i].installed.retain(|id| *id != cmd.id);
            }
            checkpoint(&groups);
        }
    }

    groups
}

/// Sweep every not-yet-confirmed-gone route left by a prior `install` in
/// this same process — the record just loaded plus any groups already
/// carried forward by an earlier sweep — folding whatever still can't be
/// confirmed gone into `persisted.stale` instead of losing it under the
/// fresh record `install` is about to write. `persisted` must already be
/// the new session's own template (`installed: Vec::new()`, `stale:
/// Vec::new()`) — this function only ever appends to/narrows `.stale`,
/// never touches `.installed`. Every group is routed through
/// [`state::coalesce`] before anything is swept, so a leftover sharing
/// identity with an already-carried-forward group merges into it instead of
/// growing the list, and an unplannable-only group never reaches the runner.
/// See CONTRIBUTING's Route ownership section.
fn sweep_leftover_before_install<R>(
    state_dir: &Path,
    owner: Option<(u32, u32)>,
    persisted: &mut state::RouteState,
    runner: R,
) where
    R: Fn(&[String], BestEffortPhase) -> Result<(), CommandFailure>,
{
    let Some(leftover) = state::load(state_dir) else {
        return;
    };
    let mut groups = leftover.stale;
    if !leftover.installed.is_empty() {
        groups.push(state::StaleRecord {
            tun_name: leftover.tun_name,
            server_ip: leftover.server_ip,
            interface_name: leftover.interface_name,
            original_gateway: leftover.original_gateway,
            installed: leftover.installed,
        });
    }
    let groups = state::coalesce(groups);
    if groups.is_empty() {
        return;
    }

    // Record the full carried-forward set up front — a superset is always
    // safe to persist, so this cannot lose information even if the process
    // crashes before a single sweep command below runs.
    persisted.stale = groups;
    if let Err(e) = state::save(state_dir, persisted, owner) {
        warn!(error = %e, "failed to checkpoint carried-forward stale route state before install");
    }
    warn!(groups = ?persisted.stale, "sweeping route records retained from a prior run before this install");

    persisted.stale = recover_groups(std::mem::take(&mut persisted.stale), &runner, |updated| {
        persisted.stale = updated.to_vec();
        if let Err(e) = state::save(state_dir, persisted, owner) {
            warn!(error = %e, "failed to checkpoint stale-route sweep");
        }
    });
    persisted.stale.retain(|g| !g.installed.is_empty());
    if let Err(e) = state::save(state_dir, persisted, owner) {
        warn!(error = %e, "failed to checkpoint stale-route sweep result");
    }
}

/// Advance `persisted.installed` on disk, rolling the in-memory value back
/// to what it was if the write fails. `install`'s `uncertain` set is derived
/// by diffing `persisted.installed` against the runtime accumulator
/// `setup_routes` maintains — an id whose checkpoint write never durably
/// landed must not linger in `persisted.installed`, or a write that never
/// happened reads as "durably recorded, fate unknown" instead of "never
/// happened" (see `setup_routes`'s own doc on pre-command checkpoint
/// failure).
fn checkpoint_installed(
    persisted: &mut state::RouteState,
    state_dir: &Path,
    owner: Option<(u32, u32)>,
    ids: &[RouteId],
) -> std::io::Result<()> {
    let prev = std::mem::replace(&mut persisted.installed, ids.to_vec());
    state::save(state_dir, persisted, owner).inspect_err(|_| persisted.installed = prev)
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
/// described by it; finally deletes the state file. Route errors are
/// best-effort and logged at `warn`.
///
/// Returns the standing-lockdown [`Recovery`] so the caller can record
/// "a standing cover is live this run" — the claim that keeps the escape
/// visible when the intent file cannot be read or repaired.
///
/// `owner` is the uid/gid every other bridge write into `state_dir` threads
/// (`SystemRouting::new`, `ProxyManager::set_lockdown_intent`). Recovery's
/// intent repair may CREATE both the directory and `bridge-lockdown.json` — a
/// wiped state dir is exactly the condition that produces the `Unset` intent —
/// so without it a user-scoped macOS bridge drops root-owned files into
/// `~/Library/Application Support/hole`.
///
/// `tun_name` is the caller's own configured TUN device name (the bridge's
/// `TUN_DEVICE_NAME` constant) — the fallback the TUN-permit reclaim uses when
/// no `bridge-routes.json` survived this startup to name one. See
/// [`recover_routes_with`]'s doc for why the file alone cannot be the only
/// source.
pub fn recover_routes(state_dir: &Path, owner: Option<(u32, u32)>, tun_name: &str) -> Recovery {
    let intent = failclosed::lockdown_state::load_intent(state_dir);
    recover_routes_with(
        state_dir,
        owner,
        tun_name,
        exec_one::<BestEffortPhase>,
        failclosed::recover_cover,
        intent,
        || failclosed::lockdown_cover_presence(state_dir),
        |decision, tun_name| failclosed::recover_lockdown(decision, state_dir, tun_name),
    )
}

/// What crash-recovery should do with a possibly-present standing lockdown
/// cover, given the recorded intent and what the OS says is installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverRecovery {
    /// A standing cover is live and nothing recorded says to remove it: KEEP
    /// the host fail-closed across the restart. Performs **no OS call that
    /// could clobber a RUNNING first bridge's cover** — its whole effect is
    /// that the bridge records "a standing cover is live this run", so the
    /// next connect re-engages through `install_lockdown`, which refreshes
    /// the volatile permits (the dead TUN LUID/utun and the possibly-changed
    /// server IP) itself.
    ///
    /// The one exception, Windows only: it also reclaims the volatile
    /// TUN-LUID permit pair when `hole-tun` no longer resolves — see
    /// `failclosed::reclaim_stale_tun_permit`. That is safe where deleting the
    /// server permit here is not: a genuinely running bridge's own `hole-tun`
    /// resolves successfully, so the reclaim can never touch a live bridge's
    /// permit, whereas the server IP has no equivalent liveness check.
    ///
    /// Disclosed cost of the remaining inertness: between an adopted cover and
    /// the next connect the stale server-IP permit stays installed rather than
    /// being dropped immediately (and, until `hole-tun` is confirmed gone, so
    /// does the TUN-LUID permit). Both are *permits* on an idle cover, and the
    /// App-ID permit already grants the bridge and plugin binaries unrestricted
    /// egress in that same window, so the added surface is one
    /// previously-configured server IP for other processes while nothing is
    /// connected. The alternative — deleting the server permit at recovery
    /// time — would let a second bridge with a fresh state dir delete a
    /// RUNNING first bridge's server permit while block-all stayed in force.
    ///
    /// This is also the crash-leak fix: a crash never runs `stop()`, so the
    /// persistent cover survives and Adopt holds it.
    Adopt,
    /// [`Intent::Off`](failclosed::lockdown_state::Intent::Off) with an
    /// actionable presence: fully disengage the leftover cover (Windows: delete
    /// all lockdown GUIDs; macOS: restore the pre-lockdown snapshot + drop the
    /// pf token). The only action that removes protection, and the only one
    /// that mutates the OS at all.
    Sweep,
    /// Nothing to do.
    Noop,
}

/// What the OS says about a standing lockdown cover — the presence axis of
/// [`decide_cover_recovery`]. Closed, because a bool made "the OS says no" and
/// "the OS could not answer" the same answer, and the second must never
/// authorise removing protection.
///
/// Each platform produces a strict subset:
///
/// - **Windows** produces `Live`, `Absent`, `Indeterminate`, `Unreachable`. It keeps no lockdown state file, so `Recorded` has no source there.
/// - **macOS** produces `Live`, `Recorded`, `Absent`, `Unreachable`. A `pfctl` that runs and prints a labels listing always yields a usable answer, so `Indeterminate` has no source there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverPresence {
    /// The OS confirmed Hole's own standing-lockdown cover, **or a residue of
    /// it**, is installed right now.
    ///
    /// "Any residue", not "the whole cover", is deliberate: the Windows sweeps
    /// loop delete-by-key over every lockdown GUID with no transaction and
    /// every return code discarded, over PERSISTENT filters. A sweep
    /// interrupted mid-loop survives a reboot as a partial cover, so probing
    /// one GUID would let that partial cover answer `Absent` forever. The probe
    /// asks about every swept GUID and `Live` means at least one was found.
    Live,
    /// The OS did not confirm one, but Hole's own state file says a cover was
    /// engaged and never confirmed released.
    Recorded,
    /// The OS was asked, answered no, and no local record contradicts it.
    Absent,
    /// The OS was reachable but its answer was unusable (Windows: a by-key
    /// query returned a code that is neither success nor "filter not found",
    /// e.g. a DACL-denied read).
    Indeterminate,
    /// The OS could not be asked at all (Windows: the Base Filtering Engine
    /// could not be reached; macOS: `pfctl` missing or non-executable with no
    /// state file to fall back on).
    Unreachable,
}

/// The outcome of [`decide_cover_recovery`]: one action, plus whether the
/// measured truth should be written back to the intent file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recovery {
    pub action: CoverRecovery,
    /// Repair the intent file to `enabled: true` before acting. Grounded in a
    /// positive OS measurement only — see rule 4.
    pub record_intent_on: bool,
    /// Echoes the `presence` this decision was made from. `action == Adopt`
    /// alone is not evidence the OS confirmed a live cover — it also covers
    /// [`CoverPresence::Recorded`] and [`CoverPresence::Indeterminate`], whose
    /// own docs say the OS did NOT confirm one. A caller recording "this run
    /// holds a live cover" (`route_recovery::recover_and_record`) must gate on
    /// `presence == CoverPresence::Live`, not on the action alone.
    pub presence: CoverPresence,
}

/// Pure recovery decision over the two measured axes. Performs **no I/O**: it
/// picks one [`CoverRecovery`], sets `record_intent_on`, and returns.
///
/// The four rules the table below encodes:
///
/// 1. [`CoverPresence::Absent`] and [`CoverPresence::Unreachable`] always yield `Noop` with `record_intent_on = false`.
/// 2. `Sweep` requires [`Intent::Off`](failclosed::lockdown_state::Intent::Off) and an actionable presence (`Live | Recorded | Indeterminate`). It is the only action that removes protection, and the only one that mutates the OS at all.
/// 3. `Adopt` requires an actionable presence and an intent of `On`, `Unreadable`, or `Unset` — with `Unset` additionally requiring positive evidence (`Live | Recorded`), because an unknown intent plus an unusable OS answer is no evidence in any direction.
/// 4. `record_intent_on` requires `Presence::Live` and an intent of `Unset` or `Unreadable`. The write is grounded in a positive OS measurement, never inferred.
///
/// The match is exhaustive on both axes with no wildcard, so a new variant of
/// either is a compile error rather than a silently inherited answer.
pub fn decide_cover_recovery(intent: failclosed::lockdown_state::Intent, presence: CoverPresence) -> Recovery {
    use failclosed::lockdown_state::Intent as I;
    use CoverPresence as P;
    use CoverRecovery::{Adopt, Noop, Sweep};

    let (action, record_intent_on) = match (intent, presence) {
        (I::On, P::Live) => (Adopt, false),
        (I::On, P::Recorded) => (Adopt, false),
        (I::On, P::Indeterminate) => (Adopt, false),
        (I::On, P::Absent) => (Noop, false),
        (I::On, P::Unreachable) => (Noop, false),

        (I::Off, P::Live) => (Sweep, false),
        (I::Off, P::Recorded) => (Sweep, false),
        (I::Off, P::Indeterminate) => (Sweep, false),
        (I::Off, P::Absent) => (Noop, false),
        (I::Off, P::Unreachable) => (Noop, false),

        (I::Unset, P::Live) => (Adopt, true),
        (I::Unset, P::Recorded) => (Adopt, false),
        // No intent AND no usable OS answer is no evidence in any direction.
        (I::Unset, P::Indeterminate) => (Noop, false),
        (I::Unset, P::Absent) => (Noop, false),
        (I::Unset, P::Unreachable) => (Noop, false),

        (I::Unreadable, P::Live) => (Adopt, true),
        (I::Unreadable, P::Recorded) => (Adopt, false),
        (I::Unreadable, P::Indeterminate) => (Adopt, false),
        (I::Unreadable, P::Absent) => (Noop, false),
        (I::Unreadable, P::Unreachable) => (Noop, false),
    };
    Recovery {
        action,
        record_intent_on,
        presence,
    }
}

/// Test seam for [`recover_routes`]: accepts an injected per-command route
/// runner, an injected transient-cover sweep, and the standing-lockdown
/// reconciliation inputs (intent + presence probe + recover action) so unit
/// tests can assert behavior without shelling out to `netsh`/`route` or
/// touching the host firewall. Production passes [`exec_one::<BestEffortPhase>`],
/// [`failclosed::recover_cover`], the classified lockdown intent,
/// [`failclosed::lockdown_cover_presence`], and [`failclosed::recover_lockdown`].
/// `owner` is passed straight through to the intent repair — see
/// [`recover_routes`].
///
/// `tun_name` is the fallback TUN-permit-reclaim hint: `bridge-routes.json`'s
/// own `tun_name` wins when a route-state file was recovered THIS startup, but
/// that file's lifetime is anti-correlated with the condition the reclaim
/// needs — `SystemRoutes::drop` clears it on every CLEAN teardown, including
/// the `Cutover` stop that precedes the canonical Adopt path, so the file is
/// present exactly when the adapter probably still resolves and absent
/// exactly when it definitely does not. Falling back to the caller's own
/// configured name keeps the reclaim reachable on that path too; the resolve
/// check inside `should_reclaim_tun_permit` is what makes deleting on a
/// guessed name safe — a live `hole-tun` still blocks it.
#[allow(clippy::too_many_arguments)] // private test seam — bundling into a struct adds more noise than the warning.
pub(crate) fn recover_routes_with<R, S, P, L>(
    state_dir: &Path,
    owner: Option<(u32, u32)>,
    tun_name: &str,
    runner: R,
    sweep_cover: S,
    lockdown_intent: failclosed::lockdown_state::Intent,
    lockdown_present: P,
    lockdown_recover: L,
) -> Recovery
where
    R: Fn(&[String], BestEffortPhase) -> Result<(), CommandFailure>,
    S: FnOnce(&Path, bool),
    P: FnOnce() -> CoverPresence,
    L: FnOnce(CoverRecovery, Option<&str>),
{
    info!(state_dir = %state_dir.display(), "starting route recovery");

    // Route recovery is guarded by the route-state file. Its absence means the
    // previous run installed no routes (the write-ordering contract persists
    // state BEFORE any route mutation), so we skip route teardown. Loaded once
    // and kept: its `tun_name` (when present) is also this bridge's own record
    // of which TUN device the standing lockdown cover, if any, was built for —
    // see the reclaim call below.
    //
    // State-file-driven recovery (not unconditional split-route teardown)
    // is required so concurrent bridge subprocesses don't rip routes out
    // from under each other: a SOCKS5-only bridge unconditionally issuing
    // `netsh delete route ... hole-tun` on startup would tear down the
    // routes of a concurrent TUN bridge mid-flight.
    let route_state = state::load(state_dir);
    if let Some(loaded) = route_state.clone() {
        let tun_name = loaded.tun_name.clone();
        let server_ip = loaded.server_ip;
        let interface_name = loaded.interface_name.clone();
        let original_gateway = loaded.original_gateway;

        // Merge the primary record and every carried-forward `stale` group
        // into one canonical set before anything runs. `state::coalesce`
        // merges groups sharing an identity (so a stale group matching the
        // primary's own emits no duplicate command), sanitizes each against
        // `planned_routes(server_ip)` (an id with no possible teardown
        // command can never drain, so it would pin the state file open
        // forever), and drops an empty survivor.
        let primary_group = state::StaleRecord {
            tun_name: tun_name.clone(),
            server_ip,
            interface_name: interface_name.clone(),
            original_gateway,
            installed: loaded.installed,
        };
        let mut all_groups = loaded.stale;
        all_groups.push(primary_group);
        let canonical = state::coalesce(all_groups);

        info!(
            tun = %tun_name,
            %server_ip,
            iface = %interface_name,
            groups = ?canonical,
            "recovering routes from crashed run"
        );

        // A canonical group's `installed` is written back to
        // `persisted.installed` (the schema's fixed primary slot) if its
        // identity matches the record's own top-level fields, else to
        // `persisted.stale` — merging can only ever produce one canonical
        // group per identity, so at most one group ever matches.
        let is_primary = |g: &state::StaleRecord| {
            g.tun_name == tun_name
                && g.server_ip == server_ip
                && g.interface_name == interface_name
                && g.original_gateway == original_gateway
        };

        let mut persisted = state::RouteState {
            version: state::SCHEMA_VERSION,
            tun_name: tun_name.clone(),
            server_ip,
            interface_name: interface_name.clone(),
            original_gateway,
            installed: Vec::new(),
            stale: Vec::new(),
        };

        // `recover_groups` runs every group's split deletes before any
        // group's bypass delete, deduping a split command that two distinct
        // groups would otherwise both emit (splits are keyed on `tun_name`
        // alone) — see `recover_groups`'s own doc.
        let final_groups = recover_groups(canonical, &runner, |groups| {
            let (primary, stale): (Vec<_>, Vec<_>) = groups.iter().cloned().partition(is_primary);
            persisted.installed = primary.into_iter().next().map(|g| g.installed).unwrap_or_default();
            persisted.stale = stale;
            if let Err(e) = state::save(state_dir, &persisted, owner) {
                warn!(error = %e, "failed to checkpoint route-state during recovery — recorded routes may be stale if this process now crashes");
            }
        });

        let (primary, mut stale): (Vec<_>, Vec<_>) = final_groups.into_iter().partition(is_primary);
        let still_installed = primary.into_iter().next().map(|g| g.installed).unwrap_or_default();
        stale.retain(|g| !g.installed.is_empty());
        persisted.installed = still_installed.clone();
        persisted.stale = stale;

        // Clear the state file once nothing remains unaccounted for,
        // primary record and every stale group alike. The checkpoints
        // above already persisted the narrowed values after every
        // command, so a non-empty remainder is already recorded — the
        // next startup's recovery will retry exactly those ids.
        if still_installed.is_empty() && persisted.stale.is_empty() {
            if let Err(e) = state::clear(state_dir) {
                warn!(error = %e, "failed to clear route-state file during recovery");
            }
        } else {
            if let Err(e) = state::save(state_dir, &persisted, owner) {
                warn!(error = %e, "failed to checkpoint route-state after recovery's stale-group sweep");
            }
            warn!(
                remaining = ?still_installed,
                stale = ?persisted.stale,
                "routes may still be leaked; left recorded for the next start's recovery"
            );
        }
    } else {
        debug!("no route-state file found, nothing to recover");
    }
    let tun_name_hint = route_state.map(|st| st.tun_name).unwrap_or_else(|| tun_name.to_owned());

    // Reconcile the standing lockdown cover FIRST. The presence is the
    // lockdown cover's OWN evidence (injected probe), NOT the route-state file,
    // whose lifetime is independent of the cover. Deciding/adopting before the
    // transient sweep means the subsequent sweep can be told a standing cover is
    // held and must not clobber it. The recover action keeps the host fail-closed
    // (Adopt) or disengages (Sweep).
    let presence = lockdown_present();
    let decision = decide_cover_recovery(lockdown_intent, presence);
    // Repair BEFORE acting, so a crash in between leaves an intent that reads
    // armed rather than one the next start would sweep on. A failed write costs
    // the persisted preference, never the action or the escape: this run's
    // adopted-cover claim carries the escape, and the bridge retries the write
    // the moment it honours that claim with a real cover install (see
    // `promote_adopted_claim`). Re-deriving it on a LATER start is not a
    // fallback — once the cover is torn down the measurement reads `Absent`.
    if decision.record_intent_on {
        if let Err(e) = failclosed::lockdown_state::set_enabled(state_dir, true, owner) {
            warn!(error = %e, "could not repair the lockdown intent over a measured live cover");
        }
    }
    let adopt = matches!(decision.action, CoverRecovery::Adopt);
    // `tun_name_hint` prefers THIS bridge's own last-known TUN device (from its
    // own `bridge-routes.json`) and falls back to the caller-supplied
    // `tun_name` otherwise — see this function's doc for why the file alone
    // is not a safe gate. `TUN_DEVICE_NAME` is a compile-time constant shared
    // by every install, so the fallback names the same device a different
    // install's cover would too; only the reclaim's server-IP counterpart is
    // scoped by the per-install identity gap CONTRIBUTING.md discloses
    // (#878), and this reclaim never touches that permit.
    lockdown_recover(decision.action, Some(tun_name_hint.as_str()));

    // Sweep any transient fail-closed cover left by a crashed update cutover.
    // Runs UNCONDITIONALLY (outside the route-state guard above): a crash can
    // leave a cover engaged with the routes already torn down, so there is no
    // bridge-routes.json, yet the cover persists. The cover is keyed
    // independently — Windows by fixed WFP GUIDs, macOS by bridge-failclosed.json
    // — and the sweep is idempotent when no cover is present. When a standing
    // lockdown cover is being adopted, the sweep must leave the lockdown ruleset
    // untouched (macOS: skip the `pfctl -f /etc/pf.conf` reload that would wipe
    // it) — passed as `adopt`. Note this is `adopt`, NOT the raw presence: on a
    // Sweep (intent off, cover present) the standing ruleset is being torn down,
    // so the transient restore SHOULD run.
    sweep_cover(state_dir, adopt);

    decision
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
    /// (no stale state file, no partially-installed routes) — unless it
    /// could not run the rollback commands at all, in which case it keeps a
    /// state file naming exactly the routes it did install, so the next
    /// start's recovery removes them.
    ///
    /// Takes the whole [`GatewayInfo`] that [`default_gateway`](Self::default_gateway)
    /// returned (not destructured fields): `gateway_ip`/`interface_name` build
    /// the server bypass route. IPv6 split-route fatality is decided
    /// separately, from the TUN's own IPv6 binding, not from anything on this
    /// struct — see [`SetupCommand`].
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

    /// Best-effort delete of `confirmed` (the only ids ever safe to attempt —
    /// never an unconfirmed/speculative one, which might belong to someone
    /// else) via [`teardown_routes`], then persist the leftover: whatever
    /// teardown could not confirm gone, unioned with `extra_unconfirmed` (ids
    /// whose install outcome is simply unknown — e.g. a spawn failure
    /// mid-command — which must stay recorded even though deleting them is
    /// not safe). The union is seeded on disk BEFORE the first delete runs,
    /// and every checkpoint during the loop re-applies it — `extra_unconfirmed`
    /// must never be absent from the record at any instant (see
    /// `teardown_routes`'s own write-ordering contract). Only ever touches
    /// `persisted.installed` — `persisted.stale` (leftovers from an earlier
    /// `install` in this process) passes through untouched, so clearing
    /// checks both. Clears the state file only once nothing remains either
    /// way. `runner` production: [`exec_one::<BestEffortPhase>`]; test-injectable
    /// so a test can observe the on-disk record between delete commands.
    #[allow(clippy::too_many_arguments)] // rollback is inherently multi-identity + multi-outcome; a struct would only rename these
    fn rollback_and_record<R>(
        &self,
        tun_name: &str,
        server_ip: IpAddr,
        interface_name: &str,
        confirmed: &[RouteId],
        mut persisted: state::RouteState,
        extra_unconfirmed: Vec<RouteId>,
        runner: R,
    ) where
        R: Fn(&[String], BestEffortPhase) -> Result<(), CommandFailure>,
    {
        persisted.installed = union_ids(confirmed, &extra_unconfirmed);
        if let Err(e) = state::save(&self.state_dir, &persisted, self.owner) {
            warn!(error = %e, "failed to checkpoint route-state before install rollback — recorded routes may be stale if this process now crashes");
        }

        #[allow(clippy::disallowed_methods)] // defensive rollback inside install — we ARE the Routing impl
        let remaining = teardown_routes(
            tun_name,
            server_ip,
            interface_name,
            persisted.original_gateway,
            confirmed,
            runner,
            |ids| {
                persisted.installed = union_ids(ids, &extra_unconfirmed);
                if let Err(e) = state::save(&self.state_dir, &persisted, self.owner) {
                    warn!(error = %e, "failed to checkpoint route-state during install rollback — recorded routes may be stale if this process now crashes");
                }
            },
        );
        let final_remaining = union_ids(&remaining, &extra_unconfirmed);
        // Clearing needs BOTH this attempt's own remainder AND any
        // carried-forward `stale` groups (leftovers from an earlier
        // `install` in this process, untouched by this function) drained —
        // clearing while `stale` is non-empty would destroy the only record
        // of that separate leak.
        if final_remaining.is_empty() && persisted.stale.is_empty() {
            if let Err(e) = state::clear(&self.state_dir) {
                warn!(error = %e, "failed to clear route-state after rollback — a stale record will trigger a redundant idempotent teardown next start");
            }
        } else {
            persisted.installed = final_remaining.clone();
            if let Err(e) = state::save(&self.state_dir, &persisted, self.owner) {
                warn!(error = %e, "failed to record the retained route-state after rollback — routes may leak untracked");
            }
            warn!(
                remaining = ?final_remaining,
                stale = ?persisted.stale,
                "routes may be leaked; left recorded for the next start's recovery"
            );
        }
    }
}

impl Routing for SystemRouting {
    type Installed = SystemRoutes;
    type Cover = failclosed::Cover;

    fn install(
        &self,
        tun_name: &str,
        server_ip: IpAddr,
        gateway: &GatewayInfo,
    ) -> Result<Self::Installed, RoutingError> {
        #[allow(clippy::disallowed_methods)] // we ARE the Routing impl
        self.install_with(
            tun_name,
            server_ip,
            gateway,
            exec_one::<FatalPhase>,
            exec_one::<BestEffortPhase>,
        )
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

impl SystemRouting {
    /// Test seam for [`Routing::install`]: injectable per-command setup/
    /// teardown runners (the same shape [`exec_one`] has) so unit tests can
    /// drive the failure/rollback path without issuing real route commands
    /// (#165), while still exercising the REAL per-command checkpointing —
    /// unlike a whole-phase seam, this cannot silently skip it. Production
    /// passes [`exec_one::<FatalPhase>`]/[`exec_one::<BestEffortPhase>`] —
    /// see [`Routing::install`].
    ///
    /// # What the failure path does
    ///
    /// A partially-installed route set is a real state — `setup_routes` is not
    /// transactional. When it reports a failed command this does exactly four
    /// things, and nothing else:
    ///
    /// 1. issues no further setup commands (`setup_routes` already stopped at
    ///    the first FATAL failure, so route mutation ends there — a non-fatal
    ///    one, an IPv6 split on a TUN with no IPv6 binding, does not reach this
    ///    path at all);
    /// 2. runs teardown narrowed to exactly the [`RouteId`]s the per-command
    ///    checkpointing confirmed installed (`rollback_and_record`), never the
    ///    full planned set — deleting a route this run never confirmed going in
    ///    is never safe, see [Route ownership](../../../CONTRIBUTING.md#route-ownership);
    /// 3. clears the persisted route-state file ONLY once nothing remains
    ///    unconfirmed — a command whose fate is genuinely unknown (a spawn
    ///    failure, or teardown itself not confirming a delete) stays recorded
    ///    for the next start's crash recovery to retry, exactly as
    ///    [Route ownership](../../../CONTRIBUTING.md#route-ownership) describes;
    /// 4. returns `Err(RoutingError::RouteSetup)`. No [`SystemRoutes`] guard is
    ///    constructed, so no caller can report the tunnel up.
    fn install_with<Rs, Rt>(
        &self,
        tun_name: &str,
        server_ip: IpAddr,
        gateway: &GatewayInfo,
        setup_runner: Rs,
        teardown_runner: Rt,
    ) -> Result<SystemRoutes, RoutingError>
    where
        Rs: Fn(&[String], FatalPhase) -> Result<(), CommandFailure>,
        Rt: Fn(&[String], BestEffortPhase) -> Result<(), CommandFailure> + Copy,
    {
        let interface_name = gateway.interface_name.as_str();
        // Checkpoint template: `setup_routes` calls `checkpoint(ids)` before
        // AND after every route command, so `persisted.installed` — and the
        // on-disk file it writes — is never a prediction. At any instant it
        // names exactly what `installed` below names, so a crash narrows the
        // leak window to at most the single command in flight. See
        // CONTRIBUTING's Route ownership section. Built BEFORE the sweep below
        // (not after) so the sweep can layer carried-forward debt into
        // `persisted.stale` instead of this install's own first checkpoint
        // racing it for the same on-disk slot.
        let mut persisted = state::RouteState {
            version: state::SCHEMA_VERSION,
            tun_name: tun_name.to_owned(),
            server_ip,
            interface_name: interface_name.to_owned(),
            original_gateway: Some(gateway.gateway_ip),
            installed: Vec::new(),
            stale: Vec::new(),
        };

        // Sweep any record a PRIOR run in THIS SAME PROCESS left retained
        // (an unconfirmed teardown/rollback), including debt already carried
        // forward by an earlier sweep. `recover_routes` only runs once per
        // process start, not once per tunnel start — a long-lived bridge
        // process reconnecting must retry this itself. Whatever still can't
        // be confirmed gone lands in `persisted.stale`, never dropped.
        sweep_leftover_before_install(&self.state_dir, self.owner, &mut persisted, teardown_runner);

        let mut installed = Vec::new();
        #[allow(clippy::disallowed_methods)] // install_with IS SystemRouting::install's implementation
        let setup_result = setup_routes(tun_name, server_ip, gateway, &mut installed, setup_runner, |ids| {
            checkpoint_installed(&mut persisted, &self.state_dir, self.owner, ids)
        });
        // Whatever the last checkpoint durably wrote (see
        // `checkpoint_installed`) but `installed` no longer names (popped
        // after a runner failure — see `setup_routes`'s doc): an id whose
        // fate is genuinely unknown, not merely "not installed". Must stay
        // recorded even though it's not safe to attempt deleting (see
        // `rollback_and_record`).
        let uncertain: Vec<RouteId> = persisted
            .installed
            .iter()
            .copied()
            .filter(|id| !installed.contains(id))
            .collect();

        if let Err(e) = setup_result {
            self.rollback_and_record(
                tun_name,
                server_ip,
                interface_name,
                &installed,
                persisted,
                uncertain,
                teardown_runner,
            );
            return Err(RoutingError::RouteSetup(e.to_string()));
        }

        // A route whose command ran but did not confirm going in (e.g.
        // another process holds that prefix) is popped from `installed` by
        // `setup_routes`, so setup_result can be `Ok` with `installed` a
        // strict subset of what was planned. A degraded tunnel is worse than
        // no tunnel (Rule #0): the user believes traffic is captured when
        // some of it is not. Roll back and fail closed rather than return a
        // partial connect as success.
        let planned = planned_routes(server_ip);
        if installed.len() != planned.len() {
            let missing: Vec<RouteId> = planned.iter().copied().filter(|id| !installed.contains(id)).collect();
            warn!(missing = ?missing, "route install incomplete — rolling back and failing closed");
            self.rollback_and_record(
                tun_name,
                server_ip,
                interface_name,
                &installed,
                persisted,
                uncertain,
                teardown_runner,
            );
            return Err(RoutingError::RouteSetup(format!(
                "route install incomplete: {}/{} routes confirmed (another process may hold a conflicting route): missing {missing:?}",
                installed.len(),
                planned.len()
            )));
        }

        // `persisted.installed` already equals `installed` here — every
        // command's post-run checkpoint above kept it current — so there is
        // no separate narrowing write. `persisted.stale` carries forward
        // whatever the pre-install sweep still could not confirm gone —
        // handed to `SystemRoutes` so ITS Drop keeps preserving it too.
        Ok(SystemRoutes {
            tun_name: tun_name.to_owned(),
            server_ip,
            interface_name: interface_name.to_owned(),
            original_gateway: gateway.gateway_ip,
            state_dir: self.state_dir.clone(),
            owner: self.owner,
            installed,
            stale: persisted.stale,
        })
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
    /// The gateway this session's own routes were installed under — scopes
    /// the Windows IPv4 bypass delete (see CONTRIBUTING's Route ownership
    /// section).
    original_gateway: IpAddr,
    state_dir: PathBuf,
    /// Forwarded to every checkpoint `state::save` in `Drop` — same
    /// uid/gid-chown contract as `SystemRouting.owner`.
    owner: Option<(u32, u32)>,
    /// The routes `install` got into the table — the only ones Drop may delete.
    installed: Vec<RouteId>,
    /// Groups carried forward from an earlier `install` in this process,
    /// still not confirmed gone as of this install — preserved (never
    /// cleared or overwritten) by every checkpoint Drop performs below, so a
    /// leak from an earlier session survives this session's own teardown.
    stale: Vec<state::StaleRecord>,
}

impl Drop for SystemRoutes {
    fn drop(&mut self) {
        // Unconditional entry log so a reader can confirm this Drop
        // actually ran on Stop (teardown-skipped diagnosis).
        info!(
            tun = %self.tun_name,
            server_ip = %self.server_ip,
            iface = %self.interface_name,
            installed = ?self.installed,
            "SystemRoutes::drop entered — tearing down routes"
        );
        let mut persisted = state::RouteState {
            version: state::SCHEMA_VERSION,
            tun_name: self.tun_name.clone(),
            server_ip: self.server_ip,
            interface_name: self.interface_name.clone(),
            original_gateway: Some(self.original_gateway),
            installed: self.installed.clone(),
            stale: self.stale.clone(),
        };
        #[allow(clippy::disallowed_methods)] // SystemRoutes IS Routing::Installed
        let remaining = teardown_routes(
            &self.tun_name,
            self.server_ip,
            &self.interface_name,
            Some(self.original_gateway),
            &self.installed,
            exec_one::<BestEffortPhase>,
            |ids| {
                persisted.installed = ids.to_vec();
                if let Err(e) = state::save(&self.state_dir, &persisted, self.owner) {
                    warn!(error = %e, "failed to checkpoint route-state during teardown — recorded routes may be stale if this process now crashes");
                }
            },
        );
        // Clear the state file only once nothing remains unaccounted for —
        // this session's own remainder AND any `stale` groups carried
        // forward from an earlier session (untouched above, so still
        // whatever `install` handed this guard). The checkpoint above
        // already persisted `remaining` after every command, so a non-empty
        // remainder is already recorded — the next start's `recover_routes`
        // will retry exactly those ids.
        if remaining.is_empty() && self.stale.is_empty() {
            if let Err(e) = state::clear(&self.state_dir) {
                warn!(error = %e, "state-file clear failed in SystemRoutes::drop");
            }
        } else {
            warn!(
                remaining = ?remaining,
                stale = ?self.stale,
                "keeping route-state for the next start's recovery — some teardown commands did not confirm their route is gone"
            );
        }
        // Belt-and-suspenders post-teardown wintun adapter cleanup.
        // `bridge::Dispatcher::drop` synchronously drains the engine task
        // so wintun's own Drop runs; this is the safety net for paths that
        // bypass it (panic, current-thread runtime tests). PowerShell
        // `Remove-NetAdapter` is idempotent on missing adapters. See
        // adapter_cleanup docs.
        crate::adapter_cleanup::remove_adapter(&self.tun_name);
        // Note: WFP/NDIS post-teardown snapshots live in bridge's Stop
        // path, not here — tun-engine can't depend on the bridge's
        // diagnostics module.

        info!("SystemRoutes::drop completed");
    }
}

// Platform-specific command builders ==================================================================================
//
// Each platform contributes three builders: the setup commands, the four
// split-route deletes, and the optional server-bypass delete. Teardown is
// built from the same tagged commands as setup so the two can never drift
// apart on which route is which.

#[cfg(target_os = "windows")]
fn platform_setup_commands(
    tun_name: &str,
    server_ip: IpAddr,
    gateway: &GatewayInfo,
    tun_ipv6_available: bool,
) -> Vec<SetupCommand> {
    let ipv6 = tun_ipv6_available;
    let mut cmds = vec![
        // IPv4 low half: 0.0.0.0/1 via TUN
        SetupCommand::fatal(
            RouteId::SplitV4Low,
            vec![
                "netsh".into(),
                "interface".into(),
                "ip".into(),
                "add".into(),
                "route".into(),
                "0.0.0.0/1".into(),
                tun_name.into(),
            ],
        ),
        // IPv4 high half: 128.0.0.0/1 via TUN
        SetupCommand::fatal(
            RouteId::SplitV4High,
            vec![
                "netsh".into(),
                "interface".into(),
                "ip".into(),
                "add".into(),
                "route".into(),
                "128.0.0.0/1".into(),
                tun_name.into(),
            ],
        ),
        // IPv6 low half: ::/1 via TUN
        SetupCommand {
            id: RouteId::SplitV6Low,
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
            id: RouteId::SplitV6High,
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
        cmds.push(SetupCommand::fatal(
            RouteId::ServerBypass,
            match server_ip {
                IpAddr::V4(_) => vec![
                    "route".into(),
                    "add".into(),
                    format!("{server_ip}"),
                    "mask".into(),
                    "255.255.255.255".into(),
                    format!("{original_gateway}"),
                ],
                IpAddr::V6(_) => vec![
                    "netsh".into(),
                    "interface".into(),
                    "ipv6".into(),
                    "add".into(),
                    "route".into(),
                    format!("{server_ip}/128"),
                    gateway.interface_name.clone(),
                ],
            },
        ));
    }

    cmds
}

#[cfg(target_os = "windows")]
fn platform_split_teardown_commands(tun_name: &str) -> Vec<RouteCommand> {
    vec![
        RouteCommand::new(
            RouteId::SplitV4Low,
            vec![
                "netsh".into(),
                "interface".into(),
                "ip".into(),
                "delete".into(),
                "route".into(),
                "0.0.0.0/1".into(),
                tun_name.into(),
            ],
        ),
        RouteCommand::new(
            RouteId::SplitV4High,
            vec![
                "netsh".into(),
                "interface".into(),
                "ip".into(),
                "delete".into(),
                "route".into(),
                "128.0.0.0/1".into(),
                tun_name.into(),
            ],
        ),
        RouteCommand::new(
            RouteId::SplitV6Low,
            vec![
                "netsh".into(),
                "interface".into(),
                "ipv6".into(),
                "delete".into(),
                "route".into(),
                "::/1".into(),
                tun_name.into(),
            ],
        ),
        RouteCommand::new(
            RouteId::SplitV6High,
            vec![
                "netsh".into(),
                "interface".into(),
                "ipv6".into(),
                "delete".into(),
                "route".into(),
                "8000::/1".into(),
                tun_name.into(),
            ],
        ),
    ]
}

/// `original_gateway`, when known, is appended as the `route delete`
/// gateway operand for an IPv4 destination — `route.exe`'s own help
/// confirms DELETE accepts (and does not require) a gateway argument, and
/// unlike macOS, that argument DOES scope which entry is deleted (see
/// CONTRIBUTING's Route ownership section). `None` (a record migrated from
/// schema 1/2, which never persisted a gateway) falls back to the old
/// unscoped delete — a disclosed residual, not a silent skip.
#[cfg(target_os = "windows")]
fn platform_bypass_teardown_command(
    server_ip: IpAddr,
    interface_name: &str,
    original_gateway: Option<IpAddr>,
) -> Option<RouteCommand> {
    // No bypass was installed for a loopback server, so none to delete.
    if server_ip.to_canonical().is_loopback() {
        return None;
    }
    Some(RouteCommand::new(
        RouteId::ServerBypass,
        match server_ip {
            IpAddr::V4(_) => {
                let mut argv = vec![
                    "route".into(),
                    "delete".into(),
                    format!("{server_ip}"),
                    "mask".into(),
                    "255.255.255.255".into(),
                ];
                if let Some(gw) = original_gateway {
                    argv.push(format!("{gw}"));
                }
                argv
            }
            IpAddr::V6(_) => vec![
                "netsh".into(),
                "interface".into(),
                "ipv6".into(),
                "delete".into(),
                "route".into(),
                format!("{server_ip}/128"),
                interface_name.into(),
            ],
        },
    ))
}

#[cfg(target_os = "macos")]
fn platform_setup_commands(
    tun_name: &str,
    server_ip: IpAddr,
    gateway: &GatewayInfo,
    tun_ipv6_available: bool,
) -> Vec<SetupCommand> {
    let ipv6 = tun_ipv6_available;
    let mut cmds = vec![
        // IPv4 low half: 0.0.0.0/1 via TUN
        SetupCommand::fatal(
            RouteId::SplitV4Low,
            vec![
                "route".into(),
                "-n".into(),
                "add".into(),
                "-net".into(),
                "0.0.0.0/1".into(),
                "-interface".into(),
                tun_name.into(),
            ],
        ),
        // IPv4 high half: 128.0.0.0/1 via TUN
        SetupCommand::fatal(
            RouteId::SplitV4High,
            vec![
                "route".into(),
                "-n".into(),
                "add".into(),
                "-net".into(),
                "128.0.0.0/1".into(),
                "-interface".into(),
                tun_name.into(),
            ],
        ),
        // IPv6 low half: ::/1 via TUN
        SetupCommand {
            id: RouteId::SplitV6Low,
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
            id: RouteId::SplitV6High,
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
        cmds.push(SetupCommand::fatal(
            RouteId::ServerBypass,
            match server_ip {
                IpAddr::V4(_) => vec![
                    "route".into(),
                    "-n".into(),
                    "add".into(),
                    "-host".into(),
                    format!("{server_ip}"),
                    format!("{original_gateway}"),
                ],
                IpAddr::V6(_) => vec![
                    "route".into(),
                    "-n".into(),
                    "add".into(),
                    "-inet6".into(),
                    "-host".into(),
                    format!("{server_ip}"),
                    "-interface".into(),
                    gateway.interface_name.clone(),
                ],
            },
        ));
    }

    cmds
}

/// The macOS deletes name no interface, unlike their `add` counterparts:
/// `-interface`/`-ifscope` are settled-and-rejected qualifiers (see
/// [`RouteId`]'s doc and CONTRIBUTING's
/// [Route ownership](../../../CONTRIBUTING.md#route-ownership) section for
/// why). Selectivity comes from [`RouteId`] provenance instead.
#[cfg(target_os = "macos")]
fn platform_split_teardown_commands(_tun_name: &str) -> Vec<RouteCommand> {
    vec![
        RouteCommand::new(
            RouteId::SplitV4Low,
            vec![
                "route".into(),
                "-n".into(),
                "delete".into(),
                "-net".into(),
                "0.0.0.0/1".into(),
            ],
        ),
        RouteCommand::new(
            RouteId::SplitV4High,
            vec![
                "route".into(),
                "-n".into(),
                "delete".into(),
                "-net".into(),
                "128.0.0.0/1".into(),
            ],
        ),
        RouteCommand::new(
            RouteId::SplitV6Low,
            vec![
                "route".into(),
                "-n".into(),
                "delete".into(),
                "-inet6".into(),
                "::/1".into(),
            ],
        ),
        RouteCommand::new(
            RouteId::SplitV6High,
            vec![
                "route".into(),
                "-n".into(),
                "delete".into(),
                "-inet6".into(),
                "8000::/1".into(),
            ],
        ),
    ]
}

/// Names no interface, for the reasons in [`platform_split_teardown_commands`].
/// The uplink outlives the tunnel, but it can still be renamed away — a
/// Wi-Fi-to-Ethernet switch between connect and stop — and `route(8)` would
/// abort on the stale name rather than delete the bypass. `original_gateway`
/// is likewise unused: macOS `route delete` never reads the gateway (see
/// CONTRIBUTING's Route ownership section), so it cannot scope anything here
/// — unlike the Windows counterpart.
#[cfg(target_os = "macos")]
fn platform_bypass_teardown_command(
    server_ip: IpAddr,
    _interface_name: &str,
    _original_gateway: Option<IpAddr>,
) -> Option<RouteCommand> {
    // No bypass was installed for a loopback server, so none to delete.
    if server_ip.to_canonical().is_loopback() {
        return None;
    }
    Some(RouteCommand::new(
        RouteId::ServerBypass,
        match server_ip {
            IpAddr::V4(_) => vec![
                "route".into(),
                "-n".into(),
                "delete".into(),
                "-host".into(),
                format!("{server_ip}"),
            ],
            IpAddr::V6(_) => vec![
                "route".into(),
                "-n".into(),
                "delete".into(),
                "-inet6".into(),
                "-host".into(),
                format!("{server_ip}"),
            ],
        },
    ))
}

#[cfg(test)]
#[path = "routing_tests.rs"]
mod routing_tests;
