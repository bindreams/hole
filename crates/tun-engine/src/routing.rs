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
/// Creates five routes:
/// 1. `0.0.0.0/1` via TUN — captures first half of IPv4 space
/// 2. `128.0.0.0/1` via TUN — captures second half of IPv4 space
/// 3. `::/1` via TUN — captures first half of IPv6 space
/// 4. `8000::/1` via TUN — captures second half of IPv6 space
/// 5. Server bypass — `<server_ip>` via `original_gateway` (IPv4 server) or `interface_name` (IPv6 server)
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
    recover_routes_with(state_dir, run_commands);
}

/// Test seam for [`recover_routes`]: accepts an injected command runner so
/// unit tests can assert on the emitted commands without shelling out to
/// `netsh`/`route`.
pub(crate) fn recover_routes_with<R>(state_dir: &Path, runner: R)
where
    R: Fn(&[Vec<String>], &str) -> std::io::Result<()>,
{
    info!(state_dir = %state_dir.display(), "starting route recovery");

    // Read the state file first. If absent, there's nothing to recover —
    // return early without poking any global routing state.
    //
    // State-file-driven recovery (not unconditional split-route teardown)
    // is required so concurrent bridge subprocesses don't rip routes out
    // from under each other: a SOCKS5-only bridge unconditionally issuing
    // `netsh delete route ... hole-tun` on startup would tear down the
    // routes of a concurrent TUN bridge mid-flight. The caller's
    // write-ordering contract guarantees the state file is persisted
    // BEFORE any route mutation, so a crashed run that installed routes
    // MUST have left a state file behind.
    let Some(st) = state::load(state_dir) else {
        debug!("no route-state file found, nothing to recover");
        return;
    };

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
}

// Routing trait =======================================================================================================

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
}

// System (production) routing =========================================================================================

/// Production implementation of [`Routing`]. Calls `setup_routes` /
/// `teardown_routes` (which shell out to `netsh`/`route`) and owns the
/// `state_dir` where `bridge-routes.json` lives for crash recovery.
pub struct SystemRouting {
    state_dir: PathBuf,
}

impl SystemRouting {
    pub fn new(state_dir: PathBuf) -> Self {
        Self { state_dir }
    }
}

impl Routing for SystemRouting {
    type Installed = SystemRoutes;

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
        state::save(&self.state_dir, &persisted)
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

    // Bypass: server IP via original gateway/interface
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

    // Bypass: server IP via original gateway/interface
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
