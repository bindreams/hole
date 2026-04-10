// Route table management — platform-specific split routing.

use crate::gateway::GatewayInfo;
use crate::proxy::ProxyError;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use tracing::{debug, info, warn};

/// Total number of routing subprocess spawns this process has performed.
/// Incremented once per command in [`run_commands`]. Exposed so
/// `diagnostics` handlers and tests can observe invariant violations
/// (see the `proxy_manager_tests_never_spawn_routing_subprocess`
/// regression test). The one-instruction `fetch_add` has negligible
/// production cost — far below the millisecond-scale subprocess itself.
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
/// Recovery is best-effort: every clean startup tries to delete the four
/// fixed split routes, and on a healthy system all four of those calls fail
/// because nothing leaked. Treating those failures as warnings would drown
/// every dev/prod startup in red. Adding a new `PHASE_RECOVER_*` constant
/// requires updating this matcher.
fn is_recovery_phase(phase: &str) -> bool {
    phase == PHASE_RECOVER_SPLIT || phase == PHASE_RECOVER_BYPASS
}

fn run_commands(commands: &[Vec<String>], phase: &str) -> std::io::Result<()> {
    let recovery = is_recovery_phase(phase);
    for cmd in commands {
        debug_assert!(!cmd.is_empty(), "route command must not be empty");
        ROUTING_SUBPROCESS_SPAWN_COUNT.fetch_add(1, Ordering::SeqCst);
        info!(phase, cmd = cmd.join(" "), "running route command");
        let output = Command::new(&cmd[0]).args(&cmd[1..]).output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let exit_code = output.status.code().unwrap_or(-1);
            if recovery {
                debug!(phase, cmd = cmd.join(" "), exit_code, stderr = %stderr,
                       "recovery command failed (expected if no leaked routes)");
            } else {
                // Post-#165: unit tests no longer invoke this path, so any
                // `warn!` fired here is a real production teardown failure —
                // not a benign test-time artifact. Framing matters: the old
                // message trained investigators to dismiss it. See the
                // #165 incident report.
                warn!(phase, cmd = cmd.join(" "), exit_code, stderr = %stderr,
                      "route command failed — investigate if this is not a no-op idempotent teardown");
            }
        }
    }
    Ok(())
}

// Crash recovery ======================================================================================================

/// Clean up routes left behind by a previous bridge run.
///
/// Called at bridge startup **after** the IPC socket bind succeeds (so a
/// second instance can't damage the first's routing state). Removes the
/// fixed-CIDR split routes (idempotent — harmless if absent); if a
/// [`crate::route_state::RouteState`] file is present in `state_dir`, also
/// removes the server bypass route described by it; finally deletes the
/// state file. Best-effort — all errors are logged at `warn` level and
/// the function returns `()` (there is no meaningful caller recovery).
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
    use crate::proxy::TUN_DEVICE_NAME;

    info!(state_dir = %state_dir.display(), "starting route recovery");

    // Read the state file first. If absent, there's nothing to recover —
    // return early without poking any global routing state.
    //
    // Previously this function unconditionally issued split-route
    // teardown commands on every startup, on the rationale that the
    // commands are idempotent. That was a problem under the test
    // harness: running multiple bridge subprocesses in parallel (one
    // TUN + one SOCKS5, say) caused each subprocess's startup recovery
    // to concurrently `netsh delete route ... hole-tun`, and a
    // SOCKS5-only bridge's recovery would rip routes out from under a
    // concurrent TUN bridge mid-flight. State-file-driven recovery is
    // strictly sufficient: the write-ordering contract in
    // `ProxyManager::start_inner` guarantees the state file is
    // persisted BEFORE any route mutation, so a crashed run that
    // installed routes MUST have left a state file behind.
    let Some(st) = crate::route_state::load(state_dir) else {
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
    //    have positive evidence of a prior route install.
    let split_cmds = build_split_route_teardown_commands(TUN_DEVICE_NAME);
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
    if let Err(e) = crate::route_state::clear(state_dir) {
        warn!(error = %e, "failed to clear route-state file during recovery");
    }
}

// Routing trait =======================================================================================================

/// OS routing: install split-tunnel routes and query routing state.
///
/// # Bridge test-isolation contract
///
/// **All production I/O that mutates or queries the host's routing tables
/// in bridge code MUST route through this trait.** Helper types whose
/// `Drop` impls tear down routes must do so through the associated
/// [`Installed`](Self::Installed) type's Drop, not by calling
/// [`teardown_routes`] directly. The only legitimate call sites of the
/// free functions are inside this module: [`SystemRouting::install`] and
/// [`SystemRoutes::drop`] for the install/teardown path, and
/// [`recover_routes`] / [`recover_routes_with`] for crash recovery.
///
/// The motivation is test isolation. [`crate::proxy_manager::ProxyManager`]
/// is generic over `R: Routing` so unit tests can substitute
/// `MockRouting` whose `Installed` type counts teardown invocations. A
/// helper that bypasses the trait cannot be intercepted by the mock and
/// will exercise real production code from unit tests. See the
/// bindreams/hole#165 incident.
pub trait Routing: Send + Sync {
    /// RAII guard returned by [`install`](Self::install). Dropping this
    /// value tears down the routes and clears the crash-recovery state
    /// file. The real implementation ([`SystemRoutes`]) calls
    /// [`teardown_routes`]; the mock implementation increments a
    /// counter. No production code outside `SystemRoutes` calls the free
    /// teardown function.
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
    ) -> Result<Self::Installed, ProxyError>;

    /// Returns the current default gateway that the *next* call to
    /// [`install`](Self::install) will bypass the tunnel through.
    /// Lives on the trait (not as a free function) so `MockRouting` can
    /// stub a predictable gateway without calling the real OS — without
    /// this seam, every `proxy_manager` unit test would depend on the
    /// host having a route to the Internet.
    fn default_gateway(&self) -> Result<GatewayInfo, ProxyError>;
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
    ) -> Result<Self::Installed, ProxyError> {
        // CRITICAL ORDERING: persist the route-recovery state BEFORE any
        // routing mutation. A panic or SIGKILL between `setup_routes` and
        // `SystemRoutes` construction would otherwise leak routes with no
        // on-disk record, defeating crash recovery on next startup. This
        // invariant used to live in a comment block in ProxyManager::start;
        // it moves here because this is now the single place where routes
        // are actually touched.
        let persisted = crate::route_state::RouteState {
            version: crate::route_state::SCHEMA_VERSION,
            tun_name: tun_name.to_owned(),
            server_ip,
            interface_name: interface_name.to_owned(),
        };
        crate::route_state::save(&self.state_dir, &persisted)
            .map_err(|e| ProxyError::RouteSetup(format!("failed to persist route-state: {e}")))?;

        // Install the routes. On failure, defensively tear down whatever
        // may have been partially installed and clear the stale state
        // file before returning. This belt-and-suspenders cleanup
        // preserves a robustness property the old code relied on:
        // `run_commands` currently returns `Err` only on process-spawn
        // failure, but a future change that makes it early-exit on first
        // non-zero status would otherwise leak partial routes.
        #[allow(clippy::disallowed_methods)] // we ARE the Routing impl
        if let Err(e) = setup_routes(tun_name, server_ip, gateway, interface_name) {
            #[allow(clippy::disallowed_methods)] // defensive rollback inside install
            let _ = teardown_routes(tun_name, server_ip, interface_name);
            let _ = crate::route_state::clear(&self.state_dir);
            return Err(ProxyError::RouteSetup(e.to_string()));
        }

        Ok(SystemRoutes {
            tun_name: tun_name.to_owned(),
            server_ip,
            interface_name: interface_name.to_owned(),
            state_dir: self.state_dir.clone(),
        })
    }

    fn default_gateway(&self) -> Result<GatewayInfo, ProxyError> {
        crate::gateway::get_default_gateway_info().map_err(|e| ProxyError::Gateway(e.to_string()))
    }
}

/// RAII guard returned by [`SystemRouting::install`]. Dropping this value
/// tears down the installed routes and clears the crash-recovery state
/// file. Replaces the pre-#165 `RouteGuard` struct whose `Drop` bypassed
/// the `ProxyBackend` trait and shelled out to `netsh` unconditionally —
/// see the incident report.
pub struct SystemRoutes {
    tun_name: String,
    server_ip: IpAddr,
    interface_name: String,
    state_dir: PathBuf,
}

impl Drop for SystemRoutes {
    fn drop(&mut self) {
        #[allow(clippy::disallowed_methods)] // SystemRoutes IS Routing::Installed
        if let Err(e) = teardown_routes(&self.tun_name, self.server_ip, &self.interface_name) {
            warn!(error = %e, "route teardown failed in SystemRoutes::drop");
        }
        // Always clear the state file — we only need it for *crash*
        // recovery, and reaching Drop means we took the normal shutdown
        // path. Per-command failures above are already logged; a stale
        // state file on the next run would just trigger an idempotent
        // no-op teardown during recover_routes, so clearing is safe.
        if let Err(e) = crate::route_state::clear(&self.state_dir) {
            warn!(error = %e, "state-file clear failed in SystemRoutes::drop");
        }
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
