// Route table management — platform-specific split routing.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, info, warn};

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

/// Execute route setup commands. Logs each command and its result.
pub fn setup_routes(
    tun_name: &str,
    server_ip: IpAddr,
    original_gateway: IpAddr,
    interface_name: &str,
) -> std::io::Result<()> {
    let commands = build_setup_commands(tun_name, server_ip, original_gateway, interface_name);
    run_commands(&commands, "setup")
}

/// Execute route teardown commands. Idempotent — safe to call even if routes don't exist.
pub fn teardown_routes(tun_name: &str, server_ip: IpAddr, interface_name: &str) -> std::io::Result<()> {
    let commands = build_teardown_commands(tun_name, server_ip, interface_name);
    run_commands(&commands, "teardown")
}

pub(crate) fn build_split_route_teardown_commands(tun_name: &str) -> Vec<Vec<String>> {
    platform_split_route_teardown_commands(tun_name)
}

fn run_commands(commands: &[Vec<String>], phase: &str) -> std::io::Result<()> {
    for cmd in commands {
        debug_assert!(!cmd.is_empty(), "route command must not be empty");
        info!(phase, cmd = cmd.join(" "), "running route command");
        let output = Command::new(&cmd[0]).args(&cmd[1..]).output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(phase, cmd = cmd.join(" "), stderr = %stderr, "route command failed (may be expected during teardown)");
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

    // 1. Split routes (IPv4 + IPv6 halves). Always attempted.
    let split_cmds = build_split_route_teardown_commands(TUN_DEVICE_NAME);
    if let Err(e) = runner(&split_cmds, "recover-split") {
        warn!(error = %e, "split-route teardown failed during recovery");
    }

    // 2. If the state file is present, tear down the per-server bypass route.
    if let Some(st) = crate::route_state::load(state_dir) {
        info!(
            tun = %st.tun_name,
            server_ip = %st.server_ip,
            iface = %st.interface_name,
            "recovering bypass route from crashed run"
        );
        let bypass_cmds = build_teardown_commands(&st.tun_name, st.server_ip, &st.interface_name);
        if let Err(e) = runner(&bypass_cmds, "recover-bypass") {
            warn!(error = %e, "bypass-route teardown failed during recovery");
        }
    } else {
        debug!("no route-state file found, nothing to recover");
    }

    // 3. Delete the state file regardless of command outcomes. Next startup
    //    re-runs the idempotent teardown if anything leaked past a failure.
    if let Err(e) = crate::route_state::clear(state_dir) {
        warn!(error = %e, "failed to clear route-state file during recovery");
    }
}

// Route guard =========================================================================================================

/// RAII guard that tears down routes on drop and deletes the route-state
/// file. Provides crash safety for the active-proxy lifetime: construction
/// is pure (no I/O), so callers MUST write the state file before
/// constructing the guard. See `ProxyManager::start` for the ordering.
pub struct RouteGuard {
    pub tun_name: String,
    pub server_ip: IpAddr,
    pub interface_name: String,
    pub state_dir: PathBuf,
}

impl RouteGuard {
    pub fn new(tun_name: String, server_ip: IpAddr, interface_name: String, state_dir: PathBuf) -> Self {
        Self {
            tun_name,
            server_ip,
            interface_name,
            state_dir,
        }
    }
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        if let Err(e) = teardown_routes(&self.tun_name, self.server_ip, &self.interface_name) {
            warn!(error = %e, "failed to teardown routes in RouteGuard drop");
        }
        // Always clear the state file — we only need it for *crash* recovery,
        // and reaching Drop means we took the normal shutdown path. Per-command
        // failures above are already logged; a stale state file on the next
        // run would just trigger an idempotent no-op teardown, so clearing is
        // safe.
        if let Err(e) = crate::route_state::clear(&self.state_dir) {
            warn!(error = %e, "failed to clear route-state file in RouteGuard drop");
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
