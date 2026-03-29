// Route table management — platform-specific split routing.

use std::net::IpAddr;
use std::process::Command;
use tracing::{info, warn};

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
pub fn build_teardown_commands(
    tun_name: &str,
    server_ip: IpAddr,
    interface_name: &str,
) -> Vec<Vec<String>> {
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
pub fn teardown_routes(
    tun_name: &str,
    server_ip: IpAddr,
    interface_name: &str,
) -> std::io::Result<()> {
    let commands = build_teardown_commands(tun_name, server_ip, interface_name);
    run_commands(&commands, "teardown")
}

/// Clean up only the split routes (IPv4 and IPv6 halves).
/// Used for crash recovery when the server IP is not known.
pub fn teardown_split_routes(tun_name: &str) -> std::io::Result<()> {
    let commands = build_split_route_teardown_commands(tun_name);
    run_commands(&commands, "crash-recovery")
}

fn build_split_route_teardown_commands(tun_name: &str) -> Vec<Vec<String>> {
    platform_split_route_teardown_commands(tun_name)
}

fn run_commands(commands: &[Vec<String>], phase: &str) -> std::io::Result<()> {
    for cmd in commands {
        info!(phase, cmd = cmd.join(" "), "running route command");
        let output = Command::new(&cmd[0]).args(&cmd[1..]).output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(phase, cmd = cmd.join(" "), stderr = %stderr, "route command failed (may be expected during teardown)");
        }
    }
    Ok(())
}

// Route guard =========================================================================================================

/// RAII guard that tears down routes on drop. Provides crash safety.
pub struct RouteGuard {
    pub tun_name: String,
    pub server_ip: IpAddr,
    pub interface_name: String,
}

impl RouteGuard {
    pub fn new(tun_name: String, server_ip: IpAddr, interface_name: String) -> Self {
        Self {
            tun_name,
            server_ip,
            interface_name,
        }
    }
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        if let Err(e) = teardown_routes(&self.tun_name, self.server_ip, &self.interface_name) {
            warn!(error = %e, "failed to teardown routes in RouteGuard drop");
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
fn platform_teardown_commands(
    tun_name: &str,
    server_ip: IpAddr,
    interface_name: &str,
) -> Vec<Vec<String>> {
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
fn platform_teardown_commands(
    _tun_name: &str,
    server_ip: IpAddr,
    _interface_name: &str,
) -> Vec<Vec<String>> {
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
