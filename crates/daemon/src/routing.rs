// Route table management — platform-specific split routing.

use std::net::IpAddr;
use std::process::Command;
use tracing::{info, warn};

// Command builders ====================================================================================================

/// Build the shell commands to set up split routing.
///
/// Creates three routes:
/// 1. `0.0.0.0/1` via TUN — captures first half of IPv4 space
/// 2. `128.0.0.0/1` via TUN — captures second half of IPv4 space
/// 3. `<server_ip>/32` via original gateway — bypass route to avoid loop
pub fn build_setup_commands(tun_name: &str, server_ip: IpAddr, original_gateway: IpAddr) -> Vec<Vec<String>> {
    platform_setup_commands(tun_name, server_ip, original_gateway)
}

/// Build the shell commands to tear down split routing.
pub fn build_teardown_commands(server_ip: IpAddr) -> Vec<Vec<String>> {
    platform_teardown_commands(server_ip)
}

// Execution ===========================================================================================================

/// Execute route setup commands. Logs each command and its result.
pub fn setup_routes(tun_name: &str, server_ip: IpAddr, original_gateway: IpAddr) -> std::io::Result<()> {
    let commands = build_setup_commands(tun_name, server_ip, original_gateway);
    run_commands(&commands, "setup")
}

/// Execute route teardown commands. Idempotent — safe to call even if routes don't exist.
pub fn teardown_routes(server_ip: IpAddr) -> std::io::Result<()> {
    let commands = build_teardown_commands(server_ip);
    run_commands(&commands, "teardown")
}

/// Clean up only the split routes (0.0.0.0/1 and 128.0.0.0/1).
/// Used for crash recovery when the server IP is not known.
pub fn teardown_split_routes() -> std::io::Result<()> {
    let commands = build_split_route_teardown_commands();
    run_commands(&commands, "crash-recovery")
}

fn build_split_route_teardown_commands() -> Vec<Vec<String>> {
    platform_split_route_teardown_commands()
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

// Route guard =========================================================================================================

/// RAII guard that tears down routes on drop. Provides crash safety.
pub struct RouteGuard {
    pub server_ip: IpAddr,
}

impl RouteGuard {
    pub fn new(server_ip: IpAddr) -> Self {
        Self { server_ip }
    }
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        if let Err(e) = teardown_routes(self.server_ip) {
            warn!(error = %e, "failed to teardown routes in RouteGuard drop");
        }
    }
}

// Platform-specific command builders ==================================================================================

#[cfg(target_os = "windows")]
fn platform_setup_commands(tun_name: &str, server_ip: IpAddr, original_gateway: IpAddr) -> Vec<Vec<String>> {
    vec![
        // Low half: 0.0.0.0/1 via TUN
        vec![
            "netsh".into(),
            "interface".into(),
            "ip".into(),
            "add".into(),
            "route".into(),
            "0.0.0.0/1".into(),
            tun_name.into(),
        ],
        // High half: 128.0.0.0/1 via TUN
        vec![
            "netsh".into(),
            "interface".into(),
            "ip".into(),
            "add".into(),
            "route".into(),
            "128.0.0.0/1".into(),
            tun_name.into(),
        ],
        // Bypass: server IP via original gateway (uses `route add` to avoid needing interface name)
        vec![
            "route".into(),
            "add".into(),
            format!("{}", server_ip),
            "mask".into(),
            "255.255.255.255".into(),
            format!("{}", original_gateway),
        ],
    ]
}

#[cfg(target_os = "windows")]
fn platform_teardown_commands(server_ip: IpAddr) -> Vec<Vec<String>> {
    vec![
        vec![
            "netsh".into(),
            "interface".into(),
            "ip".into(),
            "delete".into(),
            "route".into(),
            "0.0.0.0/1".into(),
        ],
        vec![
            "netsh".into(),
            "interface".into(),
            "ip".into(),
            "delete".into(),
            "route".into(),
            "128.0.0.0/1".into(),
        ],
        vec![
            "route".into(),
            "delete".into(),
            format!("{}", server_ip),
            "mask".into(),
            "255.255.255.255".into(),
        ],
    ]
}

#[cfg(target_os = "macos")]
fn platform_setup_commands(tun_name: &str, server_ip: IpAddr, original_gateway: IpAddr) -> Vec<Vec<String>> {
    vec![
        // Low half: 0.0.0.0/1 via TUN
        vec![
            "route".into(),
            "-n".into(),
            "add".into(),
            "-net".into(),
            "0.0.0.0/1".into(),
            "-interface".into(),
            tun_name.into(),
        ],
        // High half: 128.0.0.0/1 via TUN
        vec![
            "route".into(),
            "-n".into(),
            "add".into(),
            "-net".into(),
            "128.0.0.0/1".into(),
            "-interface".into(),
            tun_name.into(),
        ],
        // Bypass: server IP via original gateway
        vec![
            "route".into(),
            "-n".into(),
            "add".into(),
            "-host".into(),
            format!("{}", server_ip),
            format!("{}", original_gateway),
        ],
    ]
}

#[cfg(target_os = "macos")]
fn platform_teardown_commands(server_ip: IpAddr) -> Vec<Vec<String>> {
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
            "-host".into(),
            format!("{}", server_ip),
        ],
    ]
}

#[cfg(target_os = "windows")]
fn platform_split_route_teardown_commands() -> Vec<Vec<String>> {
    vec![
        vec![
            "netsh".into(),
            "interface".into(),
            "ip".into(),
            "delete".into(),
            "route".into(),
            "0.0.0.0/1".into(),
        ],
        vec![
            "netsh".into(),
            "interface".into(),
            "ip".into(),
            "delete".into(),
            "route".into(),
            "128.0.0.0/1".into(),
        ],
    ]
}

#[cfg(target_os = "macos")]
fn platform_split_route_teardown_commands() -> Vec<Vec<String>> {
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
    ]
}

#[cfg(test)]
#[path = "routing_tests.rs"]
mod routing_tests;
