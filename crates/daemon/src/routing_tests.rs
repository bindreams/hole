use super::*;
use std::net::IpAddr;

// Helpers =================================================================================================================

fn ipv4_server() -> IpAddr {
    "1.2.3.4".parse().unwrap()
}

fn ipv6_server() -> IpAddr {
    "2001:db8::1".parse().unwrap()
}

fn ipv4_gateway() -> IpAddr {
    "192.168.1.1".parse().unwrap()
}

fn setup_cmds_joined(server_ip: IpAddr, gateway: IpAddr) -> String {
    let cmds = build_setup_commands("utun7", server_ip, gateway, "en0");
    cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n")
}

fn teardown_cmds_joined(server_ip: IpAddr) -> String {
    let cmds = build_teardown_commands("utun7", server_ip, "en0");
    cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n")
}

// Setup tests — IPv4 server ==============================================================================================

#[skuld::test]
fn setup_generates_five_commands() {
    let cmds = build_setup_commands("utun7", ipv4_server(), ipv4_gateway(), "en0");
    assert_eq!(cmds.len(), 5);
}

#[skuld::test]
fn setup_includes_low_half_route() {
    let joined = setup_cmds_joined(ipv4_server(), ipv4_gateway());
    assert!(joined.contains("0.0.0.0/1"), "missing low-half route in:\n{joined}");
}

#[skuld::test]
fn setup_includes_high_half_route() {
    let joined = setup_cmds_joined(ipv4_server(), ipv4_gateway());
    assert!(joined.contains("128.0.0.0/1"), "missing high-half route in:\n{joined}");
}

#[skuld::test]
fn setup_includes_ipv6_low_half_route() {
    let joined = setup_cmds_joined(ipv4_server(), ipv4_gateway());
    assert!(joined.contains("::/1"), "missing IPv6 low-half route in:\n{joined}");
}

#[skuld::test]
fn setup_includes_ipv6_high_half_route() {
    let joined = setup_cmds_joined(ipv4_server(), ipv4_gateway());
    assert!(joined.contains("8000::/1"), "missing IPv6 high-half route in:\n{joined}");
}

#[skuld::test]
fn setup_includes_server_bypass_route() {
    let server_ip: IpAddr = "5.6.7.8".parse().unwrap();
    let joined = setup_cmds_joined(server_ip, ipv4_gateway());
    assert!(joined.contains("5.6.7.8"), "missing server bypass route in:\n{joined}");
}

#[skuld::test]
fn setup_bypass_uses_original_gateway() {
    let server_ip: IpAddr = "5.6.7.8".parse().unwrap();
    let gateway: IpAddr = "10.0.0.1".parse().unwrap();
    let joined = setup_cmds_joined(server_ip, gateway);
    assert!(joined.contains("10.0.0.1"), "missing gateway in bypass route:\n{joined}");
}

// Setup tests — IPv6 server ==============================================================================================

#[skuld::test]
fn setup_with_ipv6_server_generates_five_commands() {
    let cmds = build_setup_commands("utun7", ipv6_server(), ipv4_gateway(), "en0");
    assert_eq!(cmds.len(), 5);
}

#[skuld::test]
fn setup_with_ipv6_server_includes_ipv6_bypass() {
    let cmds = build_setup_commands("utun7", ipv6_server(), ipv4_gateway(), "en0");
    // The bypass is the last command (index 4)
    let bypass = cmds[4].join(" ");
    assert!(
        bypass.contains("2001:db8::1"),
        "missing IPv6 server address in bypass command:\n{bypass}"
    );
    assert!(
        bypass.contains("en0"),
        "missing interface name in bypass command:\n{bypass}"
    );
}

#[skuld::test]
fn setup_with_ipv6_server_has_no_ipv4_bypass() {
    let joined = setup_cmds_joined(ipv6_server(), ipv4_gateway());
    assert!(
        !joined.contains("mask 255.255.255.255"),
        "IPv6 server should not have IPv4 bypass:\n{joined}"
    );
}

// Teardown tests — IPv4 server ============================================================================================

#[skuld::test]
fn teardown_generates_five_commands() {
    let cmds = build_teardown_commands("utun7", ipv4_server(), "en0");
    assert_eq!(cmds.len(), 5);
}

#[skuld::test]
fn teardown_includes_low_half_route() {
    let joined = teardown_cmds_joined(ipv4_server());
    assert!(joined.contains("0.0.0.0/1"), "missing low-half route in:\n{joined}");
}

#[skuld::test]
fn teardown_includes_high_half_route() {
    let joined = teardown_cmds_joined(ipv4_server());
    assert!(joined.contains("128.0.0.0/1"), "missing high-half route in:\n{joined}");
}

#[skuld::test]
fn teardown_includes_ipv6_low_half_route() {
    let joined = teardown_cmds_joined(ipv4_server());
    assert!(joined.contains("::/1"), "missing IPv6 low-half route in:\n{joined}");
}

#[skuld::test]
fn teardown_includes_ipv6_high_half_route() {
    let joined = teardown_cmds_joined(ipv4_server());
    assert!(joined.contains("8000::/1"), "missing IPv6 high-half route in:\n{joined}");
}

#[skuld::test]
fn teardown_includes_server_bypass() {
    let server_ip: IpAddr = "9.8.7.6".parse().unwrap();
    let cmds = build_teardown_commands("utun7", server_ip, "en0");
    let joined = cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n");
    assert!(joined.contains("9.8.7.6"), "missing server bypass in:\n{joined}");
}

// Teardown tests — IPv6 server ============================================================================================

#[skuld::test]
fn teardown_with_ipv6_server_includes_ipv6_bypass() {
    let cmds = build_teardown_commands("utun7", ipv6_server(), "en0");
    let joined = cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n");
    assert!(
        joined.contains("2001:db8::1"),
        "missing IPv6 server bypass in:\n{joined}"
    );
}

#[skuld::test]
fn teardown_with_ipv6_server_has_no_ipv4_bypass() {
    let cmds = build_teardown_commands("utun7", ipv6_server(), "en0");
    let joined = cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n");
    assert!(
        !joined.contains("mask 255.255.255.255"),
        "IPv6 server should not have IPv4 bypass:\n{joined}"
    );
}

// Split route teardown (crash recovery) ===================================================================================

#[skuld::test]
fn split_teardown_generates_four_commands() {
    let cmds = build_split_route_teardown_commands("utun7");
    assert_eq!(cmds.len(), 4);
}

#[skuld::test]
fn split_teardown_includes_ipv4_low_half() {
    let cmds = build_split_route_teardown_commands("utun7");
    let joined = cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n");
    assert!(joined.contains("0.0.0.0/1"), "missing IPv4 low-half route in:\n{joined}");
}

#[skuld::test]
fn split_teardown_includes_ipv4_high_half() {
    let cmds = build_split_route_teardown_commands("utun7");
    let joined = cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n");
    assert!(joined.contains("128.0.0.0/1"), "missing IPv4 high-half route in:\n{joined}");
}

#[skuld::test]
fn split_teardown_includes_ipv6_low_half() {
    let cmds = build_split_route_teardown_commands("utun7");
    let joined = cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n");
    assert!(joined.contains("::/1"), "missing IPv6 low-half route in:\n{joined}");
}

#[skuld::test]
fn split_teardown_includes_ipv6_high_half() {
    let cmds = build_split_route_teardown_commands("utun7");
    let joined = cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n");
    assert!(joined.contains("8000::/1"), "missing IPv6 high-half route in:\n{joined}");
}

// Interface name with spaces ==============================================================================================

#[skuld::test]
fn setup_with_spaced_interface_name_includes_full_name() {
    let cmds = build_setup_commands("utun7", ipv6_server(), ipv4_gateway(), "Wi-Fi Direct");
    let bypass = cmds[4].join(" ");
    assert!(
        bypass.contains("Wi-Fi Direct"),
        "interface name with spaces should be preserved:\n{bypass}"
    );
}

// RouteGuard tests ========================================================================================================

#[skuld::test]
fn route_guard_stores_server_ip() {
    let guard = RouteGuard::new("utun7".into(), ipv4_server(), "en0".into());
    assert_eq!(guard.server_ip, ipv4_server());
}

#[skuld::test]
fn route_guard_stores_tun_name() {
    let guard = RouteGuard::new("utun7".into(), ipv4_server(), "en0".into());
    assert_eq!(guard.tun_name, "utun7");
}

#[skuld::test]
fn route_guard_stores_interface_name() {
    let guard = RouteGuard::new("utun7".into(), ipv4_server(), "en0".into());
    assert_eq!(guard.interface_name, "en0");
}
