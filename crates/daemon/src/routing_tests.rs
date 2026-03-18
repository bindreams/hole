use super::*;
use std::net::IpAddr;

// Command generation tests =====

#[skuld::test]
fn setup_generates_three_commands() {
    let server_ip: IpAddr = "1.2.3.4".parse().unwrap();
    let cmds = build_setup_commands("utun7", server_ip, "192.168.1.1".parse().unwrap());
    assert_eq!(cmds.len(), 3);
}

#[skuld::test]
fn setup_includes_low_half_route() {
    let server_ip: IpAddr = "1.2.3.4".parse().unwrap();
    let cmds = build_setup_commands("utun7", server_ip, "192.168.1.1".parse().unwrap());
    let joined = cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n");
    assert!(joined.contains("0.0.0.0/1"), "missing low-half route in:\n{joined}");
}

#[skuld::test]
fn setup_includes_high_half_route() {
    let server_ip: IpAddr = "1.2.3.4".parse().unwrap();
    let cmds = build_setup_commands("utun7", server_ip, "192.168.1.1".parse().unwrap());
    let joined = cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n");
    assert!(joined.contains("128.0.0.0/1"), "missing high-half route in:\n{joined}");
}

#[skuld::test]
fn setup_includes_server_bypass_route() {
    let server_ip: IpAddr = "5.6.7.8".parse().unwrap();
    let cmds = build_setup_commands("utun7", server_ip, "192.168.1.1".parse().unwrap());
    let joined = cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n");
    assert!(joined.contains("5.6.7.8"), "missing server bypass route in:\n{joined}");
}

#[skuld::test]
fn setup_bypass_uses_original_gateway() {
    let server_ip: IpAddr = "5.6.7.8".parse().unwrap();
    let gateway: IpAddr = "10.0.0.1".parse().unwrap();
    let cmds = build_setup_commands("utun7", server_ip, gateway);
    let joined = cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n");
    assert!(
        joined.contains("10.0.0.1"),
        "missing gateway in bypass route:\n{joined}"
    );
}

#[skuld::test]
fn teardown_generates_three_commands() {
    let server_ip: IpAddr = "1.2.3.4".parse().unwrap();
    let cmds = build_teardown_commands(server_ip);
    assert_eq!(cmds.len(), 3);
}

#[skuld::test]
fn teardown_includes_low_half_route() {
    let server_ip: IpAddr = "1.2.3.4".parse().unwrap();
    let cmds = build_teardown_commands(server_ip);
    let joined = cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n");
    assert!(joined.contains("0.0.0.0/1"), "missing low-half route in:\n{joined}");
}

#[skuld::test]
fn teardown_includes_high_half_route() {
    let server_ip: IpAddr = "1.2.3.4".parse().unwrap();
    let cmds = build_teardown_commands(server_ip);
    let joined = cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n");
    assert!(joined.contains("128.0.0.0/1"), "missing high-half route in:\n{joined}");
}

#[skuld::test]
fn teardown_includes_server_bypass() {
    let server_ip: IpAddr = "9.8.7.6".parse().unwrap();
    let cmds = build_teardown_commands(server_ip);
    let joined = cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n");
    assert!(joined.contains("9.8.7.6"), "missing server bypass in:\n{joined}");
}

// RouteGuard tests =====

#[skuld::test]
fn route_guard_stores_server_ip() {
    let server_ip: IpAddr = "1.2.3.4".parse().unwrap();
    let guard = RouteGuard::new(server_ip);
    assert_eq!(guard.server_ip, server_ip);
}
