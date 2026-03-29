use super::*;

#[skuld::test]
#[ignore] // Requires network — run manually with `cargo test -- --ignored`
fn get_default_gateway_info_returns_valid_result() {
    let info = get_default_gateway_info().expect("should detect default gateway info");
    assert!(info.gateway_ip.is_ipv4(), "expected IPv4 gateway, got {}", info.gateway_ip);
    assert!(!info.interface_name.is_empty(), "interface name should not be empty");
}
