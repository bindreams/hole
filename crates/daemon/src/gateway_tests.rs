use super::*;

#[skuld::test]
#[ignore] // Requires network — run manually with `cargo test -- --ignored`
fn get_default_gateway_returns_ipv4() {
    let gw = get_default_gateway().expect("should detect a default gateway");
    assert!(gw.is_ipv4(), "expected IPv4 gateway, got {gw}");
}
