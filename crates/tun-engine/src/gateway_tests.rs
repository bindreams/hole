use super::*;

#[skuld::test]
#[ignore] // Requires network — run manually with `cargo test -- --ignored`
fn get_default_gateway_info_returns_valid_result() {
    let info = get_default_gateway_info().expect("should detect default gateway info");
    assert!(
        info.gateway_ip.is_ipv4(),
        "expected IPv4 gateway, got {}",
        info.gateway_ip
    );
    assert!(!info.interface_name.is_empty(), "interface name should not be empty");
    assert!(info.interface_index > 0, "interface index should be non-zero");
    // ipv6_available is informational — just ensure it doesn't panic.
    let _ = info.ipv6_available;
}

// tun_ipv6_available probes the TUN's OWN interface, not upstream =====================================================

#[skuld::test]
fn interface_index_by_name_errs_for_an_unknown_name() {
    let result = interface_index_by_name("definitely-not-a-real-adapter-xyz");
    assert!(
        result.is_err(),
        "expected an error for a nonexistent interface, got {result:?}"
    );
}

#[skuld::test]
fn tun_ipv6_available_is_false_when_the_adapter_cannot_be_resolved() {
    // No adapter of this name exists on this host, so resolution fails —
    // `false` is the safe default (tolerate the IPv6 route commands failing,
    // never skip issuing them; see `SetupCommand`).
    assert!(!tun_ipv6_available("definitely-not-a-real-adapter-xyz"));
}

#[skuld::test]
fn probe_ipv6_bound_is_false_for_an_interface_index_that_does_not_exist() {
    // No live NIC has this index — the IPV6_UNICAST_IF/IPV6_BOUND_IF scoping
    // call itself must fail, before any network I/O.
    assert!(!probe_ipv6_bound(u32::MAX));
}
