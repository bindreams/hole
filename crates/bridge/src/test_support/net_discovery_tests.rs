//! Unit tests for the host-network facts the e2e tests build on.

use super::*;

/// The full-tunnel capture oracle is only meaningful if the host cannot
/// answer [`UNOWNED_DST`] by itself. Pin that as a checked fact.
#[skuld::test]
fn unowned_dst_is_not_an_address_this_host_holds() {
    assert_host_does_not_own(UNOWNED_DST.ip());
}

/// The counterpart fact, pinned so nobody mistakes a target bound to the
/// primary IPv4 for tunnel-transit coverage: the host holds that address,
/// so it answers from its own on-link `/32` and the packet never reaches
/// `hole-tun`.
#[skuld::test]
fn primary_ipv4_target_is_an_address_this_host_holds() {
    let primary = IpAddr::V4(detect_primary_ipv4().expect("detect primary IPv4"));
    assert!(
        host_interface_holding(primary).is_some(),
        "the host must hold its own primary IPv4 {primary}; if the ownership scan cannot see it, \
         every assertion built on assert_host_does_not_own is unsound"
    );
}
