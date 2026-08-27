//! Unit tests for the host-network facts the e2e tests build on.

use super::*;
use crate::test_support::skuld_fixtures::TUN;

/// The full-tunnel capture oracle is only meaningful if the host cannot
/// answer the probe destinations by itself. Pin that as a checked fact, per
/// address family.
#[skuld::test]
fn unowned_dsts_are_not_addresses_this_host_holds() {
    for dst in UNOWNED_DSTS {
        assert_host_does_not_own(dst.ip());
    }
}

/// The counterpart fact, pinned so nobody mistakes a target bound to the
/// primary IPv4 for tunnel-transit coverage: the host holds that address,
/// so it answers from its own on-link `/32` and the packet never reaches
/// `hole-tun`.
///
/// One [`HostNetwork`] backs both halves — the kernel's off-link source
/// address and the interface enumeration — so a TUN appearing or vanishing
/// between two reads cannot report a contradiction as an ownership failure.
///
/// `serial = TUN` without `labels = [TUN]`, the same shape as
/// `e2e_socks_only_leaves_unowned_destination_unreachable`: the kernel's
/// off-link source address is discovered by routing to a public sentinel,
/// which falls inside the `/1` split, so while a Full-mode test holds
/// `hole-tun` up this would pin the TUN's own address and pass on the wrong
/// one. skuld evaluates `serial` independently of selection, so this stays
/// unlabelled for filtering while being mutually excluded from every `TUN`
/// test in the binary.
#[skuld::test(serial = TUN)]
fn primary_ipv4_target_is_an_address_this_host_holds() {
    let host = HostNetwork::read().expect("read host network state");
    let primary = IpAddr::V4(host.primary_ipv4().expect("detect primary IPv4"));
    assert!(
        host.holder_of(primary).is_some(),
        "the host must hold its own primary IPv4 {primary}; if the ownership scan cannot see it, \
         every assertion built on assert_host_does_not_own is unsound"
    );
}
