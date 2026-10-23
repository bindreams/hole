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
    // The route can be missing while the runner's network settles; the snapshot is read until it has one.
    let host = HostNetwork::read_when_routed().expect("read host network state");
    let primary = IpAddr::V4(host.primary_ipv4().expect("detect primary IPv4"));
    assert!(
        host.holder_of(primary).is_some(),
        "the host must hold its own primary IPv4 {primary}; if the ownership scan cannot see it, \
         every assertion built on assert_host_does_not_own is unsound"
    );
}

/// A runner that briefly has no route reports `Network is unreachable`; that is
/// the environment, so the wait re-reads the kernel until it names an address.
#[skuld::test]
fn waiting_for_the_primary_ipv4_outlasts_a_lost_route() {
    let mut reads = 0;
    let mut pauses = 0;
    let found = wait_for_primary_ipv4_with(
        || {
            reads += 1;
            if reads <= 3 {
                Err("Network is unreachable (os error 101)".to_string())
            } else {
                Ok(Ipv4Addr::new(10, 0, 0, 7))
            }
        },
        || pauses += 1,
    );
    assert_eq!(found, Ipv4Addr::new(10, 0, 0, 7));
    assert_eq!(pauses, 3, "one pause per failed read");
}

fn snapshot(primary_ipv4: Result<Ipv4Addr, String>) -> HostNetwork {
    HostNetwork {
        interfaces: Vec::new(),
        primary_ipv4,
    }
}

/// The route and the interface list are one construction; a route that appears after a read is
/// retaken together with the list, never read on its own beside an older list.
#[skuld::test]
fn a_snapshot_without_a_route_is_read_again_whole() {
    let mut reads = 0;
    let mut pauses = 0;
    let host = HostNetwork::read_when_routed_with(
        || {
            reads += 1;
            Ok(snapshot(if reads <= 3 {
                Err("Network is unreachable (os error 101)".to_string())
            } else {
                Ok(Ipv4Addr::new(10, 0, 0, 7))
            }))
        },
        || pauses += 1,
    )
    .expect("a snapshot with a route");
    assert_eq!(host.primary_ipv4(), Ok(Ipv4Addr::new(10, 0, 0, 7)));
    assert_eq!((reads, pauses), (4, 3));
}

/// A scan that failed outright is not a lost route, so it is reported rather than waited out.
#[skuld::test]
fn a_failed_scan_is_not_waited_out() {
    let mut pauses = 0;
    let err = HostNetwork::read_when_routed_with(|| Err("scan failed".to_string()), || pauses += 1)
        .err()
        .expect("the scan failure is returned");
    assert_eq!(err, "scan failed");
    assert_eq!(pauses, 0);
}
