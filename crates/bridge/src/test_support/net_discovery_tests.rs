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
                Err(lost_route())
            } else {
                Ok(Ipv4Addr::new(10, 0, 0, 7))
            }
        },
        || pauses += 1,
    );
    assert_eq!(found, Ok(Ipv4Addr::new(10, 0, 0, 7)));
    assert_eq!(pauses, 3, "one pause per failed read");
}

fn lost_route() -> PrimaryIpv4Error {
    PrimaryIpv4Error::NetworkLoss("Network is unreachable".to_string())
}

fn snapshot(primary_ipv4: Result<Ipv4Addr, PrimaryIpv4Error>) -> HostNetwork {
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
                Err(lost_route())
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

/// Raw OS error numbers for (network unreachable, host unreachable, network down), as the platform's
/// socket API reports them.
#[cfg(target_os = "linux")]
const NETWORK_LOSS_ERRNOS: [i32; 3] = [101, 113, 100];
#[cfg(target_os = "macos")]
const NETWORK_LOSS_ERRNOS: [i32; 3] = [51, 65, 50];
#[cfg(windows)]
const NETWORK_LOSS_ERRNOS: [i32; 3] = [10051, 10065, 10050]; // WSAENETUNREACH, WSAEHOSTUNREACH, WSAENETDOWN

/// Raw OS error numbers for (permission denied, too many open files): the host refusing us, which
/// the network coming back does not change.
#[cfg(target_os = "linux")]
const UNRELATED_ERRNOS: [i32; 2] = [13, 24];
#[cfg(target_os = "macos")]
const UNRELATED_ERRNOS: [i32; 2] = [13, 24];
#[cfg(windows)]
const UNRELATED_ERRNOS: [i32; 2] = [10013, 10024]; // WSAEACCES, WSAEMFILE

#[skuld::test]
fn a_connect_that_finds_no_route_is_a_network_loss() {
    for errno in NETWORK_LOSS_ERRNOS {
        let err = PrimaryIpv4Error::from_connect(std::io::Error::from_raw_os_error(errno));
        assert!(
            matches!(err, PrimaryIpv4Error::NetworkLoss(_)),
            "os error {errno}: {err:?}"
        );
    }
}

#[skuld::test]
fn a_connect_refused_for_another_reason_is_not_a_network_loss() {
    for errno in UNRELATED_ERRNOS {
        let err = PrimaryIpv4Error::from_connect(std::io::Error::from_raw_os_error(errno));
        assert!(matches!(err, PrimaryIpv4Error::Failed(_)), "os error {errno}: {err:?}");
    }
}

/// The error message carries the OS's own words, so a failure that is returned names its cause.
#[skuld::test]
fn the_connect_error_text_is_kept() {
    let io_err = std::io::Error::from_raw_os_error(UNRELATED_ERRNOS[0]);
    let want = io_err.to_string();
    let err = PrimaryIpv4Error::from_connect(io_err);
    assert!(err.to_string().contains(&want), "{err}");
}

/// A link-local source means the interface is up with no lease yet (DHCP lost its server): a network
/// that comes back. Loopback and unspecified are not that.
#[skuld::test]
fn only_a_link_local_source_address_is_a_network_loss() {
    assert_eq!(
        PrimaryIpv4Error::check_source(Ipv4Addr::new(10, 0, 0, 7)),
        Ok(Ipv4Addr::new(10, 0, 0, 7))
    );
    assert!(matches!(
        PrimaryIpv4Error::check_source(Ipv4Addr::new(169, 254, 3, 4)),
        Err(PrimaryIpv4Error::NetworkLoss(_))
    ));
    for ip in [Ipv4Addr::LOCALHOST, Ipv4Addr::UNSPECIFIED] {
        assert!(
            matches!(PrimaryIpv4Error::check_source(ip), Err(PrimaryIpv4Error::Failed(_))),
            "{ip}"
        );
    }
}

/// Waiting cannot change a refusal, so it is returned at once with its cause.
#[skuld::test]
fn waiting_for_the_primary_ipv4_returns_a_failure_that_is_not_a_lost_route() {
    let mut pauses = 0;
    let err = wait_for_primary_ipv4_with(
        || Err(PrimaryIpv4Error::Failed("Permission denied (os error 13)".to_string())),
        || pauses += 1,
    )
    .unwrap_err();
    assert_eq!(err.to_string(), "Permission denied (os error 13)");
    assert_eq!(pauses, 0);
}

#[skuld::test]
fn a_snapshot_whose_route_failed_for_another_reason_is_returned_not_waited_out() {
    let mut reads = 0;
    let mut pauses = 0;
    let err = HostNetwork::read_when_routed_with(
        || {
            reads += 1;
            Ok(snapshot(Err(PrimaryIpv4Error::Failed(
                "Permission denied (os error 13)".to_string(),
            ))))
        },
        || pauses += 1,
    )
    .err()
    .expect("the failure is returned");
    assert!(err.contains("Permission denied (os error 13)"), "{err}");
    assert_eq!((reads, pauses), (1, 0));
}
