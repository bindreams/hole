//! Unprivileged unit tests for the Windows IPv6 assignment. They build and
//! classify; they call no IP Helper mutator, so they run on the `!tun` lane.

use super::*;

/// Three of these fields bite. `SkipAsSource = true` would assign an address
/// the kernel never selects — the reported defect with the address present. A
/// `DadState` left at `IpDadStateInvalid` (zero) puts the address on the
/// tentative path. And the two origins are what the `tun` crate pins for the
/// IPv4 address this product already assigns on every Full-mode start.
#[skuld::test]
fn unicast_row_is_preferred_manual_and_infinite() {
    let cidr: Ipv6Cidr = "fda6:578a:3ba8::1/64".parse().unwrap();
    let row = unicast_row(42, cidr);

    // SAFETY: `unicast_row` writes the IPv6 arm of the address union.
    unsafe {
        assert_eq!(row.Address.si_family, AF_INET6);
        assert_eq!(row.Address.Ipv6.sin6_family, AF_INET6);
        assert_eq!(row.Address.Ipv6.sin6_addr.u.Byte, cidr.address().octets());
    }
    assert_eq!(row.InterfaceIndex, 42);
    assert_eq!(row.OnLinkPrefixLength, 64);
    assert_eq!(row.ValidLifetime, u32::MAX);
    assert_eq!(row.PreferredLifetime, u32::MAX);
    assert!(!row.SkipAsSource);
    assert_eq!(row.DadState, IpDadStatePreferred);
    assert_eq!(row.PrefixOrigin, IpPrefixOriginManual);
    assert_eq!(row.SuffixOrigin, IpSuffixOriginManual);
}

/// `ERROR_NOT_SUPPORTED` is Microsoft's code for "no IPv6 stack on the local
/// computer and an IPv6 address was specified" — the same host condition the
/// appearance wait reaches from the other side.
#[skuld::test]
fn classify_create_tolerates_absent_stack_and_existing_address() {
    assert!(matches!(classify_create(NO_ERROR), CreateVerdict::Created));
    assert!(matches!(
        classify_create(ERROR_OBJECT_ALREADY_EXISTS),
        CreateVerdict::Created
    ));
    assert!(matches!(
        classify_create(ERROR_NOT_SUPPORTED),
        CreateVerdict::StackAbsent
    ));
    match classify_create(ERROR_NOT_FOUND) {
        CreateVerdict::Failed(code) => assert_eq!(code, ERROR_NOT_FOUND),
        other => panic!("an unrecognised code must be fatal and carry itself, got {other:?}"),
    }
}
