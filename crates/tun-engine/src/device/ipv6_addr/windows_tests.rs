//! Unprivileged unit tests for the Windows IPv6 assignment. They build and
//! classify; they call no IP Helper mutator, so they run on the `!tun` lane.

use std::cell::Cell;

use windows::Win32::Networking::WinSock::IpDadStateInvalid;

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

// The assign seam -----------------------------------------------------------------------------------------------------

// An interface with IPv6 unbound is not a state a test can create, so the
// verdict is injected rather than provoked — the same reason the `Routing` and
// `Dns` traits exist.

fn test_cidr() -> Ipv6Cidr {
    "fda6:578a:3ba8::1/64".parse().unwrap()
}

#[skuld::test]
fn never_appeared_skips_the_address_and_reports_it() {
    let created = Cell::new(false);
    let verdict = assign_with(
        42,
        test_cidr(),
        || Appearance::NeverAppeared,
        |_row| {
            created.set(true);
            NO_ERROR
        },
    )
    .unwrap();

    assert_eq!(verdict, Assigned::Ipv6StackAbsent);
    assert!(
        !created.get(),
        "no address is created for an interface with no IPv6 half"
    );
}

/// The same host condition as `NeverAppeared`, reached through the create call
/// instead of the wait.
#[skuld::test]
fn an_unsupported_create_reports_the_stack_absent() {
    let verdict = assign_with(42, test_cidr(), || Appearance::Appeared, |_row| ERROR_NOT_SUPPORTED).unwrap();
    assert_eq!(verdict, Assigned::Ipv6StackAbsent);
}

/// Once the interface has appeared, a failure is a real failure — not "no IPv6
/// here". That separation is what the wait exists for.
#[skuld::test]
fn a_failed_create_is_fatal() {
    match assign_with(42, test_cidr(), || Appearance::Appeared, |_row| ERROR_NOT_FOUND).unwrap_err() {
        DeviceError::Ipv6Assign { index, message } => {
            assert_eq!(index, 42);
            assert!(
                message.contains(&ERROR_NOT_FOUND.0.to_string()),
                "the Win32 code survives into the message: {message}"
            );
        }
        other => panic!("expected Ipv6Assign, got {other:?}"),
    }
}

/// A wait that could not be performed says nothing about the interface, so it
/// must not be laundered into "this host has no IPv6 stack".
#[skuld::test]
fn a_failed_wait_is_fatal() {
    let created = Cell::new(false);
    let err = assign_with(
        42,
        test_cidr(),
        || Appearance::Failed(ERROR_NOT_SUPPORTED),
        |_row| {
            created.set(true);
            NO_ERROR
        },
    )
    .unwrap_err();

    assert!(matches!(err, DeviceError::Ipv6Assign { .. }), "got {err:?}");
    assert!(!created.get(), "a failed wait must not proceed to the create");
}

#[skuld::test]
fn an_appeared_interface_creates_the_address_once() {
    let calls = Cell::new(0u32);
    let dad = Cell::new(IpDadStateInvalid);
    let verdict = assign_with(
        42,
        test_cidr(),
        || Appearance::Appeared,
        |row| {
            calls.set(calls.get() + 1);
            dad.set(row.DadState);
            NO_ERROR
        },
    )
    .unwrap();

    assert_eq!(verdict, Assigned::Address);
    assert_eq!(calls.get(), 1);
    assert_eq!(dad.get(), IpDadStatePreferred, "the address is never tentative");
}
