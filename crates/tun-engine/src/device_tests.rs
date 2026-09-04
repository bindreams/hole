//! Unprivileged unit tests for [`Device`](super::Device)'s pure helpers. The
//! device lifecycle itself needs elevation and a real driver; it is covered by
//! `device/ipv6_addr_privileged_tests.rs`.

use super::*;

#[skuld::test]
fn interface_index_from_accepts_a_positive_index() {
    assert_eq!(interface_index_from(Ok(42)).unwrap(), 42);
}

#[skuld::test]
fn interface_index_from_rejects_a_negative_index() {
    let err = interface_index_from(Ok(-1)).unwrap_err();
    let DeviceError::Ipv6Assign { message, .. } = &err else {
        panic!("expected Ipv6Assign, got {err:?}");
    };
    assert!(
        message.contains("-1"),
        "the message names the rejected value: {message}"
    );
}

/// `0` is a reserved sentinel — real interface indices start at 1 — so it is a
/// broken device handle, not a host without IPv6. Folding it into the tolerate
/// branch would read the two as the same thing.
#[skuld::test]
fn interface_index_from_rejects_the_zero_sentinel() {
    let err = interface_index_from(Ok(0)).unwrap_err();
    assert!(
        matches!(err, DeviceError::Ipv6Assign { .. }),
        "expected Ipv6Assign, got {err:?}"
    );
}

#[skuld::test]
fn interface_index_from_carries_a_failed_query_message() {
    let err = interface_index_from(Err("adapter handle closed".into())).unwrap_err();
    let DeviceError::Ipv6Assign { message, .. } = &err else {
        panic!("expected Ipv6Assign, got {err:?}");
    };
    assert!(
        message.contains("adapter handle closed"),
        "the driver's own message survives: {message}"
    );
}

/// An empty `Requested` name is still rejected before any OS call — the
/// validation this test guards runs ahead of `tun::create_as_async`, so it
/// needs no elevation to exercise.
#[skuld::test]
fn build_rejects_an_empty_requested_name() {
    let result = Device::build(|c| {
        c.tun_name = TunName::Requested(String::new());
        c.mtu = 1400;
        c.ipv4 = Some("10.255.0.1/24".parse().unwrap());
    });
    let err = match result {
        Ok(_) => panic!("expected InvalidConfig, got Ok"),
        Err(e) => e,
    };
    assert!(
        matches!(err, DeviceError::InvalidConfig(_)),
        "expected InvalidConfig, got {err:?}"
    );
}
