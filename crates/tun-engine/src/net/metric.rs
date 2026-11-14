//! Give `hole-tun` the lowest interface metric, per address family, so
//! Windows prefers whatever resolver Hole advertises over the physical
//! adapter's (the negative half is `crate::dns_confine`).
//!
//! The metric is set here rather than through `tun::Configuration::metric`:
//! `tun` swallows `ERROR_NOT_FOUND` on the IPv6 call into a `log` record Hole
//! never surfaces. Here absence is a returned value,
//! [`MetricOutcome::NoInterfaceRow`], which the caller logs at `warn!`.
//!
//! That removes the silent part of the failure, not the race: the IPv6
//! interface row may not exist yet when this runs, so the IPv6 outcome is
//! timing-dependent, and no test asserts the row is present. See
//! `docs/contributing/architecture/tun-device.md`.

use std::io;

use windows::Win32::Foundation::{ERROR_NOT_FOUND, ERROR_SUCCESS};
use windows::Win32::NetworkManagement::IpHelper::{GetIpInterfaceEntry, SetIpInterfaceEntry, MIB_IPINTERFACE_ROW};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

/// The metric `Dispatcher::new` requests for `hole-tun`, both families: the
/// lowest value the OS accepts, not a tuned rank.
pub const TUNNEL_INTERFACE_METRIC: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

/// What [`set_interface_metric`] actually did. `NoInterfaceRow` is a value
/// the caller must handle, not a swallowed warning — see the module doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricOutcome {
    Applied,
    NoInterfaceRow,
}

/// Map a raw `GetIpInterfaceEntry`/`SetIpInterfaceEntry` status to a typed
/// outcome. `ERROR_NOT_FOUND` — no interface row for this LUID/family yet —
/// is `Ok(NoInterfaceRow)`; every other non-success status is `Err`. Pure,
/// so the two mapping tests need no FFI.
fn classify_metric_status(status: u32) -> io::Result<MetricOutcome> {
    if status == ERROR_SUCCESS.0 {
        return Ok(MetricOutcome::Applied);
    }
    if status == ERROR_NOT_FOUND.0 {
        return Ok(MetricOutcome::NoInterfaceRow);
    }
    Err(io::Error::from_raw_os_error(status as i32))
}

/// Set `hole-tun`'s (identified by `luid`) `family` metric to `metric`.
/// Reads the current `MIB_IPINTERFACE_ROW` first (required by
/// `SetIpInterfaceEntry` — most of its fields must round-trip unchanged),
/// then writes back with `Metric` and `UseAutomaticMetric` overridden. A
/// `GetIpInterfaceEntry` `ERROR_NOT_FOUND` short-circuits to
/// `Ok(NoInterfaceRow)` without attempting the set.
pub fn set_interface_metric(luid: u64, metric: u32, family: Family) -> io::Result<MetricOutcome> {
    let af = match family {
        Family::V4 => AF_INET,
        Family::V6 => AF_INET6,
    };
    let mut row = MIB_IPINTERFACE_ROW {
        Family: af,
        InterfaceLuid: NET_LUID_LH { Value: luid },
        ..Default::default()
    };

    // SAFETY: `row` is an owned, stack-allocated struct whose address is
    // valid for the duration of the call; `Family`/`InterfaceLuid` are the
    // documented lookup key fields for this FFI.
    let rc = unsafe { GetIpInterfaceEntry(&mut row) };
    match classify_metric_status(rc.0)? {
        MetricOutcome::NoInterfaceRow => return Ok(MetricOutcome::NoInterfaceRow),
        MetricOutcome::Applied => {}
    }

    // MSDN's `SetIpInterfaceEntry` Remarks: an application must not try to
    // modify `SitePrefixLength`; it must be set to 0. `GetIpInterfaceEntry`
    // above can return a nonzero value (measured: 64 on a real IPv4
    // interface), and round-tripping it back unmodified is exactly what
    // that Remark forbids.
    row.SitePrefixLength = 0;
    row.Metric = metric;
    row.UseAutomaticMetric = false;

    // SAFETY: `row` was just populated by the successful `GetIpInterfaceEntry`
    // call above and then had only `Metric`/`UseAutomaticMetric` overridden —
    // every other field round-trips unchanged, which is what
    // `SetIpInterfaceEntry` requires.
    let rc = unsafe { SetIpInterfaceEntry(&mut row) };
    classify_metric_status(rc.0)
}

#[cfg(test)]
#[path = "metric_tests.rs"]
mod metric_tests;

#[cfg(test)]
#[path = "metric_privileged_tests.rs"]
mod metric_privileged_tests;
