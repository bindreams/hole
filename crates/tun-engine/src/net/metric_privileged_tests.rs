//! Privileged-lane live proof for [`set_interface_metric`]: a real wintun
//! device, both families, read back via `GetIpInterfaceEntry` — the module
//! had no live coverage at all before this. Same shape as
//! `device::ipv6_addr_privileged_tests`.
//!
//! Runs on the elevated `tun` lane only (creating a wintun adapter needs
//! elevation): the `TUN` label gates it out of the `SKULD_LABELS="!tun"`
//! pass and into the `SKULD_LABELS="tun"` one.
//!
//! Deliberately NOT in the `global_net_state` nextest group: unlike the
//! IPv6-address test, this one only ever reads/writes the row keyed by its
//! own device's LUID, never anything host-global another concurrent test
//! could race.

use windows::Win32::Foundation::NO_ERROR;
use windows::Win32::NetworkManagement::IpHelper::{GetIpInterfaceEntry, MIB_IPINTERFACE_ROW};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

use super::{set_interface_metric, Family, MetricOutcome, TUNNEL_INTERFACE_METRIC};
use crate::{Device, MutDeviceConfig, TUN};

/// Deliberately NOT `hole-tun*` — see `device::ipv6_addr_privileged_tests`'s
/// module doc for why (`adapter_cleanup::remove_adapter` sweeps `hole-tun*`,
/// which would delete this test's adapter out from under a live production
/// teardown running on the same box).
const DEVICE_NAME: &str = "metrict-hole";

struct RemoveAdapter;
impl Drop for RemoveAdapter {
    fn drop(&mut self) {
        crate::adapter_cleanup::remove_adapter(DEVICE_NAME);
    }
}

/// Read the live `MIB_IPINTERFACE_ROW` for `luid`'s `family`.
fn read_row(luid: u64, ipv6: bool) -> MIB_IPINTERFACE_ROW {
    let af = if ipv6 { AF_INET6 } else { AF_INET };
    let mut row = MIB_IPINTERFACE_ROW {
        Family: af,
        InterfaceLuid: NET_LUID_LH { Value: luid },
        ..Default::default()
    };
    // SAFETY: `row` is a live out-parameter with its lookup keys set.
    let status = unsafe { GetIpInterfaceEntry(&mut row) };
    assert_eq!(
        status, NO_ERROR,
        "HARNESS: GetIpInterfaceEntry(family={ipv6}) failed with {}",
        status.0
    );
    row
}

/// Regression proof for the dropped `SitePrefixLength = 0` line: MSDN's
/// `SetIpInterfaceEntry` Remarks forbid round-tripping a nonzero
/// `SitePrefixLength` back unmodified. `Dispatcher::new` treats a failed
/// `set_interface_metric(V4)` as fatal to every Windows Full-mode connect,
/// so a regression here is a ship-blocking bug, not a cosmetic one.
#[skuld::test(labels = [TUN], serial = TUN)]
fn set_interface_metric_zeroes_site_prefix_length_and_sets_metric() {
    crate::device::wintun::ensure_loaded().expect("HARNESS: ensure_loaded (wintun.dll)");
    let _cleanup = RemoveAdapter;

    let device = Device::build(|c: &mut MutDeviceConfig| {
        c.tun_name = DEVICE_NAME.into();
        c.mtu = 1400;
        c.ipv4 = Some("10.255.2.1/24".parse().expect("literal"));
        c.ipv6 = Some("fda6:578a:3ba9::1/64".parse().expect("literal"));
    })
    .unwrap_or_else(|e| panic!("HARNESS: Device::build({DEVICE_NAME}) failed: {e}"));

    let luid = device.identity().luid();

    for family in [Family::V4, Family::V6] {
        let outcome = set_interface_metric(luid, TUNNEL_INTERFACE_METRIC, family)
            .unwrap_or_else(|e| panic!("set_interface_metric({family:?}) failed: {e}"));
        assert_eq!(
            outcome,
            MetricOutcome::Applied,
            "{family:?}'s interface row must exist immediately after Device::build created it"
        );

        let row = read_row(luid, family == Family::V6);
        assert_eq!(
            row.Metric, TUNNEL_INTERFACE_METRIC,
            "{family:?} metric must round-trip through SetIpInterfaceEntry"
        );
        assert_eq!(
            row.SitePrefixLength, 0,
            "{family:?} SitePrefixLength must be zeroed by set_interface_metric — MSDN forbids \
             round-tripping GetIpInterfaceEntry's own (possibly nonzero) value back unmodified"
        );
    }
}
