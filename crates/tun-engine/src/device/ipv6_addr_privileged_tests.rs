//! Privileged-lane oracle for the TUN interface's IPv6 address: it creates a
//! REAL wintun device and asks the kernel whether the address `Device::build`
//! assigned is on that interface and selectable as a source.
//!
//! It needs no IPv6 connectivity at all. The source-selection question is a
//! `/128` question answered by a packet-free UDP `connect` — the kernel's own
//! route and source lookup, the idiom `gateway::probe_ipv6` already uses. So a
//! red here is the product gap, not an IPv4-only runner; and a green here
//! while the full-tunnel transit oracle's IPv6 arm is red points at capture or
//! environment rather than at the address.
//!
//! Runs on the elevated `tun` lane only (creating a wintun adapter needs
//! elevation): the `TUN` label gates it out of the `SKULD_LABELS="!tun"` pass
//! and into the `SKULD_LABELS="tun"` one. NOT `#[ignore]`d and it does not skip
//! on missing privilege — opting out is the explicit `!tun` filter, and CI
//! provisions the elevation.
//!
//! Isolation is `serial = TUN` plus `.config/nextest.toml`'s `global_net_state`
//! group, which serializes it across test binaries. The device NAME buys none
//! of that: it is `ipv6t-hole` rather than anything under `hole-tun` only
//! because `adapter_cleanup::remove_adapter` sweeps `hole-tun*`, so a
//! production teardown running on the box would delete this test's adapter out
//! from under it.
//!
//! COUPLED NAMES: the test name below contains the substring
//! `tun_device_ipv6_`, which `.config/nextest.toml`'s `global_net_state` filter
//! matches. Renaming it without updating that filter silently drops it from the
//! group.
//!
//! There is no teardown assertion. `GetUnicastIpAddressEntry` is keyed on
//! `InterfaceIndex`, so after the interface departs it returns `ERROR_NOT_FOUND`
//! because the interface is gone — indistinguishable from the address having
//! been removed — and the interface-delete and the address-row removal are
//! separate publications with no documented ordering. Microsoft already
//! guarantees a `CreateUnicastIpAddressEntry` address is non-persistent and
//! lives only as long as the adapter; a persistence regression would surface as
//! the precondition below failing on the next run.

use std::net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket};

use smoltcp::wire::Ipv6Cidr;
use windows::Win32::Foundation::NO_ERROR;
use windows::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetUnicastIpAddressEntry, GetUnicastIpAddressTable, MIB_UNICASTIPADDRESS_ROW,
    MIB_UNICASTIPADDRESS_TABLE,
};
use windows::Win32::Networking::WinSock::{IpDadStatePreferred, AF_INET6, SOCKADDR_INET};

use super::{Assigned, Device, MutDeviceConfig};
use crate::{GLOBAL_NET_STATE, TUN};

/// Deliberately NOT `hole-tun*` — see the module doc.
const DEVICE_NAME: &str = "ipv6t-hole";

/// Generated the same way as production's `TUN_SUBNET6` and deliberately
/// different from it: a developer dogfooding Hole has a live `hole-tun` holding
/// the production ULA, which would fail the precondition below and send them to
/// clean an environment that is working correctly. This test proves the
/// mechanism — that `config.ipv6` reaches the OS interface. Production's own
/// literal is pinned by `hole_bridge::proxy::TUN_SUBNET6`'s unit test.
const TEST_CIDR: &str = "fda6:578a:3ba8::1/64";
const TEST_ADDR: Ipv6Addr = Ipv6Addr::new(0xfda6, 0x578a, 0x3ba8, 0, 0, 0, 0, 1);
/// A neighbour inside [`TEST_CIDR`]'s prefix, for the recorded on-link
/// measurement.
const TEST_NEIGHBOUR: Ipv6Addr = Ipv6Addr::new(0xfda6, 0x578a, 0x3ba8, 0, 0, 0, 0, 9);

/// Removes the adapter on every exit path, so a failed assertion cannot strand
/// it.
struct RemoveAdapter;
impl Drop for RemoveAdapter {
    fn drop(&mut self) {
        crate::adapter_cleanup::remove_adapter(DEVICE_NAME);
    }
}

/// Every AF_INET6 unicast address the host holds inside `prefix`, with the
/// interface index holding it.
fn addresses_inside(prefix: Ipv6Cidr) -> Vec<(u32, Ipv6Addr)> {
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    // SAFETY: `table` is a live out-parameter for a table IP Helper allocates.
    let status = unsafe { GetUnicastIpAddressTable(AF_INET6, &mut table) };
    assert_eq!(
        status, NO_ERROR,
        "HARNESS: GetUnicastIpAddressTable(AF_INET6) failed with {}",
        status.0
    );

    let mut found = Vec::new();
    // SAFETY: on `NO_ERROR` the table is non-null and `Table` is a flexible
    // array of `NumEntries` rows; it is freed before this block ends.
    unsafe {
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        for row in rows {
            let addr = Ipv6Addr::from(row.Address.Ipv6.sin6_addr.u.Byte);
            if prefix.contains_addr(&addr) {
                found.push((row.InterfaceIndex, addr));
            }
        }
        FreeMibTable(table.cast());
    }
    found
}

/// The unicast row for `addr` on `if_index`, or `None` when the interface does
/// not hold it.
fn address_row(if_index: u32, addr: Ipv6Addr) -> Option<MIB_UNICASTIPADDRESS_ROW> {
    let mut address = SOCKADDR_INET::default();
    address.Ipv6.sin6_family = AF_INET6;
    address.Ipv6.sin6_addr.u.Byte = addr.octets();
    let mut row = MIB_UNICASTIPADDRESS_ROW {
        Address: address,
        InterfaceIndex: if_index,
        ..Default::default()
    };
    // SAFETY: `row` is a live out-parameter with its lookup keys set.
    match unsafe { GetUnicastIpAddressEntry(&mut row) } {
        NO_ERROR => Some(row),
        _ => None,
    }
}

/// The source address the kernel would use to reach `dst`. The UDP `connect`
/// sends nothing and waits for nothing — it is a route and source lookup.
fn source_for(dst: Ipv6Addr) -> std::io::Result<SocketAddr> {
    let sock = UdpSocket::bind("[::]:0")?;
    sock.connect(SocketAddr::new(IpAddr::V6(dst), 80))?;
    sock.local_addr()
}

#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn tun_device_ipv6_address_is_assigned_and_selectable() {
    let cidr: Ipv6Cidr = TEST_CIDR.parse().expect("TEST_CIDR is a valid IPv6 CIDR");
    let prefix = Ipv6Cidr::new(Ipv6Addr::new(0xfda6, 0x578a, 0x3ba8, 0, 0, 0, 0, 0), cidr.prefix_len());

    // 1. Precondition. Prefix-scoped, not address-scoped: another interface
    //    holding a DIFFERENT address in the same prefix would create a
    //    competing on-link route and select the wrong source. Read through IP
    //    Helper rather than `default_net`, whose Windows enumeration skips
    //    adapters outside its `IfType` allow-list.
    let squatters = addresses_inside(prefix);
    assert!(
        squatters.is_empty(),
        "ENVIRONMENT: an interface already holds an address inside {prefix} — clean the box \
         (an adapter stranded by an earlier run, or a real network using this prefix). Found: {squatters:?}"
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("HARNESS: build tokio runtime");

    rt.block_on(async move {
        crate::device::wintun::ensure_loaded().expect("HARNESS: ensure_loaded (wintun.dll)");
        let _cleanup = RemoveAdapter;

        let device = Device::build(|c: &mut MutDeviceConfig| {
            c.tun_name = DEVICE_NAME.into();
            c.mtu = 1400;
            c.ipv4 = Some("10.255.1.1/24".parse().expect("literal"));
            c.ipv6 = Some(cidr);
        })
        .expect("HARNESS: Device::build");

        // 2. Assignment. Index-scoped, so nothing else on the box can satisfy
        //    it; `DadState` makes "assigned but tentative" a distinct failure
        //    from "not assigned".
        assert_eq!(
            device.ipv6_assigned(),
            Some(Assigned::Address),
            "Device::build must report the IPv6 address as assigned"
        );
        let index = device
            .interface_index()
            .expect("a device built with an IPv6 CIDR carries its interface index");
        let row = address_row(index, TEST_ADDR).unwrap_or_else(|| {
            panic!(
                "interface {index} holds no {TEST_ADDR} — this is the reported defect: the ::/1 and \
                 8000::/1 split routes point at an adapter with no IPv6 address to source from"
            )
        });
        assert_eq!(
            row.DadState, IpDadStatePreferred,
            "the address must not be tentative — duplicate address detection is skipped for it"
        );

        // 3. Selectable as a source. Compare `.ip()`, not the `SocketAddr`:
        //    `SocketAddrV6: PartialEq` includes `scope_id`, which comes back
        //    non-zero.
        let source = source_for(TEST_ADDR).expect("the kernel must find a source for the device's own address");
        assert_eq!(
            source.ip(),
            IpAddr::V6(TEST_ADDR),
            "the assigned address must be selectable as a source for itself"
        );

        // Recorded measurement, deliberately not an assertion: Microsoft
        // describes `OnLinkPrefixLength` as the address's prefix length and
        // documents no route side effect, so whether an on-link /64 route
        // follows is unverified. If this reports the ULA as the source, it can
        // be promoted to an assertion; if it reports NetworkUnreachable, the
        // /1 split routes are what carry the flow.
        eprintln!(
            "[tun_device_ipv6] on-link source lookup for the in-prefix neighbour {TEST_NEIGHBOUR}: {:?}",
            source_for(TEST_NEIGHBOUR)
        );
    });
}
