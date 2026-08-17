//! Privileged-lane proof that the upstream-route lookup can see a **wintun**
//! adapter.
//!
//! This is the one test that covers bindreams/hole#798's actual defect. The
//! `default-net` crate this replaced enumerated adapters through
//! `GetAdaptersAddresses` and silently skipped every one whose `IfType` was
//! absent from its own hard-coded allowlist. Wintun reports
//! `IF_TYPE_PROP_VIRTUAL` (53), which is not in that list, so an adapter of
//! exactly this kind was invisible to it, and a user whose default route ran
//! through one got `"Default Interface not found"`. A lookup that asks the OS
//! cannot have that blind spot — and here is the adapter that proves it.
//!
//! **It never touches the default route.** The property under test is "can this
//! lookup name an `IfType 53` adapter", not "what happens when one owns the
//! default route" — and hijacking a runner's (or a dev box's) default route to
//! ask the second question would sever the machine. Creating the adapter with an
//! address is enough: Windows installs the on-link subnet route itself, so a
//! lookup into that subnet must land on the adapter. No `route add`, and
//! therefore no route to leak.
//!
//! Its own binary rather than a module in the lib test binary: skuld validates
//! that a label is declared once per binary, and the lib already declares `TUN`
//! in `routing/failclosed/lockdown_privileged_tests.rs`. Keeping this separate
//! also leaves that file — contended by bindreams/hole#832 — untouched.
//!
//! Runs on the elevated `tun` lane only: creating a wintun adapter needs the
//! elevated token. Not `#[ignore]`d, and it does not skip on missing privilege —
//! a default run on an unelevated box runs it and fails loud; opting out is the
//! explicit `SKULD_LABELS="!tun"` filter, and CI provisions the elevation.
//!
//! COUPLED NAME: `.config/nextest.toml`'s `global-net-state` filter matches this
//! test by the `gateway_global_net_state_` prefix, serializing it against the
//! other tests that mutate global OS network state across binaries. Renaming it
//! without updating that filter would silently drop it from the group — which
//! `nextest_group_filter_covers_every_serialized_net_test` (tun-engine lib,
//! unprivileged) fails on.

hole_test_observability::register!();

fn main() {
    skuld::run_all();
}

#[skuld::label]
const TUN: skuld::Label;

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::TUN;
    use std::sync::mpsc::{channel, Sender};

    use windows::Win32::Foundation::{ERROR_NOT_FOUND, HANDLE, NO_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::{
        CancelMibChangeNotify2, ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex, GetUnicastIpAddressEntry,
        NotifyUnicastIpAddressChange, MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW,
    };
    use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows::Win32::Networking::WinSock::{
        IpDadStateDeprecated, IpDadStateDuplicate, IpDadStateInvalid, IpDadStatePreferred, AF_INET, SOCKADDR_INET,
    };

    /// Distinct from `TUN_DEVICE_NAME` (`hole-tun`) so a concurrent bridge e2e,
    /// the adapter-cleanup sweep, and this test can never target each other's
    /// adapter.
    const TEST_ADAPTER: &str = "hole-test-gw";
    /// Distinct from `TUN_SUBNET` (`10.255.0.1/24`), same reason.
    const TEST_CIDR: &str = "10.254.0.1/24";
    /// The address inside `TEST_CIDR`, as `GetUnicastIpAddressEntry` needs it.
    const TEST_ADDR: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 254, 0, 1);
    /// Inside `TEST_CIDR`, so the on-link route Windows creates for the adapter
    /// is the route this lookup must find.
    const TEST_DEST: &str = "10.254.0.7";

    /// Removes the adapter on the way out, including on panic — a leaked wintun
    /// adapter is exactly the residue `diagnostics::ndis` reports as a teardown
    /// leak, so a failing test must not manufacture one.
    struct AdapterGuard;

    impl Drop for AdapterGuard {
        fn drop(&mut self) {
            tun_engine::adapter_cleanup::remove_adapter(TEST_ADAPTER);
        }
    }

    /// What the address's DAD state means for this test, read from the
    /// authoritative entry rather than from the notification.
    enum DadVerdict {
        /// Usable as a source address, so `GetBestRoute2` can resolve through
        /// this interface.
        Usable,
        /// DAD found another host holding the address.
        Duplicate,
        /// The stack rejected the address outright.
        Invalid,
        /// `GetUnicastIpAddressEntry` itself failed.
        QueryFailed(u32),
        /// DAD is still running, or the address is not registered yet. The only
        /// state worth waiting through — wait for the next notification.
        Pending,
    }

    /// The notification callback.
    ///
    /// **It must not read `DadState`.** `NotifyUnicastIpAddressChange`'s contract
    /// is that the row handed to the callback "contains incomplete data ... only
    /// enough information that an application can call
    /// `GetUnicastIpAddressEntry`": exactly `Address`, `InterfaceLuid` and
    /// `InterfaceIndex`. Every other member — `DadState` included — is left at
    /// its zero value, and `IpDadStateInvalid` IS zero, so reading it here
    /// reports a rejection on every single notification. That is what made the
    /// first version of this test fail deterministically while claiming the
    /// subnet was already in use.
    ///
    /// So the callback forwards only the interface index and the main thread
    /// does the authoritative query. Keeping it to a channel send also respects
    /// the documented rule that `CancelMibChangeNotify2` must never be reached
    /// from the callback thread.
    unsafe extern "system" fn on_address_change(
        context: *const core::ffi::c_void,
        row: *const MIB_UNICASTIPADDRESS_ROW,
        _kind: MIB_NOTIFICATION_TYPE,
    ) {
        if context.is_null() || row.is_null() {
            return;
        }
        // SAFETY: `context` is the boxed `Sender` passed to
        // `NotifyUnicastIpAddressChange`, kept alive until after
        // `CancelMibChangeNotify2`. `row` is kernel-owned and valid for the
        // duration of the callback; `InterfaceIndex` is one of the three members
        // the API documents as populated.
        let tx = unsafe { &*(context as *const Sender<u32>) };
        let index = unsafe { (*row).InterfaceIndex };
        let _ = tx.send(index);
    }

    /// Ask for the COMPLETE entry, which is the only place `DadState` is real.
    fn dad_verdict(luid: NET_LUID_LH, index: u32) -> DadVerdict {
        let mut row = MIB_UNICASTIPADDRESS_ROW {
            Address: ipv4_sockaddr(TEST_ADDR),
            InterfaceLuid: luid,
            InterfaceIndex: index,
            ..Default::default()
        };
        // SAFETY: `row` is an owned local seeded with the three members
        // `GetUnicastIpAddressEntry` requires as input.
        let status = unsafe { GetUnicastIpAddressEntry(&mut row) };
        if status == ERROR_NOT_FOUND {
            // The address has not been registered yet — the adapter's creation
            // notification can arrive first.
            return DadVerdict::Pending;
        }
        if status != NO_ERROR {
            return DadVerdict::QueryFailed(status.0);
        }
        match row.DadState {
            s if s == IpDadStatePreferred || s == IpDadStateDeprecated => DadVerdict::Usable,
            s if s == IpDadStateDuplicate => DadVerdict::Duplicate,
            s if s == IpDadStateInvalid => DadVerdict::Invalid,
            // Tentative — the documented transient.
            _ => DadVerdict::Pending,
        }
    }

    /// The test adapter's LUID and interface index, or `None` while it does not
    /// exist yet.
    fn adapter_identity() -> Option<(NET_LUID_LH, u32)> {
        let alias = windows::core::HSTRING::from(TEST_ADAPTER);
        let mut luid = NET_LUID_LH::default();
        // SAFETY: both calls take a live reference in and write an owned local.
        if unsafe { ConvertInterfaceAliasToLuid(&alias, &mut luid) } != NO_ERROR {
            return None;
        }
        let mut index = 0u32;
        if unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) } != NO_ERROR {
            return None;
        }
        Some((luid, index))
    }

    fn ipv4_sockaddr(addr: std::net::Ipv4Addr) -> SOCKADDR_INET {
        let mut sa = SOCKADDR_INET::default();
        sa.Ipv4.sin_family = AF_INET;
        sa.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(addr.octets());
        sa
    }

    #[skuld::test(labels = [TUN], serial = TUN)]
    fn gateway_global_net_state_best_route_sees_a_wintun_adapter() {
        // A previously crashed run could have left the adapter behind; removing
        // it first makes this idempotent rather than order-dependent.
        tun_engine::adapter_cleanup::remove_adapter(TEST_ADAPTER);

        // `Device::build` does NOT pre-load wintun.dll — production calls this
        // separately, and the `tun` crate's bare `LoadLibraryExW("wintun.dll")`
        // would fail from the test binary's directory. `resolve_wintun_path`
        // falls back to the repo's `.cache/wintun/wintun.dll`, which covers it.
        tun_engine::device::wintun::ensure_loaded().expect("wintun.dll must load (run `cargo xtask deps`)");

        // Registered BEFORE the adapter exists, so the address's DAD transition
        // cannot be missed in the gap between creation and subscription.
        let (tx, rx) = channel::<u32>();
        let tx = Box::new(tx);
        let mut notify = HANDLE::default();
        // SAFETY: `tx` is boxed and outlives the registration (cancelled below),
        // so the callback's context pointer stays valid throughout.
        let status = unsafe {
            NotifyUnicastIpAddressChange(
                AF_INET,
                Some(on_address_change),
                Some(&*tx as *const Sender<u32> as *const core::ffi::c_void),
                false,
                &mut notify,
            )
        };
        assert_eq!(status, NO_ERROR, "NotifyUnicastIpAddressChange failed: {status:?}");

        let _guard = AdapterGuard;
        let _device = tun_engine::Device::build(|c| {
            c.tun_name = TEST_ADAPTER.into();
            c.mtu = 1400;
            c.ipv4 = Some(TEST_CIDR.parse().unwrap());
        })
        .expect("creating a wintun adapter requires elevation");

        // Rendezvous on the OS publishing a TERMINAL DAD state — never a sleep
        // and never a poll. `GetBestRoute2` requires a valid unicast source on
        // the interface, so asserting while the address is still `Tentative`
        // would be a race.
        //
        // The notification only reports THAT something changed; `dad_verdict`
        // does the authoritative `GetUnicastIpAddressEntry` query, because the
        // row handed to the callback leaves `DadState` zeroed and zero is
        // `IpDadStateInvalid` (see `on_address_change`).
        //
        // Checks BEFORE blocking, so an address that is already usable by the
        // time `Device::build` returns needs no notification at all. Registering
        // the callback before creating the adapter means any change after the
        // check is already queued, so nothing can be missed in between. Every
        // terminal verdict panics, so this cannot wait forever on an address the
        // stack rejected.
        let expected = loop {
            if let Some((luid, index)) = adapter_identity() {
                match dad_verdict(luid, index) {
                    DadVerdict::Usable => break index,
                    DadVerdict::Duplicate => panic!(
                        "{TEST_ADDR} is already in use on this host (DAD reported a duplicate); pick a different subnet than {TEST_CIDR}"
                    ),
                    DadVerdict::Invalid => panic!(
                        "the stack rejected {TEST_ADDR} as invalid — this is NOT an address collision; check the adapter's IP configuration"
                    ),
                    DadVerdict::QueryFailed(code) => {
                        panic!("GetUnicastIpAddressEntry failed for {TEST_ADDR} with status {code}")
                    }
                    DadVerdict::Pending => {}
                }
            }
            // Not usable yet: block until the OS reports another change, then
            // re-read the authoritative state.
            rx.recv().expect("the channel outlives the registration");
        };

        // SAFETY: `notify` is the live handle from the registration above.
        let cancelled = unsafe { CancelMibChangeNotify2(notify) };
        assert_eq!(cancelled, NO_ERROR, "CancelMibChangeNotify2 failed: {cancelled:?}");
        drop(tx);

        let hop = tun_engine::gateway::best_route(TEST_DEST.parse().unwrap())
            .expect("route lookup must not fail")
            .expect("Windows installs an on-link route for the adapter's own subnet");

        assert_eq!(
            hop.interface_index, expected,
            "the lookup named interface {} instead of the wintun adapter {expected} — that is \
             the #798 blind spot: an IfType 53 adapter the enumeration cannot see",
            hop.interface_index
        );
        assert_eq!(hop.interface_alias, TEST_ADAPTER);
    }
}
