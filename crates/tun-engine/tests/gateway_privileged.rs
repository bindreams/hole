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

    use windows::Win32::Foundation::{HANDLE, NO_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::{
        CancelMibChangeNotify2, ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex, NotifyUnicastIpAddressChange,
        MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW,
    };
    use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows::Win32::Networking::WinSock::{
        IpDadStateDeprecated, IpDadStateDuplicate, IpDadStateInvalid, IpDadStatePreferred, AF_INET,
    };

    /// Distinct from `TUN_DEVICE_NAME` (`hole-tun`) so a concurrent bridge e2e,
    /// the adapter-cleanup sweep, and this test can never target each other's
    /// adapter.
    const TEST_ADAPTER: &str = "hole-test-gw";
    /// Distinct from `TUN_SUBNET` (`10.255.0.1/24`), same reason.
    const TEST_CIDR: &str = "10.254.0.1/24";
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

    enum DadOutcome {
        Usable,
        Rejected(i32),
    }

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
        // duration of the callback.
        let tx = unsafe { &*(context as *const Sender<DadOutcome>) };
        let row = unsafe { &*row };

        if Some(row.InterfaceIndex) != adapter_index() {
            return;
        }
        // Every TERMINAL DAD state is reported, not just success. Waiting only
        // for `Preferred` would never return if the address were rejected, and
        // an unbounded wait is precisely the shape this codebase forbids.
        let outcome = match row.DadState {
            s if s == IpDadStatePreferred || s == IpDadStateDeprecated => DadOutcome::Usable,
            s if s == IpDadStateDuplicate || s == IpDadStateInvalid => DadOutcome::Rejected(s.0),
            _ => return, // Tentative — not yet terminal.
        };
        let _ = tx.send(outcome);
    }

    /// The test adapter's interface index, or `None` while it does not exist.
    fn adapter_index() -> Option<u32> {
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
        Some(index)
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
        let (tx, rx) = channel::<DadOutcome>();
        let tx = Box::new(tx);
        let mut notify = HANDLE::default();
        // SAFETY: `tx` is boxed and outlives the registration (cancelled below),
        // so the callback's context pointer stays valid throughout.
        let status = unsafe {
            NotifyUnicastIpAddressChange(
                AF_INET,
                Some(on_address_change),
                Some(&*tx as *const Sender<DadOutcome> as *const core::ffi::c_void),
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

        // Rendezvous on the OS publishing a terminal DAD state, not on a sleep
        // or a poll: `GetBestRoute2` needs a valid unicast source on the
        // interface, so asserting while the address is still `Tentative` would
        // be a race.
        match rx.recv().expect("the channel outlives the registration") {
            DadOutcome::Usable => {}
            DadOutcome::Rejected(state) => panic!(
                "the test adapter's address was rejected by DAD (state {state}) — \
                 is {TEST_CIDR} already in use on this host?"
            ),
        }

        // SAFETY: `notify` is the live handle from the registration above.
        let cancelled = unsafe { CancelMibChangeNotify2(notify) };
        assert_eq!(cancelled, NO_ERROR, "CancelMibChangeNotify2 failed: {cancelled:?}");
        drop(tx);

        let expected = adapter_index().expect("the test adapter must resolve after creation");

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
