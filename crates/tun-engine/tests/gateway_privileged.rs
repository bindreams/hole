//! Privileged-lane proof that the upstream-route lookup can see a **wintun**
//! adapter.
//!
//! This is the one test that covers bindreams/hole#798's actual defect — see
//! `gateway/windows.rs`'s module doc for the full blind-spot story. Here, a
//! real wintun adapter proves the lookup can see an `IfType 53` interface,
//! which `default-net`'s allowlist could not.
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
//! COUPLED NAME: `.config/nextest.toml`'s `global_net_state` filter matches this
//! test by the `gateway_global_net_state_` prefix, serializing it against the
//! other tests that mutate global OS network state across binaries. Renaming it
//! without updating both that filter AND the `GLOBAL_NET_STATE` label below
//! would silently drop it from the group — which `cargo xtask
//! verify-global-net-state-labels` (run in CI, unprivileged) fails on.

hole_test_observability::register!();

fn main() {
    skuld::run_all();
}

#[skuld::label]
const TUN: skuld::Label;

/// Binds to `.config/nextest.toml`'s `global_net_state` test-group via
/// `cargo xtask verify-global-net-state-labels` — see that guard's own doc
/// for what it checks. This is a THIRD binary alongside the lib and
/// `hole-bridge`'s privileged tests, each needing its own declaration (skuld
/// requires exactly one per binary).
#[skuld::label]
const GLOBAL_NET_STATE: skuld::Label;

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::{GLOBAL_NET_STATE, TUN};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{channel, Sender};
    use std::sync::Arc;

    use windows::Win32::Foundation::{ERROR_NOT_FOUND, HANDLE, NO_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::{
        CancelMibChangeNotify2, ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex, GetUnicastIpAddressEntry,
        NotifyUnicastIpAddressChange, MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW,
    };
    use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows::Win32::Networking::WinSock::{
        IpDadStateDeprecated, IpDadStateDuplicate, IpDadStateInvalid, IpDadStatePreferred, AF_INET, SOCKADDR_INET,
    };

    /// Distinct from `WINDOWS_TUN_ALIAS` (`hole-tun`) so a concurrent bridge e2e,
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

    /// Owns both the registration handle and the boxed [`Sender`] its context
    /// pointer targets, so one `Drop` cancels the registration before the box
    /// releases — regardless of which order the two were constructed in.
    /// Declaration order alone does not give this: `tx` was declared before
    /// `notify` below, so a panic unwinding past both would drop `tx` (and
    /// free the box) FIRST, while the kernel-held registration still points
    /// into it — a leak turned into a use-after-free, reachable from every
    /// `panic!` in the `DadVerdict` match below, not just a happy-path
    /// return. Bundling them means there is no order left to get wrong.
    struct AddressChangeRegistration {
        notify: HANDLE,
        /// Never read after registration — kept alive only because `notify`
        /// holds a raw pointer into it until cancelled.
        _tx: Box<Sender<u32>>,
        /// Test-only observability: set once `Drop` confirms the cancel
        /// succeeded. `None` in the privileged test's real usage. A second
        /// real `CancelMibChangeNotify2` on an already-cancelled handle is
        /// itself unsafe (confirmed empirically: it corrupted the heap) —
        /// this flag is what lets `address_change_registration_cancels_on_drop_
        /// even_through_an_early_return` observe the cancel ran without
        /// touching the handle again.
        cancel_confirmed: Option<Arc<AtomicBool>>,
    }

    impl AddressChangeRegistration {
        /// Registers `tx` boxed, so its address is stable for the
        /// registration's context pointer.
        ///
        /// # Safety
        /// The boxed `tx` outlives the registration (this `Drop` cancels it
        /// before the box releases), so the callback's context pointer stays
        /// valid throughout.
        fn register(tx: Sender<u32>) -> Self {
            Self::register_with(tx, None)
        }

        fn register_with(tx: Sender<u32>, cancel_confirmed: Option<Arc<AtomicBool>>) -> Self {
            let tx = Box::new(tx);
            let mut notify = HANDLE::default();
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
            Self {
                notify,
                _tx: tx,
                cancel_confirmed,
            }
        }
    }

    impl Drop for AddressChangeRegistration {
        fn drop(&mut self) {
            // SAFETY: `self.notify` is the live handle `register`'s
            // successful call produced.
            let cancelled = unsafe { CancelMibChangeNotify2(self.notify) };
            // Gated on `!panicking()`: a failed cancel during unwind must not
            // itself panic — a second panic during unwind aborts the process,
            // destroying the ORIGINAL failure message this Drop is running to
            // preserve (a leaked, still-armed registration either way; abort
            // just also erases the diagnostic).
            if cancelled != NO_ERROR && !std::thread::panicking() {
                panic!("CancelMibChangeNotify2 failed: {cancelled:?}");
            }
            if cancelled == NO_ERROR {
                if let Some(flag) = &self.cancel_confirmed {
                    flag.store(true, Ordering::SeqCst);
                }
            }
            // `_tx` (and the box `notify`'s context pointer named) drops only
            // after this line — the registration is confirmed gone first.
        }
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

    #[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
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
        let registration = AddressChangeRegistration::register(tx);

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

        // The registration is no longer needed once the address is known
        // usable — dropped explicitly (rather than left to fall out of scope
        // after the assertions below) so it cannot be live, even briefly,
        // while `best_route` runs.
        drop(registration);

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
        // `TEST_DEST` is inside the adapter's own directly-attached subnet
        // (`TEST_CIDR`), so this route is on-link — Microsoft documents
        // `MIB_IPFORWARD_ROW2.NextHop` as unspecified for exactly that case.
        // `classify_hop` never reads `DestinationPrefix`, so a real on-link
        // route against a real kernel — not a fabricated `RouteHop` — is
        // what proves `NextHop::OnLink` (bindreams/hole#798's PR1) reaches
        // production from something the OS actually returned.
        assert!(
            hop.next_hop.is_unspecified(),
            "an on-link destination must resolve to an unspecified next hop, got {}",
            hop.next_hop
        );
    }

    /// Proves `AddressChangeRegistration`'s cancel-before-release ordering
    /// directly, without the elevation the privileged test above needs for
    /// `Device::build`. `NotifyUnicastIpAddressChange`/`CancelMibChangeNotify2`
    /// registration is itself unprivileged — only creating the wintun adapter
    /// needs the elevated token — so this is the ONE piece of that test
    /// reachable unelevated, and the ONLY one the leaked-callback defect
    /// actually lived in.
    ///
    /// Drops the guard via an early return (not the end of its natural
    /// scope — the same "control leaves before the happy-path cleanup"
    /// shape a `panic!` unwind has) and proves the cancel already ran, via
    /// `cancel_confirmed` — a second REAL `CancelMibChangeNotify2` on the
    /// same handle is not a safe way to observe this (confirmed empirically:
    /// it corrupted the heap on this box), so `Drop`'s own confirmation is
    /// the only sound signal. Mutates no OS routing/adapter state, so —
    /// unlike the test above — it carries neither `TUN` nor
    /// `GLOBAL_NET_STATE` and runs in the ordinary unprivileged pass.
    #[skuld::test]
    fn address_change_registration_cancels_on_drop_even_through_an_early_return() {
        fn construct_and_drop_early(tx: Sender<u32>, cancel_confirmed: Arc<AtomicBool>) {
            let _registration = AddressChangeRegistration::register_with(tx, Some(cancel_confirmed));
            // early return — exercises the same "control leaves before the
            // happy-path cleanup" shape a `panic!` unwind has, dropping
            // `_registration` here rather than at some later, explicit point.
        }

        let (tx, _rx) = channel::<u32>();
        let cancel_confirmed = Arc::new(AtomicBool::new(false));
        construct_and_drop_early(tx, Arc::clone(&cancel_confirmed));

        assert!(
            cancel_confirmed.load(Ordering::SeqCst),
            "the registration's Drop must have cancelled it by the time the early return returns"
        );
    }
}
