//! Privileged-lane proof that the TUN device [`Dispatcher::new`](super::Dispatcher::new)
//! asks the OS for is one the OS will actually create, AND that the device's
//! reported identity actually names the interface the OS created.
//!
//! `Dispatcher::new` is the first irreversible step of a Full-mode start — it
//! runs before `routing.install`, before either fail-closed cover, and before
//! `Dns::apply`. If the OS refuses the device, Full mode cannot start at all
//! and nothing downstream is ever reached. No test had ever asked a
//! non-Windows platform to create one before this file (bindreams/hole#850).
//!
//! Drives `Dispatcher::new` rather than `Device::build` with a copied config:
//! the device name, subnet and MTU are chosen INSIDE the dispatcher, so a test
//! that rebuilt them would assert about its own copy. Both tests below assert
//! about whatever the production path actually asks for.
//!
//! `dispatcher_opens_tun_device_the_os_accepts` is #864's originally-authored
//! test, harvested here unchanged in intent: the device open (and clean
//! shutdown) must succeed on every platform Hole ships Full mode on.
//! `dispatcher_opens_tun_names_the_interface_it_opened` closes the
//! name-coherence gap #864's own doc explicitly left open: it resolves
//! `identity().alias()` back to a live OS interface through
//! [`tun_engine::gateway::interface_index_by_name`] — the same Windows
//! `ConvertInterfaceAliasToLuid`+`ConvertInterfaceLuidToIndex` / macOS
//! `if_nametoindex` lookup production route-install already trusts, made
//! `pub` for this test rather than reimplemented against raw platform FFI —
//! and, on macOS, that the resolved name has the kernel-assigned `utunN`
//! shape Task 6 now actually requests (closes #850), rather than falling
//! back to the constant Task 6 renamed to `WINDOWS_TUN_ALIAS` because it is
//! meaningless off Windows.
//!
//! Runs on the elevated `tun` lane only — the `TUN` label (reused from
//! `crate::test_support::skuld_fixtures`, this crate's "elevated lane" bucket)
//! gates it, so the unprivileged `SKULD_LABELS="!tun"` pass excludes it and the
//! `SKULD_LABELS="tun"` pass runs it (Windows under CI's elevated token, macOS
//! under `sudo`). NOT `#[ignore]`d and does not skip on missing privilege: a
//! default `cargo nextest` run on an unprivileged box runs this and fails loud;
//! opting out is the explicit `!tun` filter, and CI provisions the privilege.
//!
//! COUPLED NAMES: both test names below share the substring
//! `dispatcher_opens_tun_`, which `.config/nextest.toml`'s `global_net_state`
//! test-group filter matches — creating a real TUN is global OS state (adapter
//! name, interface index, and on macOS an automatic route for the device
//! subnet), so it must not run beside another real-device or real-cover test.
//! `cargo xtask verify-global-net-state-labels` binds that name-substring
//! membership to the `GLOBAL_NET_STATE` skuld label carried on both tests
//! (bindreams/hole#894) — rename either only in lockstep with the other AND
//! with the filter.

#![allow(clippy::disallowed_methods)] // this fixture builds its own root cancel token; see clippy.toml

use super::*;
use crate::filter::rules::RuleSet;
use crate::test_support::skuld_fixtures::{GLOBAL_NET_STATE, TUN};
use garter::tracing_test::set_default_in_current_thread;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::{Layer, SubscriberExt};

/// DEBUG-level per-test subscriber, so a device-open failure below carries
/// the device layer's own diagnostics, not just the panic line. Returns the
/// guard: the caller must keep it alive (`let _guard = ...`) for the whole
/// test body, not just this call.
fn debug_subscriber_guard() -> tracing::subscriber::DefaultGuard {
    let subscriber = tracing_subscriber::registry().with(
        fmt::layer()
            .with_writer(std::io::stderr)
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::DEBUG),
    );
    set_default_in_current_thread(subscriber)
}

/// Opens the dispatcher via the exact production call
/// `ProxyManager::start_inner` makes for a Full-mode start. Everything besides
/// the device is inert: no packet ever flows, so `local_port` is never
/// dialled and `iface_index` is only stored on the bypass endpoint.
async fn open_dispatcher_the_production_way() -> Dispatcher {
    // Production preamble: `ProxyManager::start_inner` pre-loads wintun.dll
    // before reaching `Dispatcher::new`.
    #[cfg(target_os = "windows")]
    tun_engine::device::wintun::ensure_loaded().expect("wintun.dll must be resolvable");

    let cancel = CancellationToken::new();
    Dispatcher::new(0, 0, false, None, false, RuleSet::default(), None, &cancel)
        .await
        .unwrap_or_else(|e| {
            panic!(
                "Full-mode start cannot open its TUN device on {}, so Full mode cannot start at all: {e}",
                std::env::consts::OS,
            )
        })
        .expect("HARNESS: cancel token was never cancelled, so build_or_cancel cannot return None")
}

/// The production Full-mode device open must succeed on every platform Hole
/// ships Full mode on. The device open is the whole test; drained rather than
/// dropped, so the device handle is released here rather than on the
/// abort-only `Drop` fallback a current-thread runtime takes.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
async fn dispatcher_opens_tun_device_the_os_accepts() {
    let _guard = debug_subscriber_guard();
    let mut dispatcher = open_dispatcher_the_production_way().await;
    dispatcher.shutdown().await;
}

/// The name-coherence gap #864 explicitly left open: the dispatcher's own
/// `identity().alias()` — not a name this test picked — must resolve, through
/// the OS's own interface-name table, to the live interface the dispatcher
/// just opened; and on macOS, where the name is kernel-assigned rather than
/// the fixed constant Windows still requests, it must have the `utunN` shape
/// `man 4 utun` documents rather than falling back to `hole-tun`.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
async fn dispatcher_opens_tun_names_the_interface_it_opened() {
    let _guard = debug_subscriber_guard();
    let mut dispatcher = open_dispatcher_the_production_way().await;

    let alias = dispatcher.identity().alias().to_string();
    let index = tun_engine::gateway::interface_index_by_name(&alias).unwrap_or_else(|e| {
        panic!("identity().alias() {alias:?} must resolve to a live OS interface via the OS's own name table: {e}")
    });
    assert!(
        index > 0,
        "resolved interface index for {alias:?} must be positive, got {index}"
    );

    #[cfg(target_os = "macos")]
    {
        assert_ne!(
            alias, "hole-tun",
            "KernelAssigned must read the real OS-assigned name back, not fall back to the Windows-only alias"
        );
        let suffix = alias.strip_prefix("utun").unwrap_or_else(|| {
            panic!("expected a name of the form utunN (man 4 utun / UTUN_OPT_IFNAME read-back), got {alias:?}")
        });
        suffix
            .parse::<u32>()
            .unwrap_or_else(|e| panic!("the utun suffix must parse as u32, got {suffix:?} in {alias:?}: {e}"));
    }

    dispatcher.shutdown().await;
}
