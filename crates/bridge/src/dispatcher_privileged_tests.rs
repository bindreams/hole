//! Privileged-lane proof that the TUN device [`Dispatcher::new`](super::Dispatcher::new)
//! asks the OS for is one the OS will actually create.
//!
//! `Dispatcher::new` is the first irreversible step of a Full-mode start — it
//! runs before `routing.install`, before either fail-closed cover, and before
//! `Dns::apply`. If the OS refuses the device, Full mode cannot start at all
//! and nothing downstream is ever reached. No test had ever asked a non-Windows
//! platform to create one (bindreams/hole#850).
//!
//! Drives `Dispatcher::new` rather than `Device::build` with a copied config:
//! the device name, subnet and MTU are chosen INSIDE the dispatcher, so a test
//! that rebuilt them would assert about its own copy. This asserts about
//! whatever the production path actually asks for.
//!
//! Runs on the elevated `tun` lane only — the `TUN` label (reused from
//! `crate::test_support::skuld_fixtures`, this crate's "elevated lane" bucket)
//! gates it, so the unprivileged `SKULD_LABELS="!tun"` pass excludes it and the
//! `SKULD_LABELS="tun"` pass runs it (Windows under CI's elevated token, macOS
//! under `sudo`). NOT `#[ignore]`d and does not skip on missing privilege: a
//! default `cargo nextest` run on an unprivileged box runs this and fails loud;
//! opting out is the explicit `!tun` filter, and CI provisions the privilege.
//!
//! COUPLED NAME: `.config/nextest.toml`'s `global-net-state` group matches this
//! test by the substring `dispatcher_opens_tun_`. Creating a real TUN is global
//! OS state (adapter name, interface index, and on macOS an automatic route for
//! the device subnet), so it must not run beside another real-device or
//! real-cover test. Rename only in lockstep with that filter.
//!
//! **Not covered here:** name coherence with downstream consumers.
//! `routing.install`, both covers and `Dns::apply` are each handed the
//! `TUN_DEVICE_NAME` constant, and nothing below proves the device the OS
//! actually created answers to that name.

use super::*;
use crate::filter::rules::RuleSet;
use crate::test_support::skuld_fixtures::TUN;
use garter::tracing_test::set_default_in_current_thread;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::{Layer, SubscriberExt};

/// The production Full-mode device open must succeed on every platform Hole
/// ships Full mode on.
///
/// Everything the dispatcher is handed besides the device is inert: no packet
/// ever flows, so `local_port` is never dialled and `iface_index` is only
/// stored on the bypass endpoint. The device open is the whole test.
#[skuld::test(labels = [TUN], serial = TUN)]
async fn dispatcher_opens_tun_device_the_os_accepts() {
    // DEBUG so a failure carries the device layer's own diagnostics, not just
    // the panic line.
    let subscriber = tracing_subscriber::registry().with(
        fmt::layer()
            .with_writer(std::io::stderr)
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::DEBUG),
    );
    let _guard = set_default_in_current_thread(subscriber);

    // Production preamble: `ProxyManager::start_inner` pre-loads wintun.dll
    // before reaching `Dispatcher::new`.
    #[cfg(target_os = "windows")]
    tun_engine::device::wintun::ensure_loaded().expect("wintun.dll must be resolvable");

    let mut dispatcher = Dispatcher::new(0, 0, false, None, false, RuleSet::default(), None).unwrap_or_else(|e| {
        panic!(
            "Full-mode start cannot open its TUN device on {}, so Full mode cannot start at all: {e}",
            std::env::consts::OS,
        )
    });

    // Drains the driver task, so the device handle is released here rather
    // than on the abort-only `Drop` fallback a current-thread runtime takes.
    dispatcher.shutdown().await;
}
