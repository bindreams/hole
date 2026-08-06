// `CancellationToken::new` is the cancel-test harness root; module-level
// allow per clippy.toml's "Bridge cancellation contract" sanctioned-
// test-file exception.
#![allow(clippy::disallowed_methods)]

use std::net::SocketAddr;

use tokio_util::sync::CancellationToken;
use tracing_subscriber::layer::{Layer, SubscriberExt};

use super::{proxy_err_to_io_err, recover_exit_detail, spawn_plugin_runner_at, start_plugin_chain};
use crate::proxy::ProxyError;
use crate::test_support::log_capture::VecWriter;

// recover_exit_detail (the shared join-and-recover logic both new arms call) ==========================================

#[skuld::test]
async fn recover_exit_detail_surfaces_the_specific_reason() {
    let handle = tokio::spawn(async { Err(garter::Error::Chain("the specific reason".into())) });
    assert_eq!(recover_exit_detail(handle).await, "the specific reason");
}

#[skuld::test]
async fn recover_exit_detail_falls_back_when_handle_has_nothing_better() {
    let handle: tokio::task::JoinHandle<garter::Result<()>> = tokio::spawn(async { Ok(()) });
    assert_eq!(recover_exit_detail(handle).await, garter::EXITED_BEFORE_READY_DETAIL);
}

// A panicking (or aborted) handle is distinct from "exited cleanly with no
// diagnosis" — both fall back to the same placeholder text, but the panic
// itself must not be silently absorbed with zero logging: this pins BOTH
// the fallback text AND that the `tracing::error!` call actually fires
// (the two arms are otherwise indistinguishable by their string output).
#[skuld::test]
async fn recover_exit_detail_falls_back_when_the_handle_panicked() {
    let writer = VecWriter::new();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::ERROR),
    );
    let detail = {
        let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);
        let handle: tokio::task::JoinHandle<garter::Result<()>> = tokio::spawn(async { panic!("boom") });
        recover_exit_detail(handle).await
    };
    assert_eq!(detail, garter::EXITED_BEFORE_READY_DETAIL);
    let output = writer.snapshot_string();
    assert!(
        output.contains("plugin-driving task ended abnormally"),
        "expected an error-level log for the panic, got:\n{output}"
    );
}

// `start_plugin_chain`'s own `inject_plugin_directives` pre-validates
// SS_PLUGIN_OPTIONS for every plugin name, so a malformed string never
// reaches `BinaryPlugin::sip003_env` through that entry point — these tests
// call the lower-level `spawn_plugin_runner_at` directly to exercise
// `sip003_env`'s own fallibility and pin what actually surfaces when its
// `Err` beats the chain-level ready oneshot.
async fn spawn_with_malformed_options(diagnostic_tap: bool) -> String {
    let cancel = CancellationToken::new();
    let log = crate::proxy::plugin_log::PluginLog::new();
    let err = spawn_plugin_runner_at(
        "v2ray-plugin",
        "/nonexistent/binary",
        Some(r"path=/a\"), // dangling escape
        dummy_addr(),
        "127.0.0.1", // a literal IP: no DNS lookup precedes the plugin spawn
        443,
        None,
        None,
        diagnostic_tap,
        cancel,
        &log,
    )
    .await
    .unwrap_err();

    let ProxyError::Plugin(detail) = err else {
        panic!("expected ProxyError::Plugin, got: {err:?}");
    };
    detail
}

#[skuld::test]
async fn spawn_plugin_runner_surfaces_the_real_reason_on_malformed_options() {
    let detail = spawn_with_malformed_options(false).await;
    assert!(
        detail.contains("unpaired backslash"),
        "expected the specific malformed-options reason, got a generic message: {detail}"
    );
}

// `TapPlugin` synthesizes its OWN `StartError::ExitedBeforeReady` on the
// same "inner exited before readying" race — this pins that it, like the
// untapped path above, still surfaces the plugin's real reason rather than
// the generic placeholder.
#[skuld::test]
async fn spawn_plugin_runner_surfaces_the_real_reason_on_malformed_options_through_the_tap() {
    let detail = spawn_with_malformed_options(true).await;
    assert!(
        detail.contains("unpaired backslash"),
        "expected the specific malformed-options reason through the tap, got a generic message: {detail}"
    );
}

// The OTHER synthesis point: the chain-level ready oneshot itself dropping
// unsent because `ChainRunner::run` errors before the readiness aggregator
// is ever spawned (here: DNS resolution of the SS_REMOTE address fails,
// before any plugin runs or the aggregator starts) — distinct from the
// `ExitedBeforeReady` arm above, which requires the aggregator to have
// started and observed a per-plugin readiness sender drop.
#[skuld::test]
async fn spawn_plugin_runner_surfaces_the_real_reason_when_the_chain_never_starts_the_aggregator() {
    let cancel = CancellationToken::new();
    let log = crate::proxy::plugin_log::PluginLog::new();
    // A DNS label exceeding RFC 1035's 63-byte-per-label / 255-byte-total
    // limits fails resolution PURELY through the resolver's own local
    // wire-format validation, before any query ever reaches the network —
    // unlike an unusual-but-syntactically-valid hostname, this cannot be
    // answered by a captive portal or a DNS-hijacking resolver, so the
    // failure is deterministic across network environments.
    let bogus_host = "a".repeat(260);
    let err = spawn_plugin_runner_at(
        "v2ray-plugin",
        "/nonexistent/binary",
        None,
        dummy_addr(),
        &bogus_host, // fails DNS resolution before any plugin spawns
        443,
        None,
        None,
        false,
        cancel,
        &log,
    )
    .await
    .unwrap_err();

    let ProxyError::Plugin(detail) = err else {
        panic!("expected ProxyError::Plugin, got: {err:?}");
    };
    // The OS's own DNS-failure wording is not portable across platforms
    // (Windows/Linux/macOS phrase `getaddrinfo` failures differently); the
    // portable claim is that it's NOT the generic placeholder, proving
    // `recover_exit_detail` actually reached and used `handle`'s result.
    assert_ne!(
        detail,
        garter::EXITED_BEFORE_READY_DETAIL,
        "expected the DNS failure's own reason, not the generic placeholder: {detail}"
    );
}

#[skuld::test]
async fn start_with_nonexistent_binary_returns_plugin_error() {
    let cancel = CancellationToken::new();
    let result = start_plugin_chain(
        "v2ray-plugin",
        "/nonexistent/binary",
        None,
        "127.0.0.1",
        12345,
        None,
        None,
        false,
        &cancel,
        None,
    )
    .await;

    let err = result.unwrap_err();
    assert!(
        matches!(err, ProxyError::Plugin(_)),
        "expected ProxyError::Plugin, got: {err:?}"
    );
}

// Bind-race classification (#414) =====================================================================================
//
// The load-bearing guarantee: a plugin-reported `StartError::BindConflict`
// (mapped to `ProxyError::BindRace` in `spawn_plugin_runner_at`) must be
// retryable on EVERY OS. `proxy_err_to_io_err` synthesizes an
// `AddrInUse`-kind `io::Error` directly (NOT via `from_raw_os_error`,
// which is platform-fragile), and `bind_ephemeral` retries when
// `util::retry::is_bind_race` returns true. These tests pin both
// halves: BindRace IS a bind race; Plugin / Cancelled are NOT.

fn dummy_addr() -> SocketAddr {
    "127.0.0.1:5300".parse().unwrap()
}

#[skuld::test]
fn bind_race_maps_to_retryable_addr_in_use_io_error() {
    // errno 0 (unknown) is the worst case — even with no host-native errno
    // the synthesized ErrorKind must still classify as a bind race.
    let io_err = proxy_err_to_io_err(ProxyError::BindRace {
        errno: 0,
        addr: dummy_addr(),
    });
    assert_eq!(
        io_err.kind(),
        std::io::ErrorKind::AddrInUse,
        "BindRace must synthesize an AddrInUse-kind io::Error"
    );
    assert!(
        util::retry::is_bind_race(&io_err),
        "BindRace io::Error must classify as a retryable bind race on every OS"
    );
}

#[skuld::test]
fn bind_race_with_nonzero_errno_still_retryable() {
    // A host-native errno (e.g. macOS 48, Windows 10048, Linux 98) must
    // not change the classification — it keys on ErrorKind, not errno.
    let io_err = proxy_err_to_io_err(ProxyError::BindRace {
        errno: 10048,
        addr: dummy_addr(),
    });
    assert!(util::retry::is_bind_race(&io_err));
    // The errno is preserved in the message for bridge.log diagnostics.
    assert!(
        io_err.to_string().contains("10048"),
        "errno should be preserved in the io::Error message, got: {io_err}"
    );
}

#[skuld::test]
fn plugin_error_is_not_a_bind_race() {
    let io_err = proxy_err_to_io_err(ProxyError::Plugin("upstream dial failed".into()));
    assert!(
        !util::retry::is_bind_race(&io_err),
        "ProxyError::Plugin must NOT classify as a bind race (terminal failure)"
    );
}

#[skuld::test]
fn cancelled_is_not_a_bind_race() {
    let io_err = proxy_err_to_io_err(ProxyError::Cancelled);
    assert!(
        !util::retry::is_bind_race(&io_err),
        "ProxyError::Cancelled must NOT classify as a bind race"
    );
}
