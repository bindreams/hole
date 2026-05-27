//! Layer-2 unit tests for the Win32 DNS backend.
//!
//! See [`super::WinDnsBackend`] for the trait surface and
//! [`super::Win32Real`] for the production impl. These tests use
//! [`MockBackend`] to verify cancel-aware behavior in
//! [`crate::dns::system::SystemDns::apply`] without touching the OS.

// `CancellationToken::new` is the cancel-test harness root; module-level
// allow per clippy.toml's "Bridge cancellation contract" sanctioned-
// test-file exception.
#![allow(clippy::disallowed_methods)]

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};

use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use super::WinDnsBackend;
use crate::dns::system::{Dns, DnsApplied, DnsError, SystemDns};
use crate::dns_state::{AdapterId, DnsPrior, DnsPriorAdapter};

// MockBackend =========================================================================================================

/// Test-only [`WinDnsBackend`]. Counts calls per method and supports
/// parking the *first* `set_loopback` invocation on a rendezvous so cancel
/// tests can fire `cancel.cancel()` while the FFI is mid-flight without
/// any `sleep`-based synchronization.
struct MockBackend {
    get_calls: AtomicUsize,
    set_calls: AtomicUsize,
    restore_calls: AtomicUsize,
    flush_calls: AtomicUsize,
    /// One-shot rendezvous pair: when set, the first `set_loopback` call
    /// fires `entered_tx`, then blocks on `release_rx` before returning.
    set_rendezvous: Mutex<Option<Rendezvous>>,
}

struct Rendezvous {
    entered_tx: oneshot::Sender<()>,
    /// `std::sync::mpsc::Receiver` rather than `tokio::sync::oneshot::Receiver`
    /// because `set_loopback` is sync and runs on the blocking pool.
    release_rx: std::sync::mpsc::Receiver<()>,
}

impl MockBackend {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            get_calls: AtomicUsize::new(0),
            set_calls: AtomicUsize::new(0),
            restore_calls: AtomicUsize::new(0),
            flush_calls: AtomicUsize::new(0),
            set_rendezvous: Mutex::new(None),
        })
    }

    /// Arm the first-`set_loopback` rendezvous. Returns the receiver/sender
    /// the test should park on / fire respectively:
    /// - `entered_rx`: completes when the first `set_loopback` runs.
    /// - `release_tx`: send to let the first `set_loopback` return.
    fn arm_set_rendezvous(&self) -> (oneshot::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        *self.set_rendezvous.lock().unwrap() = Some(Rendezvous { entered_tx, release_rx });
        (entered_rx, release_tx)
    }
}

impl WinDnsBackend for MockBackend {
    fn get_settings(&self, alias: &str) -> io::Result<Option<DnsPriorAdapter>> {
        self.get_calls.fetch_add(1, SeqCst);
        Ok(Some(DnsPriorAdapter {
            id: AdapterId::WindowsAlias {
                value: alias.to_string(),
            },
            name_at_capture: alias.to_string(),
            v4: DnsPrior::Dhcp,
            v6: DnsPrior::None,
        }))
    }

    fn set_loopback(&self, _alias: &str, _ip: IpAddr) -> io::Result<()> {
        let n = self.set_calls.fetch_add(1, SeqCst);
        if n == 0 {
            // First call — fire entered signal and park if rendezvous armed.
            let r = self.set_rendezvous.lock().unwrap().take();
            if let Some(r) = r {
                let _ = r.entered_tx.send(());
                let _ = r.release_rx.recv();
            }
        }
        Ok(())
    }

    fn restore(&self, _adapter: &DnsPriorAdapter) -> io::Result<()> {
        self.restore_calls.fetch_add(1, SeqCst);
        Ok(())
    }

    fn flush(&self) -> io::Result<()> {
        self.flush_calls.fetch_add(1, SeqCst);
        Ok(())
    }
}

// Helpers =============================================================================================================

/// Build a `LocalDnsServer` bound to an ephemeral loopback port. The
/// bind is real (so the apply path's accept of a `LocalDnsServer` value
/// is exercised end-to-end), but the test never sends traffic to it.
async fn fake_local_dns_server() -> crate::dns::server::LocalDnsServer {
    use crate::dns::server::LocalDnsServer;
    use std::sync::Arc;

    // Build a forwarder that's never actually used by these tests — its
    // upstream connector is a placeholder. The server binds locally;
    // packets are not sent.
    let dns_cfg = hole_common::config::DnsConfig::default();
    let connector = Arc::new(crate::dns::socks5_connector::Socks5Connector::new(
        std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1080),
    )) as Arc<dyn crate::dns::connector::UpstreamConnector>;
    let forwarder = Arc::new(crate::dns::forwarder::DnsForwarder::new(dns_cfg, connector, false));
    LocalDnsServer::bind_ladder(forwarder, CancellationToken::new())
        .await
        .expect("LocalDnsServer::bind_ladder")
}

// Tests ===============================================================================================================

/// Cooperative cancel observed BETWEEN `set_loopback` calls aborts
/// `apply` before the second adapter is touched and runs inline-restore
/// for the captured prior. The first call is parked via the rendezvous;
/// the test fires cancel from a peer task; the parked call is released
/// and apply observes cancel before issuing the second call.
#[skuld::test]
async fn system_dns_apply_aborts_between_calls_on_cancel() {
    let backend = MockBackend::new();
    let (entered_rx, release_tx) = backend.arm_set_rendezvous();
    let restore_calls = Arc::clone(&backend);
    let set_calls = Arc::clone(&backend);

    let dns = SystemDns::new_with_backend(Arc::clone(&backend) as Arc<dyn WinDnsBackend>);
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    tokio::spawn(async move {
        entered_rx.await.expect("first set_loopback never entered");
        cancel_clone.cancel();
        let _ = release_tx.send(());
    });

    let srv = fake_local_dns_server().await;
    let result = dns
        .apply(
            srv,
            vec!["upstream-alias".into()],
            vec!["wintun".into(), "upstream-alias".into()],
            None,
            cancel,
        )
        .await;

    // `SystemDnsApplied` is intentionally not `Debug` (its
    // `LocalDnsServer` carries platform-specific handles that don't
    // implement Debug). Sidestep `expect_err`'s `T: Debug` bound by
    // matching the result directly.
    match result {
        Ok(mut applied) => {
            // Test invariant violated; defuse the bomb before panicking
            // so the panic message that surfaces is ours, not the bomb's.
            applied.shutdown().await;
            panic!("apply should have returned DnsError::Cancelled");
        }
        Err(DnsError::Cancelled) => {}
        Err(e) => panic!("expected Cancelled, got {e:?}"),
    }
    assert_eq!(
        set_calls.set_calls.load(SeqCst),
        1,
        "second apply (wintun) must NOT run after cancel"
    );
    assert_eq!(
        restore_calls.restore_calls.load(SeqCst),
        1,
        "inline restore must run for the one captured upstream adapter"
    );
}

/// Regression: cancel mid-apply must clear `bridge-dns.json` alongside
/// the inline-restore, so the next bridge start's `recover_dns_config`
/// doesn't replay an already-restored prior over any user-side DNS
/// changes made between the cancelled start and the next start.
#[skuld::test]
async fn inline_restore_clears_state_file_on_cancel() {
    let backend = MockBackend::new();
    let (entered_rx, release_tx) = backend.arm_set_rendezvous();

    let dns = SystemDns::new_with_backend(Arc::clone(&backend) as Arc<dyn WinDnsBackend>);
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    let tmp = tempfile::tempdir().expect("tempdir");
    let state_dir = tmp.path().to_path_buf();

    tokio::spawn(async move {
        entered_rx.await.expect("first set_loopback never entered");
        cancel_clone.cancel();
        let _ = release_tx.send(());
    });

    let srv = fake_local_dns_server().await;
    let result = dns
        .apply(
            srv,
            vec!["upstream-alias".into()],
            vec!["wintun".into(), "upstream-alias".into()],
            Some(state_dir.clone()),
            cancel,
        )
        .await;
    assert!(matches!(result, Err(DnsError::Cancelled)), "apply should cancel");

    // `apply` writes the state file BEFORE the apply loop (the `save`
    // call after capture). On cancel, inline_restore must clear it so
    // the next start's recovery doesn't replay over user DNS changes.
    assert!(
        crate::dns_state::load(&state_dir).is_none(),
        "inline_restore must clear bridge-dns.json on cancel; presence would replay restore on next start"
    );
}

/// One `set_loopback` per `apply_aliases` entry — guards against accidental
/// double-application or reordering.
#[skuld::test]
async fn system_dns_apply_one_set_per_apply_alias() {
    let backend = MockBackend::new();
    let dns = SystemDns::new_with_backend(Arc::clone(&backend) as Arc<dyn WinDnsBackend>);
    let cancel = CancellationToken::new();

    let srv = fake_local_dns_server().await;
    let mut applied = dns
        .apply(
            srv,
            vec!["upstream-alias".into()],
            vec!["wintun".into(), "upstream-alias".into()],
            None,
            cancel,
        )
        .await
        .expect("apply should succeed");

    assert_eq!(
        backend.set_calls.load(SeqCst),
        2,
        "exactly one set_loopback per apply_alias"
    );
    assert_eq!(
        backend.get_calls.load(SeqCst),
        1,
        "exactly one get_settings per capture_alias"
    );

    // Clean shutdown to defuse the bomb.
    applied.shutdown().await;
}

/// The `DebugDropBomb` safeguard panics in debug builds when `shutdown`
/// is not awaited before drop, catching missed-shutdown bugs at the
/// first test run. Release builds use the no-op variant and fall through
/// to the sync-fallback restore — exercised by
/// [`drop_invokes_sync_fallback_when_shutdown_skipped`] below.
#[skuld::test]
#[cfg(debug_assertions)]
#[should_panic(expected = "SystemDnsApplied dropped without awaiting shutdown()")]
async fn system_dns_applied_drop_panics_in_debug_if_shutdown_not_awaited() {
    let backend = MockBackend::new();
    let dns = SystemDns::new_with_backend(Arc::clone(&backend) as Arc<dyn WinDnsBackend>);
    let cancel = CancellationToken::new();

    let srv = fake_local_dns_server().await;
    let applied = dns
        .apply(srv, vec!["upstream-alias".into()], vec!["wintun".into()], None, cancel)
        .await
        .expect("apply should succeed");

    // No .shutdown().await — bomb panics on drop.
    drop(applied);
}

/// Regression for the release-mode dead-code bug in `SystemDnsApplied::Drop`:
/// the previous gate `if !self.bomb.is_defused()` was always `false` in
/// release (`drop_bomb::FakeBomb::is_defused()` returns `true`
/// unconditionally), so the sync-fallback restore never ran on a missed
/// `shutdown().await` in release — the user's DNS would stay pointed at
/// the loopback forwarder forever.
///
/// The fix tracks a separate `shutdown_completed: bool` field; this test
/// asserts the manual `Drop` impl invokes the backend's `restore` for
/// each captured prior in **both** build profiles. In debug, the bomb's
/// own Drop still panics afterward (manual Drop runs first, then field
/// drops trigger the bomb) — `std::panic::catch_unwind` absorbs that.
#[skuld::test]
async fn drop_invokes_sync_fallback_when_shutdown_skipped() {
    let backend = MockBackend::new();
    let dns = SystemDns::new_with_backend(Arc::clone(&backend) as Arc<dyn WinDnsBackend>);
    let cancel = CancellationToken::new();

    let srv = fake_local_dns_server().await;
    let applied = dns
        .apply(
            srv,
            vec!["upstream-alias".into()],
            vec!["wintun".into(), "upstream-alias".into()],
            None,
            cancel,
        )
        .await
        .expect("apply should succeed");

    let restore_before = backend.restore_calls.load(SeqCst);
    let flush_before = backend.flush_calls.load(SeqCst);

    // Drop without shutdown. In debug, the bomb (a field of `applied`)
    // panics on its own Drop AFTER our `impl Drop` has run the sync
    // fallback — catch_unwind absorbs the panic so the test can assert
    // on the backend's call counts in either build profile.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(applied)));

    assert!(
        backend.restore_calls.load(SeqCst) > restore_before,
        "Drop must invoke sync-fallback restore when shutdown_completed=false (release dead-code regression)"
    );
    assert!(
        backend.flush_calls.load(SeqCst) > flush_before,
        "Drop must invoke flush after sync-fallback restore"
    );
}
