//! Layer-2 unit tests for the macOS DNS-steering seam.
//!
//! See [`super::MacDnsSteerer`] for the trait surface and
//! [`super::RealMacDnsSteerer`] for the production impl backed by
//! `tun_engine::dns_steer`. These tests use [`MockSteerer`] to verify
//! [`crate::dns::system::SystemDns::apply`]'s cancel/routed-family/error
//! handling without touching configd or a real `SCDynamicStore` session.
//!
//! `routed_families_come_from_the_installed_routes` (the plan's 8th named
//! test) is deferred to Task 5: `RoutedFamilies` is constructed directly by
//! every test here rather than derived from a `Routing::Installed` guard —
//! that accessor does not exist on the `Routing` trait until Task 5 adds
//! it (see `crates/bridge/src/proxy_manager.rs`'s call site, and Task 5's
//! own `routed_families_reports_only_the_splits_that_landed`, the natural
//! home for this assertion once the accessor exists).

// `CancellationToken::new` is the cancel-test harness root — sanctioned
// for test files by clippy.toml's "Bridge cancellation contract" exception.
#![allow(clippy::disallowed_methods)]

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};

use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use super::{MacDnsBackend, MacDnsSteerer, SteeringHandle};
use crate::dns::system::{Dns, DnsApplied, DnsError, RoutedFamilies, SystemDns};
use crate::dns_state::{DnsPrior, DnsPriorAdapter};

// MockBackend (flush only — apply never reaches get/set/restore any more) =============================================

struct MockBackend {
    flush_calls: AtomicUsize,
}

impl MockBackend {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            flush_calls: AtomicUsize::new(0),
        })
    }
}

impl MacDnsBackend for MockBackend {
    fn get_settings(&self, _service: &str) -> io::Result<Option<DnsPriorAdapter>> {
        unreachable!("apply never calls get_settings")
    }
    fn set_servers(&self, _service: &str, _servers: &[IpAddr]) -> io::Result<()> {
        unreachable!("apply must not call set_servers any more — see macos.rs's module doc")
    }
    fn restore(&self, _adapter: &DnsPriorAdapter) -> io::Result<()> {
        unreachable!("apply never calls restore")
    }
    fn restore_family(&self, _service: &str, _ipv6: bool, _prior: &DnsPrior) -> io::Result<()> {
        unreachable!("apply never calls restore_family")
    }
    fn flush(&self) -> io::Result<()> {
        self.flush_calls.fetch_add(1, SeqCst);
        Ok(())
    }
}

// MockSteerer / MockHandle ============================================================================================

struct Rendezvous {
    entered_tx: oneshot::Sender<()>,
    /// `std::sync::mpsc::Receiver` rather than `tokio::sync::oneshot::Receiver`
    /// because the mocked call is sync and runs on the blocking pool.
    release_rx: std::sync::mpsc::Receiver<()>,
}

/// Test-only [`MacDnsSteerer`]. Records every `engage` call's server list,
/// can fail on demand, and can park mid-`engage` on a rendezvous so a test
/// can race a cancel against it — mirrors `windows_tests::MockConfiner`.
struct MockSteerer {
    engage_calls: Mutex<Vec<Vec<IpAddr>>>,
    fail: AtomicBool,
    rendezvous: Mutex<Option<Rendezvous>>,
    /// Withdraw call count and outcome, shared with every [`MockHandle`]
    /// this steerer hands out.
    withdraw_calls: Arc<AtomicUsize>,
    withdraw_fails: Arc<AtomicBool>,
}

impl MockSteerer {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            engage_calls: Mutex::new(Vec::new()),
            fail: AtomicBool::new(false),
            rendezvous: Mutex::new(None),
            withdraw_calls: Arc::new(AtomicUsize::new(0)),
            withdraw_fails: Arc::new(AtomicBool::new(false)),
        })
    }

    fn failing() -> Arc<Self> {
        let m = Self::new();
        m.fail.store(true, SeqCst);
        m
    }

    fn withdraw_failing() -> Arc<Self> {
        let m = Self::new();
        m.withdraw_fails.store(true, SeqCst);
        m
    }

    fn arm_rendezvous(&self) -> (oneshot::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        *self.rendezvous.lock().unwrap() = Some(Rendezvous { entered_tx, release_rx });
        (entered_rx, release_tx)
    }

    fn engage_call_count(&self) -> usize {
        self.engage_calls.lock().unwrap().len()
    }

    fn last_engage_servers(&self) -> Vec<IpAddr> {
        self.engage_calls.lock().unwrap().last().cloned().unwrap_or_default()
    }

    fn withdraw_call_count(&self) -> usize {
        self.withdraw_calls.load(SeqCst)
    }
}

impl MacDnsSteerer for MockSteerer {
    fn engage(&self, servers: &[IpAddr]) -> io::Result<Box<dyn SteeringHandle>> {
        self.engage_calls.lock().unwrap().push(servers.to_vec());
        if let Some(r) = self.rendezvous.lock().unwrap().take() {
            let _ = r.entered_tx.send(());
            let _ = r.release_rx.recv();
        }
        if self.fail.load(SeqCst) {
            return Err(io::Error::other("mock steerer failure"));
        }
        Ok(Box::new(MockHandle {
            calls: Arc::clone(&self.withdraw_calls),
            fails: Arc::clone(&self.withdraw_fails),
        }))
    }
}

struct MockHandle {
    calls: Arc<AtomicUsize>,
    fails: Arc<AtomicBool>,
}

impl SteeringHandle for MockHandle {
    fn withdraw(self: Box<Self>) -> io::Result<()> {
        self.calls.fetch_add(1, SeqCst);
        if self.fails.load(SeqCst) {
            Err(io::Error::other("mock withdraw failure"))
        } else {
            Ok(())
        }
    }
}

// Helpers =============================================================================================================

fn tun_identity() -> tun_engine::TunIdentity {
    tun_engine::TunIdentity::synthetic(0xFEED, "hole-tun")
}

fn server_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))
}

fn both_routed() -> RoutedFamilies {
    RoutedFamilies { v4: true, v6: true }
}

fn v4() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))
}

fn v6() -> IpAddr {
    "2606:4700:4700::1111".parse().unwrap()
}

// Tests ===============================================================================================================

/// A steerer that fails to engage must abort the apply — fail-fatal on
/// macOS, exactly like the Windows confinement.
#[skuld::test]
async fn macos_apply_aborts_when_steering_fails() {
    let backend = MockBackend::new();
    let steerer = MockSteerer::failing();
    let dns = SystemDns::new_with_mac_backend(
        Arc::clone(&backend) as Arc<dyn MacDnsBackend>,
        Arc::clone(&steerer) as Arc<dyn MacDnsSteerer>,
    );

    let result = dns
        .apply(
            vec![v4()],
            both_routed(),
            tun_identity(),
            server_ip(),
            CancellationToken::new(),
        )
        .await;

    match result {
        Err(DnsError::Io(_)) => {}
        Err(DnsError::Cancelled) => panic!("expected Io, got Cancelled"),
        Ok(_) => panic!("expected Io, got Ok"),
    }
    assert_eq!(backend.flush_calls.load(SeqCst), 0, "a failed engage must not flush");
}

/// `apply` must hold the steering guard until `shutdown` withdraws it —
/// exactly once.
#[skuld::test]
async fn macos_apply_holds_the_steering_until_shutdown() {
    let backend = MockBackend::new();
    let steerer = MockSteerer::new();
    let dns = SystemDns::new_with_mac_backend(
        Arc::clone(&backend) as Arc<dyn MacDnsBackend>,
        Arc::clone(&steerer) as Arc<dyn MacDnsSteerer>,
    );

    let mut applied = dns
        .apply(
            vec![v4()],
            both_routed(),
            tun_identity(),
            server_ip(),
            CancellationToken::new(),
        )
        .await
        .expect("apply should succeed");

    assert!(
        applied.steering_engaged(),
        "the steering guard must be held right after apply"
    );
    assert_eq!(steerer.withdraw_call_count(), 0);

    applied.shutdown().await;

    assert_eq!(steerer.withdraw_call_count(), 1, "shutdown must withdraw exactly once");
    assert!(!applied.steering_engaged());
}

/// A cancel fired before `apply` even starts must never reach `engage` —
/// mirrors Windows' pre-engage cancel checkpoint.
#[skuld::test]
async fn macos_apply_cancelled_before_steering_engages_nothing() {
    let backend = MockBackend::new();
    let steerer = MockSteerer::new();
    let dns = SystemDns::new_with_mac_backend(
        Arc::clone(&backend) as Arc<dyn MacDnsBackend>,
        Arc::clone(&steerer) as Arc<dyn MacDnsSteerer>,
    );
    let cancel = CancellationToken::new();
    cancel.cancel();

    let result = dns
        .apply(vec![v4()], both_routed(), tun_identity(), server_ip(), cancel)
        .await;

    match result {
        Err(DnsError::Cancelled) => {}
        Err(DnsError::Io(e)) => panic!("expected Cancelled, got Io({e})"),
        Ok(_) => panic!("expected Cancelled, got Ok"),
    }
    assert_eq!(
        steerer.engage_call_count(),
        0,
        "engage must never run after a pre-fired cancel"
    );
}

/// A cancel that lands WHILE `engage` is in flight must still be honored:
/// the post-engage cancel checkpoint (contract point 1) withdraws the
/// just-published key before returning Cancelled, mirroring
/// `dns_apply_cancelled_drops_the_confinement` on Windows.
#[skuld::test]
async fn macos_apply_cancelled_during_engage_withdraws_it() {
    let backend = MockBackend::new();
    let steerer = MockSteerer::new();
    let (entered_rx, release_tx) = steerer.arm_rendezvous();
    let dns = SystemDns::new_with_mac_backend(
        Arc::clone(&backend) as Arc<dyn MacDnsBackend>,
        Arc::clone(&steerer) as Arc<dyn MacDnsSteerer>,
    );
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    tokio::spawn(async move {
        entered_rx.await.expect("engage never entered");
        cancel_clone.cancel();
        let _ = release_tx.send(());
    });

    let result = dns
        .apply(vec![v4()], both_routed(), tun_identity(), server_ip(), cancel)
        .await;

    match result {
        Err(DnsError::Cancelled) => {}
        Err(DnsError::Io(e)) => panic!("expected Cancelled, got Io({e})"),
        Ok(_) => panic!("expected Cancelled, got Ok"),
    }
    assert_eq!(
        steerer.withdraw_call_count(),
        1,
        "exactly one withdraw after a cancel that raced the engage"
    );
}

/// A failed withdraw must not fail `shutdown` (`Cosmetic`) but must be
/// reported (logged with the key) — the whole point of making withdraw
/// confirmable rather than `Drop`-only.
#[skuld::test]
async fn macos_shutdown_reports_a_failed_withdraw() {
    use crate::test_support::log_capture::VecWriter;
    use garter::tracing_test::set_default_in_current_thread;
    use tracing_subscriber::fmt;
    use tracing_subscriber::layer::{Layer, SubscriberExt};

    let backend = MockBackend::new();
    let steerer = MockSteerer::withdraw_failing();
    let dns = SystemDns::new_with_mac_backend(
        Arc::clone(&backend) as Arc<dyn MacDnsBackend>,
        Arc::clone(&steerer) as Arc<dyn MacDnsSteerer>,
    );

    let mut applied = dns
        .apply(
            vec![v4()],
            both_routed(),
            tun_identity(),
            server_ip(),
            CancellationToken::new(),
        )
        .await
        .expect("apply should succeed");

    let writer = VecWriter::new();
    let subscriber = tracing_subscriber::registry().with(
        fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
    );
    let _guard = set_default_in_current_thread(subscriber);

    applied.shutdown().await; // must complete despite the failing withdraw — never panics/hangs

    assert_eq!(steerer.withdraw_call_count(), 1);
    assert!(!applied.steering_engaged());
    let output = writer.snapshot_string();
    assert!(
        output.contains("WARN"),
        "a failed withdraw must be logged; got:\n{output}"
    );
}

/// D4's narrow filter: a resolver whose family has no live split route
/// must not be advertised, even when the raw configured list carries it.
#[skuld::test]
async fn macos_apply_advertises_only_routed_families() {
    let backend = MockBackend::new();
    let steerer = MockSteerer::new();
    let dns = SystemDns::new_with_mac_backend(
        Arc::clone(&backend) as Arc<dyn MacDnsBackend>,
        Arc::clone(&steerer) as Arc<dyn MacDnsSteerer>,
    );

    let mut applied = dns
        .apply(
            vec![v4(), v6()],
            RoutedFamilies { v4: true, v6: false },
            tun_identity(),
            server_ip(),
            CancellationToken::new(),
        )
        .await
        .expect("apply should succeed");

    assert_eq!(
        steerer.last_engage_servers(),
        vec![v4()],
        "only the v4 resolver has a live split route"
    );
    applied.shutdown().await;
}

/// If NO advertised resolver's family has a live split route, `apply` must
/// refuse rather than silently publish an empty (or wrong-family) key.
#[skuld::test]
async fn macos_apply_refuses_when_no_routed_family_has_a_resolver() {
    let backend = MockBackend::new();
    let steerer = MockSteerer::new();
    let dns = SystemDns::new_with_mac_backend(
        Arc::clone(&backend) as Arc<dyn MacDnsBackend>,
        Arc::clone(&steerer) as Arc<dyn MacDnsSteerer>,
    );

    let result = dns
        .apply(
            vec![v6()],
            RoutedFamilies { v4: true, v6: false },
            tun_identity(),
            server_ip(),
            CancellationToken::new(),
        )
        .await;

    match result {
        Err(DnsError::Io(_)) => {}
        Err(DnsError::Cancelled) => panic!("expected Io, got Cancelled"),
        Ok(_) => panic!("expected Io, got Ok"),
    }
    assert_eq!(steerer.engage_call_count(), 0, "must refuse before ever engaging");
}
