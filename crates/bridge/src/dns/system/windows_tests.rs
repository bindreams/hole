//! Layer-2 unit tests for the Win32 DNS backend and the confinement seam.
//!
//! See [`super::WinDnsBackend`] for the trait surface and
//! [`super::Win32Real`] for the production impl; [`super::DnsConfiner`] for
//! the confinement seam. These tests use [`MockBackend`] / [`MockConfiner`]
//! to verify [`crate::dns::system::SystemDns::apply`]'s cancel/error
//! handling without touching the OS or a real WFP engine.

// `CancellationToken::new` is the cancel-test harness root — sanctioned
// for test files by clippy.toml's "Bridge cancellation contract" exception.
#![allow(clippy::disallowed_methods)]

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};

use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use super::{DnsConfiner, WinDnsBackend};
use crate::dns::system::{Dns, DnsApplied, DnsError, SystemDns};
use crate::dns_state::{AdapterId, DnsPrior, DnsPriorAdapter};

// MockBackend =========================================================================================================

/// Test-only [`WinDnsBackend`]. Counts calls per method. `apply` now has
/// exactly one target (`hole-tun`), so there is no second call for a cancel
/// test to race against on the backend side any more — that race moved to
/// [`MockConfiner::engage`], which still has a window before it (see
/// `dns_apply_cancelled_drops_the_confinement`).
struct MockBackend {
    get_calls: AtomicUsize,
    set_calls: AtomicUsize,
    restore_calls: AtomicUsize,
    flush_calls: AtomicUsize,
    set_ips: Mutex<Vec<Vec<IpAddr>>>,
    set_luids: Mutex<Vec<u64>>,
}

struct Rendezvous {
    entered_tx: oneshot::Sender<()>,
    /// `std::sync::mpsc::Receiver` rather than `tokio::sync::oneshot::Receiver`
    /// because the mocked call is sync and runs on the blocking pool.
    release_rx: std::sync::mpsc::Receiver<()>,
}

impl MockBackend {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            get_calls: AtomicUsize::new(0),
            set_calls: AtomicUsize::new(0),
            restore_calls: AtomicUsize::new(0),
            flush_calls: AtomicUsize::new(0),
            set_ips: Mutex::new(Vec::new()),
            set_luids: Mutex::new(Vec::new()),
        })
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

    fn set_servers(&self, luid: u64, servers: &[IpAddr]) -> io::Result<()> {
        self.set_ips.lock().unwrap().push(servers.to_vec());
        self.set_luids.lock().unwrap().push(luid);
        self.set_calls.fetch_add(1, SeqCst);
        Ok(())
    }

    fn restore(&self, _adapter: &DnsPriorAdapter) -> io::Result<()> {
        self.restore_calls.fetch_add(1, SeqCst);
        Ok(())
    }

    fn restore_family(&self, _alias: &str, _ipv6: bool, _prior: &DnsPrior) -> io::Result<()> {
        self.restore_calls.fetch_add(1, SeqCst);
        Ok(())
    }

    fn flush(&self) -> io::Result<()> {
        self.flush_calls.fetch_add(1, SeqCst);
        Ok(())
    }
}

// MockConfiner ========================================================================================================

/// Boxed as the `SystemDnsApplied` confinement value; its `Drop` flips
/// `alive` to `false` so a test can observe "the confinement was released"
/// without inspecting `SystemDnsApplied`'s private fields.
struct ConfinementProbe(Arc<AtomicBool>);

impl Drop for ConfinementProbe {
    fn drop(&mut self) {
        self.0.store(false, SeqCst);
    }
}

/// Test-only [`DnsConfiner`]. Supports failing on demand and parking
/// `engage` on a rendezvous, mirroring [`MockBackend`].
struct MockConfiner {
    engage_calls: AtomicUsize,
    fail: AtomicBool,
    rendezvous: Mutex<Option<Rendezvous>>,
    /// Shared with every [`ConfinementProbe`] this confiner hands out —
    /// `true` while (the most recent) confinement is alive.
    alive: Arc<AtomicBool>,
}

impl MockConfiner {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            engage_calls: AtomicUsize::new(0),
            fail: AtomicBool::new(false),
            rendezvous: Mutex::new(None),
            alive: Arc::new(AtomicBool::new(false)),
        })
    }

    fn failing() -> Arc<Self> {
        let m = Self::new();
        m.fail.store(true, SeqCst);
        m
    }

    fn arm_rendezvous(&self) -> (oneshot::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        *self.rendezvous.lock().unwrap() = Some(Rendezvous { entered_tx, release_rx });
        (entered_rx, release_tx)
    }

    fn confinement_alive(&self) -> bool {
        self.alive.load(SeqCst)
    }
}

impl DnsConfiner for MockConfiner {
    fn engage(
        &self,
        _tun_luid: u64,
        _server_ip: IpAddr,
    ) -> Result<Box<dyn std::any::Any + Send>, tun_engine::dns_confine::DnsConfineError> {
        self.engage_calls.fetch_add(1, SeqCst);
        if let Some(r) = self.rendezvous.lock().unwrap().take() {
            let _ = r.entered_tx.send(());
            let _ = r.release_rx.recv();
        }
        if self.fail.load(SeqCst) {
            return Err(tun_engine::dns_confine::DnsConfineError::EngineOpen(io::Error::other(
                "mock confiner failure",
            )));
        }
        self.alive.store(true, SeqCst);
        Ok(Box::new(ConfinementProbe(Arc::clone(&self.alive))))
    }
}

// Helpers =============================================================================================================

fn tun_identity() -> tun_engine::TunIdentity {
    tun_engine::TunIdentity::synthetic(0xFEED, "hole-tun")
}

fn server_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))
}

// Tests ===============================================================================================================

/// Cancel fired AFTER the confinement engages but BEFORE `set_servers`
/// aborts the apply and — the load-bearing assertion — leaves no
/// confinement engaged. The confinement engage is parked via the
/// rendezvous; the test fires cancel from a peer task while it's mid-flight.
#[skuld::test]
async fn dns_apply_cancelled_drops_the_confinement() {
    let backend = MockBackend::new();
    let confiner = MockConfiner::new();
    let (entered_rx, release_tx) = confiner.arm_rendezvous();

    let dns = SystemDns::new_with_backend(
        Arc::clone(&backend) as Arc<dyn WinDnsBackend>,
        Arc::clone(&confiner) as Arc<dyn DnsConfiner>,
    );
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    tokio::spawn(async move {
        entered_rx.await.expect("engage never entered");
        cancel_clone.cancel();
        let _ = release_tx.send(());
    });

    let result = dns
        .apply(
            vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
            tun_identity(),
            server_ip(),
            cancel,
        )
        .await;

    match result {
        Ok(mut applied) => {
            applied.shutdown().await;
            panic!("apply should have returned DnsError::Cancelled");
        }
        Err(DnsError::Cancelled) => {}
        Err(e) => panic!("expected Cancelled, got {e:?}"),
    }
    assert_eq!(
        backend.set_calls.load(SeqCst),
        0,
        "set_servers must NOT run after cancel"
    );
    assert!(
        !confiner.confinement_alive(),
        "the confinement must be dropped when apply returns Cancelled"
    );
}

#[skuld::test]
async fn apply_sets_resolvers_on_hole_tun_only() {
    let backend = MockBackend::new();
    let confiner = MockConfiner::new();
    let dns = SystemDns::new_with_backend(
        Arc::clone(&backend) as Arc<dyn WinDnsBackend>,
        confiner as Arc<dyn DnsConfiner>,
    );

    let mut applied = dns
        .apply(
            vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
            tun_identity(),
            server_ip(),
            CancellationToken::new(),
        )
        .await
        .expect("apply should succeed");

    assert_eq!(backend.set_calls.load(SeqCst), 1, "exactly one set_servers call");
    assert_eq!(backend.get_calls.load(SeqCst), 0, "apply must never call get_settings");
    // `set_servers` must be handed the LUID of the opened device
    // (`TunIdentity::luid`), never a value it would have to re-resolve from
    // a name — see `apply_windows`'s doc.
    assert_eq!(
        backend.set_luids.lock().unwrap().as_slice(),
        [tun_identity().luid()],
        "set_servers must receive tun.luid() directly"
    );

    applied.shutdown().await;
}

/// The `DebugDropBomb` safeguard panics in debug builds when `shutdown`
/// is not awaited before drop, catching missed-shutdown bugs at the
/// first test run.
#[skuld::test]
#[cfg(debug_assertions)]
#[should_panic(expected = "SystemDnsApplied dropped without awaiting shutdown()")]
async fn system_dns_applied_drop_panics_in_debug_if_shutdown_not_awaited() {
    let backend = MockBackend::new();
    let confiner = MockConfiner::new();
    let dns = SystemDns::new_with_backend(backend as Arc<dyn WinDnsBackend>, confiner as Arc<dyn DnsConfiner>);

    let applied = dns
        .apply(
            vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
            tun_identity(),
            server_ip(),
            CancellationToken::new(),
        )
        .await
        .expect("apply should succeed");

    // No .shutdown().await — bomb panics on drop.
    drop(applied);
}

/// `shutdown` must release the confinement — the Rule #0 guarantee,
/// pinned at this layer (the live proof that dropping it actually reopens
/// DNS lives in the elevated `dns_confine_global_net_state_filters_die_with_the_session`).
#[skuld::test]
async fn shutdown_releases_the_confinement() {
    let backend = MockBackend::new();
    let confiner = MockConfiner::new();
    let dns = SystemDns::new_with_backend(
        Arc::clone(&backend) as Arc<dyn WinDnsBackend>,
        Arc::clone(&confiner) as Arc<dyn DnsConfiner>,
    );

    let mut applied = dns
        .apply(
            vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
            tun_identity(),
            server_ip(),
            CancellationToken::new(),
        )
        .await
        .expect("apply should succeed");

    assert!(
        confiner.confinement_alive(),
        "the confinement must be held right after apply"
    );
    applied.shutdown().await;
    assert!(!confiner.confinement_alive(), "shutdown must release the confinement");
    assert!(!applied.confinement_engaged());
}

/// A `DnsConfiner` failure must surface as `DnsError::Confine` and must not
/// call `set_servers` at all — confinement-up-with-no-resolver is worse
/// than no confinement, so the two must never be reordered.
#[skuld::test]
async fn confiner_failure_surfaces_as_confine_error_and_skips_set_servers() {
    let backend = MockBackend::new();
    let confiner = MockConfiner::failing();
    let dns = SystemDns::new_with_backend(
        Arc::clone(&backend) as Arc<dyn WinDnsBackend>,
        confiner as Arc<dyn DnsConfiner>,
    );

    let result = dns
        .apply(
            vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
            tun_identity(),
            server_ip(),
            CancellationToken::new(),
        )
        .await;

    match result {
        Err(DnsError::Confine(_)) => {}
        Err(DnsError::Cancelled) => panic!("expected Confine, got Cancelled"),
        Err(DnsError::Io(e)) => panic!("expected Confine, got Io({e})"),
        Ok(_) => panic!("expected Confine, got Ok"),
    }
    assert_eq!(
        backend.set_calls.load(SeqCst),
        0,
        "set_servers must not run when confinement fails"
    );
}

/// `set_servers` failure must be fatal on Windows: `hole-tun` is the only
/// target, so "continuing" has nowhere to continue to.
#[skuld::test]
async fn set_servers_failure_is_fatal() {
    struct FailingSetBackend;
    impl WinDnsBackend for FailingSetBackend {
        fn get_settings(&self, _alias: &str) -> io::Result<Option<DnsPriorAdapter>> {
            unreachable!("apply never calls get_settings")
        }
        fn set_servers(&self, _luid: u64, _servers: &[IpAddr]) -> io::Result<()> {
            Err(io::Error::other("mock set_servers failure"))
        }
        fn restore(&self, _adapter: &DnsPriorAdapter) -> io::Result<()> {
            unreachable!("apply never calls restore")
        }
        fn restore_family(&self, _alias: &str, _ipv6: bool, _prior: &DnsPrior) -> io::Result<()> {
            unreachable!("apply never calls restore_family")
        }
        fn flush(&self) -> io::Result<()> {
            Ok(())
        }
    }

    let confiner = MockConfiner::new();
    let dns = SystemDns::new_with_backend(
        Arc::new(FailingSetBackend) as Arc<dyn WinDnsBackend>,
        Arc::clone(&confiner) as Arc<dyn DnsConfiner>,
    );

    let result = dns
        .apply(
            vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
            tun_identity(),
            server_ip(),
            CancellationToken::new(),
        )
        .await;

    match result {
        Err(DnsError::Io(_)) => {}
        Err(DnsError::Cancelled) => panic!("expected Io, got Cancelled"),
        Err(DnsError::Confine(e)) => panic!("expected Io, got Confine({e})"),
        Ok(_) => panic!("expected Io, got Ok"),
    }
}

/// `Dns::apply` advertises the configured upstream resolver IPs
/// (NOT 127.0.0.1), so OS UDP/53 routes into hole-tun and is intercepted
/// by the in-TUN LocalDnsEndpoint.
#[skuld::test]
async fn apply_advertises_resolver_ips_not_loopback() {
    let backend = MockBackend::new();
    let confiner = MockConfiner::new();
    let dns = SystemDns::new_with_backend(
        Arc::clone(&backend) as Arc<dyn WinDnsBackend>,
        confiner as Arc<dyn DnsConfiner>,
    );

    let resolvers = vec![
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
    ];
    let mut applied = dns
        .apply(resolvers.clone(), tun_identity(), server_ip(), CancellationToken::new())
        .await
        .expect("apply should succeed");

    let recorded = backend.set_ips.lock().unwrap().clone();
    assert_eq!(recorded.len(), 1, "exactly one set_servers call");
    assert_eq!(
        recorded[0], resolvers,
        "must advertise resolver IPs, got {:?}",
        recorded[0]
    );
    assert!(
        !recorded[0].contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)),
        "must NOT advertise 127.0.0.1"
    );
    applied.shutdown().await;
}

/// `Dns::apply` forwards the full configured resolver list — both v4
/// and v6 — to `set_servers`. `set_servers` splits the list per family
/// internally, leaving an unconfigured family untouched. This pins that v6
/// resolvers are advertised end-to-end, not dropped.
#[skuld::test]
async fn apply_advertises_both_v4_and_v6_resolvers() {
    let backend = MockBackend::new();
    let confiner = MockConfiner::new();
    let dns = SystemDns::new_with_backend(
        Arc::clone(&backend) as Arc<dyn WinDnsBackend>,
        confiner as Arc<dyn DnsConfiner>,
    );

    let resolvers = vec![
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        "2606:4700:4700::1111".parse().unwrap(),
    ];
    let mut applied = dns
        .apply(resolvers.clone(), tun_identity(), server_ip(), CancellationToken::new())
        .await
        .expect("apply should succeed");

    let recorded = backend.set_ips.lock().unwrap().clone();
    assert_eq!(recorded.len(), 1);
    assert_eq!(
        recorded[0], resolvers,
        "set_servers must receive the full mixed v4+v6 list"
    );
    applied.shutdown().await;
}

/// `Dns::apply` performs zero `get_settings` calls — nothing is captured
/// before overwriting resolvers, because there is nothing left to restore
/// but `hole-tun` itself.
#[skuld::test]
async fn dns_apply_captures_nothing() {
    let backend = MockBackend::new();
    let confiner = MockConfiner::new();
    let dns = SystemDns::new_with_backend(
        Arc::clone(&backend) as Arc<dyn WinDnsBackend>,
        confiner as Arc<dyn DnsConfiner>,
    );

    let mut applied = dns
        .apply(
            vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
            tun_identity(),
            server_ip(),
            CancellationToken::new(),
        )
        .await
        .expect("apply should succeed");

    assert_eq!(backend.get_calls.load(SeqCst), 0);
    applied.shutdown().await;
}

// empty_settings contract (regression: bindreams/hole#437) ============================================================
//
// CONTRACT PINS, not OOB detectors. The original 48-byte out-of-bounds FFI
// access is NOT observable from a unit test: `MockBackend` substitutes at
// the `WinDnsBackend` level — ABOVE `empty_settings` and the real Win32 FFI
// — so no unit test reaches the corrupting path. These pin the constructor's
// contract (the layer that carried the bug); the
// `const _: () = assert!(size_of::<V1>() < size_of::<V3>())` guard in
// windows.rs is the compile-time companion.

use windows::Win32::NetworkManagement::IpHelper::{
    DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER,
};

#[skuld::test]
fn empty_settings_always_stamps_version1() {
    // #437: stamping VERSION3 onto the 64-byte V1 allocation was the OOB.
    // windows-rs models all three DNS FFIs as taking the V1 struct, so V1
    // is the only version that matches the buffer we allocate.
    assert_eq!(super::empty_settings(false).Version, DNS_INTERFACE_SETTINGS_VERSION1);
    assert_eq!(super::empty_settings(true).Version, DNS_INTERFACE_SETTINGS_VERSION1);
}

#[skuld::test]
fn empty_settings_flags_select_family() {
    let v4 = super::empty_settings(false).Flags;
    assert_ne!(v4 & DNS_SETTING_NAMESERVER as u64, 0, "NAMESERVER must always be set");
    assert_eq!(v4 & DNS_SETTING_IPV6 as u64, 0, "v4 must not set the IPV6 flag");

    let v6 = super::empty_settings(true).Flags;
    assert_ne!(v6 & DNS_SETTING_NAMESERVER as u64, 0, "NAMESERVER must always be set");
    assert_ne!(v6 & DNS_SETTING_IPV6 as u64, 0, "v6 must set the IPV6 flag");
}
