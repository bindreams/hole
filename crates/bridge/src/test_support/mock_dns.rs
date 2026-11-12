//! `MockDns` — a recording [`Dns`] implementation for unit tests that need
//! to observe what [`Dns::apply`] was called with, without touching the
//! host's real OS DNS. Mirrors `MockProxy` / `MockRouting`'s
//! state-handle-captured-before-move shape in `proxy_manager_tests.rs`.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use tokio_util::sync::CancellationToken;

use crate::dns::system::{Dns, DnsApplied, DnsError, RoutedFamilies};
use crate::test_support::EventLog;

/// One recorded [`Dns::apply`] call. `targets` is named generically — not
/// `apply_aliases` — because it carries the single `TunIdentity`'s alias
/// wrapped in a one-element `Vec`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DnsApplyCall {
    pub(crate) advertise_ips: Vec<IpAddr>,
    pub(crate) targets: Vec<String>,
    pub(crate) server_ip: IpAddr,
    /// What `RoutesInstalled::routed_families` reported for the install this
    /// apply followed — recorded so a test can prove the value actually
    /// travels from the routes guard to `Dns::apply`, rather than both ends
    /// being correct in isolation.
    pub(crate) routed: RoutedFamilies,
}

/// Instrumentation shared between `MockDns` and the handle a test clones
/// out before handing the mock to `ProxyManager::new_with_dns`.
#[derive(Default)]
pub(crate) struct MockDnsState {
    calls: Mutex<Vec<DnsApplyCall>>,
    shutdown_called: std::sync::atomic::AtomicBool,
    /// When `Some`, `apply` returns this error instead of recording a call
    /// or succeeding. Lets a test simulate a `DnsError::Confine` /
    /// `DnsError::Cancelled` / `DnsError::Io` failure without a real
    /// confinement or backend.
    fail_with: Mutex<Option<FailKind>>,
    /// When `Some`, dropping a [`MockDnsApplied`] appends "dns" to this log.
    drop_log: Mutex<Option<EventLog>>,
}

/// Which [`DnsError`] variant [`MockDns::apply`] should return, chosen by a
/// test via [`MockDns::fail_with`]. A plain enum (not the error itself) —
/// `DnsError` isn't `Clone`, and a test only ever needs to select a shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FailKind {
    Cancelled,
    Io,
    #[cfg(target_os = "windows")]
    Confine,
}

impl MockDnsState {
    pub(crate) fn calls(&self) -> Vec<DnsApplyCall> {
        self.calls.lock().unwrap().clone()
    }

    pub(crate) fn shutdown_called(&self) -> bool {
        self.shutdown_called.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Record "dns" in `log` whenever an applied guard is dropped.
    pub(crate) fn log_drops_to(&self, log: EventLog) {
        *self.drop_log.lock().unwrap() = Some(log);
    }
}

pub(crate) struct MockDns {
    state: Arc<MockDnsState>,
}

impl MockDns {
    pub(crate) fn new() -> Self {
        Self {
            state: Arc::new(MockDnsState::default()),
        }
    }

    pub(crate) fn state_handle(&self) -> Arc<MockDnsState> {
        Arc::clone(&self.state)
    }

    /// Make every subsequent `apply` call return the given error kind
    /// instead of recording a call.
    pub(crate) fn fail_with(self, kind: FailKind) -> Self {
        *self.state.fail_with.lock().unwrap() = Some(kind);
        self
    }
}

impl Dns for MockDns {
    type Applied = MockDnsApplied;

    async fn apply(
        &self,
        advertise_ips: Vec<IpAddr>,
        routed: RoutedFamilies,
        tun: tun_engine::TunIdentity,
        server_ip: IpAddr,
        _cancel: CancellationToken,
    ) -> Result<Self::Applied, DnsError> {
        if let Some(kind) = *self.state.fail_with.lock().unwrap() {
            return Err(match kind {
                FailKind::Cancelled => DnsError::Cancelled,
                FailKind::Io => DnsError::Io(std::io::Error::other("mock dns failure")),
                #[cfg(target_os = "windows")]
                FailKind::Confine => DnsError::Confine(tun_engine::dns_confine::DnsConfineError::EngineOpen(
                    std::io::Error::other("mock confine failure"),
                )),
            });
        }
        self.state.calls.lock().unwrap().push(DnsApplyCall {
            advertise_ips,
            targets: vec![tun.alias().to_string()],
            server_ip,
            routed,
        });
        Ok(MockDnsApplied {
            state: Arc::clone(&self.state),
        })
    }
}

/// RAII guard `MockDns::apply` returns. Deliberately carries no drop bomb
/// (unlike `SystemDnsApplied`) — this mock exists to observe call
/// arguments, not to pin the production shutdown-safety contract.
pub(crate) struct MockDnsApplied {
    state: Arc<MockDnsState>,
}

impl DnsApplied for MockDnsApplied {
    async fn shutdown(&mut self) {
        self.state
            .shutdown_called
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Drop for MockDnsApplied {
    fn drop(&mut self) {
        if let Some(log) = self.state.drop_log.lock().unwrap().as_ref() {
            log.lock().unwrap().push("dns");
        }
    }
}
