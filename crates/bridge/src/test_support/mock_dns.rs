//! `MockDns` — a recording [`Dns`] implementation for unit tests that need
//! to observe what [`Dns::apply`] was called with, without touching the
//! host's real OS DNS. Mirrors `MockProxy` / `MockRouting`'s
//! state-handle-captured-before-move shape in `proxy_manager_tests.rs`.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tokio_util::sync::CancellationToken;

use crate::dns::system::{Dns, DnsApplied, DnsError};

/// One recorded [`Dns::apply`] call. `targets` is named generically —
/// not `apply_aliases` — because bindreams/hole#846 replaces the
/// alias-list argument with a single `TunIdentity` target; keeping the
/// field name stable across that signature change means tests written
/// against it don't need touching twice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DnsApplyCall {
    pub(crate) advertise_ips: Vec<IpAddr>,
    pub(crate) targets: Vec<String>,
}

/// Instrumentation shared between `MockDns` and the handle a test clones
/// out before handing the mock to `ProxyManager::new_with_dns`.
#[derive(Default)]
pub(crate) struct MockDnsState {
    calls: Mutex<Vec<DnsApplyCall>>,
    /// Set once `MockDnsApplied::shutdown` has run. Not yet read by any
    /// test in this task; a later #846 task asserts on it directly.
    #[allow(dead_code)]
    shutdown_called: std::sync::atomic::AtomicBool,
}

impl MockDnsState {
    pub(crate) fn calls(&self) -> Vec<DnsApplyCall> {
        self.calls.lock().unwrap().clone()
    }

    #[allow(dead_code)]
    pub(crate) fn shutdown_called(&self) -> bool {
        self.shutdown_called.load(std::sync::atomic::Ordering::SeqCst)
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
}

impl Dns for MockDns {
    type Applied = MockDnsApplied;

    async fn apply(
        &self,
        advertise_ips: Vec<IpAddr>,
        capture_aliases: Vec<String>,
        apply_aliases: Vec<String>,
        _state_dir: Option<PathBuf>,
        _owner: Option<(u32, u32)>,
        _cancel: CancellationToken,
    ) -> Result<Self::Applied, DnsError> {
        // Pre-#846 signature still carries a separate capture list; the
        // targets this mock records are the apply side, which is what
        // #846's guard tests care about.
        let _ = capture_aliases;
        self.state.calls.lock().unwrap().push(DnsApplyCall {
            advertise_ips,
            targets: apply_aliases,
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
