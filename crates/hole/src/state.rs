// Application state management.

use crate::bridge_client::{BridgeClient, ClientError};
use hole_common::config::AppConfig;
use hole_common::config_store::ConfigStore;
use hole_common::protocol::{BridgeRequest, BridgeResponse, CANCELLED_MESSAGE};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tracing::warn;

/// Shared application state managed by Tauri.
pub struct AppState {
    pub config_store: ConfigStore,
    pub config: Mutex<AppConfig>,
    /// Tauri app handle, used by commands that need to emit events
    /// (currently `test_server` → `validation-changed`).
    pub app_handle: tauri::AppHandle,
    pub(crate) link: BridgeLink,
    /// Per-entry test serialization. Acquired for the entire duration of a
    /// `test_server` call so a slower test cannot overwrite a faster newer
    /// one. Different entries do NOT contend.
    test_locks: tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// One-shot startup-connect intent (#458): armed at launch when the
    /// `on_startup` policy says connect, consumed by the status reconciler the
    /// first time the bridge proves reachable (so a cold-boot race against the
    /// bridge's socket bind can't drop the connect).
    pending_startup_connect: AtomicBool,
}

// Loading (with quarantine, logging, and the #481/#467 recovery dialog data)
// lives in `ConfigStore::load`; main.rs calls it and hands the results here.

impl AppState {
    pub fn new(config_store: ConfigStore, config: AppConfig, app_handle: tauri::AppHandle) -> Self {
        // The self-heal hook captures the AppHandle (BridgeLink has none of
        // its own). `hole::selfheal` resolves in both the lib and bin units.
        let hook_app = app_handle.clone();
        let self_heal: SelfHealHook = std::sync::Arc::new(move |bridge| hole::selfheal::trigger(&hook_app, bridge));
        Self {
            config_store,
            config: Mutex::new(config),
            app_handle,
            link: BridgeLink::new(resolve_bridge_socket_path(), self_heal),
            test_locks: tokio::sync::Mutex::new(HashMap::new()),
            pending_startup_connect: AtomicBool::new(false),
        }
    }

    /// Arm the one-shot startup-connect intent (#458). Called once at launch
    /// when `startup_should_connect` is true; the status reconciler applies it.
    pub fn arm_pending_startup_connect(&self) {
        self.pending_startup_connect.store(true, Ordering::Release);
    }

    /// Consume the startup-connect intent, returning whether it was armed.
    /// Single-shot: a second call returns false, so the reconciler connects at
    /// most once even if two ticks observe a reachable bridge.
    pub fn take_pending_startup_connect(&self) -> bool {
        self.pending_startup_connect.swap(false, Ordering::AcqRel)
    }

    /// Fetch (or create on first access) the per-entry async mutex used to
    /// serialize concurrent `test_server` calls on the same entry. The
    /// outer mutex around the HashMap is held only for the lookup; the
    /// inner per-entry mutex is what serializes the test runs.
    pub async fn entry_test_lock(&self, entry_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.test_locks.lock().await;
        locks
            .entry(entry_id.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    pub async fn bridge_send(&self, req: BridgeRequest) -> Result<BridgeResponse, ClientError> {
        self.link.send(req).await
    }

    pub async fn bridge_send_oneshot(&self, req: BridgeRequest) -> Result<BridgeResponse, ClientError> {
        self.link.send_oneshot(req).await
    }

    pub fn proxy_snapshot(&self) -> ProxySnapshot {
        self.link.cell().snapshot()
    }

    pub fn subscribe_proxy_state(&self) -> tokio::sync::watch::Receiver<ProxySnapshot> {
        self.link.cell().subscribe()
    }
}

/// Resolve the bridge socket path from `HOLE_BRIDGE_SOCKET` or the
/// platform default. Read once at `AppState` construction; tests inject
/// per-test paths directly into `BridgeLink::new` instead (the env var is
/// process-global and skuld tests may share a process).
fn resolve_bridge_socket_path() -> PathBuf {
    std::env::var("HOLE_BRIDGE_SOCKET")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(hole_common::protocol::default_bridge_socket_path)
}

// BridgeLink ==========================================================================================================

/// The GUI's bridge channel plus the runtime-state cell it feeds (#462).
///
/// All pooled requests flow through `send`, which commits what the
/// exchange revealed about `running` (see `observed_running`) BEFORE
/// releasing the client lock — commit order therefore equals bridge
/// processing order, with no separate synchronization.
/// Fired (off the reactor) whenever a bridge exchange reveals a version
/// mismatch, to drive the GUI self-heal. Injected so `BridgeLink` stays
/// testable and holds no `AppHandle` of its own.
pub type SelfHealHook = std::sync::Arc<dyn Fn(Option<String>) + Send + Sync>;

pub struct BridgeLink {
    socket_path: PathBuf,
    client: tokio::sync::Mutex<Option<BridgeClient>>,
    cell: ProxyStateCell,
    self_heal: SelfHealHook,
}

impl BridgeLink {
    pub fn new(socket_path: PathBuf, self_heal: SelfHealHook) -> Self {
        Self {
            socket_path,
            client: tokio::sync::Mutex::new(None),
            cell: ProxyStateCell::new(),
            self_heal,
        }
    }

    pub fn cell(&self) -> &ProxyStateCell {
        &self.cell
    }

    /// Drive the self-heal hook if the exchange revealed a version mismatch.
    /// Covers every send path (pooled, oneshot, reload) since all funnel here.
    fn note_mismatch(&self, result: &Result<BridgeResponse, ClientError>) {
        if let Err(ClientError::VersionMismatch { bridge }) = result {
            (self.self_heal)(bridge.clone());
        }
    }

    /// Send a request to the bridge, lazily connecting on first use.
    /// On connection failure, clears the cached client so the next call
    /// reconnects.
    pub async fn send(&self, req: BridgeRequest) -> Result<BridgeResponse, ClientError> {
        let kind = ReqKind::of(&req);
        let mut guard = self.client.lock().await;
        let result = Self::send_locked(&mut guard, &self.socket_path, req).await;
        if let Some(running) = observed_running(kind, &result) {
            // A Status exchange reveals lockdown too — commit all three
            // atomically under this lock; other exchanges know only `running`.
            match observed_lockdown(&result) {
                Some((le, la)) => self.cell.commit_status(running, le, la),
                None => self.cell.commit(running),
            }
        }
        self.note_mismatch(&result);
        result
    }

    /// The transport body, operating on the already-held client guard so
    /// every exit path stays inside the lock until the caller has
    /// committed its observation.
    async fn send_locked(
        guard: &mut Option<BridgeClient>,
        socket_path: &std::path::Path,
        req: BridgeRequest,
    ) -> Result<BridgeResponse, ClientError> {
        // Lazy connect
        if guard.is_none() {
            match BridgeClient::connect(socket_path).await {
                Ok(client) => *guard = Some(client),
                Err(e) => {
                    warn!(error = %e, "failed to connect to bridge");
                    return Err(e);
                }
            }
        }

        // Send request
        match guard
            .as_mut()
            .expect("guaranteed Some after lazy-connect block")
            .send(req)
            .await
        {
            Ok(resp) => Ok(resp),
            // A version mismatch is not a broken connection — keep the pooled
            // client (reconnecting cannot fix a version skew). `ClientError`
            // is not `Clone`, so bind-and-move the error out of the match.
            Err(e @ ClientError::VersionMismatch { .. }) => Err(e),
            Err(e) => {
                // Connection broken — clear so next call reconnects
                warn!(error = %e, "bridge communication error, will reconnect");
                *guard = None;
                Err(e)
            }
        }
    }

    /// Send a request over a fresh, single-use bridge connection that
    /// bypasses the pooled client. This exists specifically so
    /// `BridgeRequest::Cancel` can race an in-flight request on the main
    /// connection: `send` holds the client lock for the entire duration of
    /// each request, which would otherwise block a concurrent cancel until
    /// the request it is trying to cancel finishes.
    ///
    /// Deliberately never commits an observation: the raced Start's own
    /// outcome carries the truth.
    ///
    /// Unix-domain-socket connect latency is sub-millisecond, so the
    /// per-call overhead is negligible. Use sparingly — the pooled client
    /// is still the right choice for normal request traffic.
    pub async fn send_oneshot(&self, req: BridgeRequest) -> Result<BridgeResponse, ClientError> {
        let mut client = BridgeClient::connect(&self.socket_path).await?;
        let result = client.send(req).await;
        self.note_mismatch(&result);
        result
    }

    /// Send Reload iff the proxy is running, decided at the linearization
    /// point: Status and Reload ride ONE client-lock acquisition, so the
    /// check cannot go stale against a concurrent Start/Stop (they queue
    /// behind this lock). The check is load-bearing: bridge-side `reload`
    /// on a stopped proxy STARTS it, so an unguarded Reload queued behind
    /// a failed Start would resurrect the tunnel.
    ///
    /// Returns Ok(false) when skipped (not running), Ok(true) on a
    /// successful reload.
    pub async fn reload_if_running(&self, config: hole_common::protocol::ProxyConfig) -> Result<bool, String> {
        let mut guard = self.client.lock().await;
        let status = Self::send_locked(&mut guard, &self.socket_path, BridgeRequest::Status).await;
        self.note_mismatch(&status);
        if let Some(running) = observed_running(ReqKind::Status, &status) {
            match observed_lockdown(&status) {
                Some((le, la)) => self.cell.commit_status(running, le, la),
                None => self.cell.commit(running),
            }
        }
        if !matches!(status, Ok(BridgeResponse::Status { running: true, .. })) {
            return Ok(false); // Not running; changes apply on next start.
        }
        let reload = Self::send_locked(&mut guard, &self.socket_path, BridgeRequest::Reload { config }).await;
        self.note_mismatch(&reload);
        match reload {
            Ok(BridgeResponse::Ack) => Ok(true),
            Ok(BridgeResponse::Error { message }) => Err(message),
            Ok(_) => Err("unexpected response from bridge".into()),
            Err(e) => Err(e.to_string()),
        }
    }
}

// Proxy runtime state =================================================================================================

/// A versioned observation of the proxy's runtime state. `seq` increases
/// only when `running` changes; consumers (tray watcher, webview) discard
/// observations whose seq is not newer than the last applied, which makes
/// application monotone across the unordered event/poll channels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct ProxySnapshot {
    pub seq: u64,
    pub running: bool,
    /// Standing kill-switch intent (#527), from the bridge's StatusResponse.
    pub lockdown_enabled: bool,
    /// Whether a lockdown cover is engaged. `enabled && !active` is a tray
    /// warning state — never silent green.
    pub lockdown_active: bool,
}

/// Single owner of the GUI's view of "is the proxy running" (#462).
pub struct ProxyStateCell {
    tx: tokio::sync::watch::Sender<ProxySnapshot>,
}

impl Default for ProxyStateCell {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyStateCell {
    pub fn new() -> Self {
        let (tx, _) = tokio::sync::watch::channel(ProxySnapshot {
            seq: 0,
            running: false,
            lockdown_enabled: false,
            lockdown_active: false,
        });
        Self { tx }
    }

    /// Commit an observed running state. Bumps `seq` (and wakes watchers)
    /// only when the value actually changes. Preserves the lockdown fields:
    /// the non-Status paths that call this only know `running`.
    pub fn commit(&self, running: bool) {
        self.tx.send_if_modified(|snap| {
            if snap.running == running {
                return false;
            }
            *snap = ProxySnapshot {
                seq: snap.seq + 1,
                running,
                ..*snap
            };
            true
        });
    }

    /// Commit a full Status observation (running + lockdown). Bumps `seq`
    /// (waking watchers) when any field changes. Used by the `Status` arm so
    /// all three commit atomically under the one client lock.
    pub fn commit_status(&self, running: bool, lockdown_enabled: bool, lockdown_active: bool) {
        self.tx.send_if_modified(|snap| {
            if snap.running == running
                && snap.lockdown_enabled == lockdown_enabled
                && snap.lockdown_active == lockdown_active
            {
                return false;
            }
            *snap = ProxySnapshot {
                seq: snap.seq + 1,
                running,
                lockdown_enabled,
                lockdown_active,
            };
            true
        });
    }

    pub fn snapshot(&self) -> ProxySnapshot {
        *self.tx.borrow()
    }

    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<ProxySnapshot> {
        self.tx.subscribe()
    }
}

/// Which request kinds reveal the proxy's running state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReqKind {
    Status,
    Start,
    Stop,
    Other,
}

impl ReqKind {
    fn of(req: &BridgeRequest) -> Self {
        match req {
            BridgeRequest::Status => Self::Status,
            BridgeRequest::Start { .. } => Self::Start,
            BridgeRequest::Stop => Self::Stop,
            _ => Self::Other,
        }
    }
}

/// The bridge's Start-error taxonomy, classified in exactly one place —
/// both the runtime-truth axis (`observed_running`) and the user-outcome
/// axis (`tray::outcome_for_start_response`) consume this; the string
/// literals must never appear anywhere else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartErrorKind {
    Cancelled,
    AlreadyRunning,
    Other,
}

pub(crate) fn classify_start_error(message: &str) -> StartErrorKind {
    if message == CANCELLED_MESSAGE {
        StartErrorKind::Cancelled
    } else if message.contains("already running") {
        StartErrorKind::AlreadyRunning
    } else {
        StartErrorKind::Other
    }
}

/// What a completed bridge exchange proves about `running`, if anything.
///
/// - Stop+Error commits nothing: the bridge takes the running slot before
///   teardown (`ProxyManager::stop`), so its own Status already reports
///   false — the caller follows up with a Status instead of guessing.
/// - PermissionDenied commits nothing: a connect-phase DACL rejection
///   says nothing about the tunnel.
/// - Transport errors on tracked kinds commit false: an unreachable
///   bridge tunnels nothing (the mapping `get_proxy_status` always used).
pub(crate) fn observed_running(kind: ReqKind, result: &Result<BridgeResponse, ClientError>) -> Option<bool> {
    use ReqKind::*;
    match (kind, result) {
        (Other, _) => None,
        (_, Err(ClientError::PermissionDenied)) => None,
        // A version mismatch triggers self-heal; do not flip `running` during
        // the self-heal window (must precede the `(_, Err(_))` catch-all).
        (_, Err(ClientError::VersionMismatch { .. })) => None,
        (_, Err(_)) => Some(false),
        (Status, Ok(BridgeResponse::Status { running, .. })) => Some(*running),
        (Start, Ok(BridgeResponse::Ack)) => Some(true),
        (Start, Ok(BridgeResponse::Error { message })) => match classify_start_error(message) {
            StartErrorKind::Cancelled => Some(false),
            // A failed start is rolled back bridge-side.
            StartErrorKind::Other => Some(false),
            StartErrorKind::AlreadyRunning => Some(true),
        },
        (Stop, Ok(BridgeResponse::Ack)) => Some(false),
        (Stop, Ok(BridgeResponse::Error { .. })) => None,
        (_, Ok(_)) => None,
    }
}

/// The lockdown (enabled, active) a Status exchange revealed, if any. Only a
/// `Status` Ok carries them; every other exchange yields None (leave the
/// snapshot's prior lockdown fields untouched).
pub(crate) fn observed_lockdown(result: &Result<BridgeResponse, ClientError>) -> Option<(bool, bool)> {
    match result {
        Ok(BridgeResponse::Status {
            lockdown_enabled,
            lockdown_active,
            ..
        }) => Some((*lockdown_enabled, *lockdown_active)),
        _ => None,
    }
}

#[cfg(test)]
#[path = "state_tests.rs"]
mod state_tests;
