// Application state management.

use crate::bridge_client::{BridgeClient, ClientError};
use hole_common::config::AppConfig;
use hole_common::config_store::ConfigStore;
use hole_common::protocol::{BridgeRequest, BridgeResponse, StartError};
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
    /// Whether the bridge is externally supervised — the GUI was pointed at a
    /// caller-provided socket via `HOLE_BRIDGE_SOCKET` (dev-console / manual dev
    /// run) instead of the platform default. In that mode the GUI does NOT own
    /// the bridge lifecycle: it must not prompt to install the production service
    /// nor elevate, since the elevated helper and the post-install reachability
    /// poll both target the default production socket, not this one (#569).
    bridge_externally_supervised: bool,
}

// Loading (with quarantine, logging, and the #481/#467 recovery dialog data)
// lives in `ConfigStore::load`; main.rs calls it and hands the results here.

impl AppState {
    pub fn new(config_store: ConfigStore, config: AppConfig, app_handle: tauri::AppHandle) -> Self {
        // The self-heal hook captures the AppHandle (BridgeLink has none of
        // its own). `hole::selfheal` resolves in both the lib and bin units.
        let hook_app = app_handle.clone();
        let self_heal: SelfHealHook = std::sync::Arc::new(move |bridge| hole::selfheal::trigger(&hook_app, bridge));
        let (socket_path, externally_supervised) =
            resolve_bridge_socket(std::env::var_os("HOLE_BRIDGE_SOCKET").map(PathBuf::from));
        Self {
            config_store,
            config: Mutex::new(config),
            app_handle,
            link: BridgeLink::new(socket_path, self_heal),
            test_locks: tokio::sync::Mutex::new(HashMap::new()),
            pending_startup_connect: AtomicBool::new(false),
            bridge_externally_supervised: externally_supervised,
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

    /// True when the GUI was pointed at a caller-provided bridge socket via
    /// `HOLE_BRIDGE_SOCKET` (dev-console / manual dev run); see the field doc.
    pub fn bridge_is_externally_supervised(&self) -> bool {
        self.bridge_externally_supervised
    }

    pub fn subscribe_proxy_state(&self) -> tokio::sync::watch::Receiver<ProxySnapshot> {
        self.link.cell().subscribe()
    }
}

/// Resolve the bridge socket path and whether it was externally provided.
/// `override_path` is the `HOLE_BRIDGE_SOCKET` value (read once at `AppState`
/// construction; the env var is process-global and skuld tests share a process,
/// so this takes the value as a parameter to stay purely testable). A non-empty
/// value ⇒ externally supervised (dev-console / manual dev run); absent or empty
/// ⇒ the platform default production socket (an empty `HOLE_BRIDGE_SOCKET=` is
/// malformed and conventionally means unset — never an external "" socket).
fn resolve_bridge_socket(override_path: Option<PathBuf>) -> (PathBuf, bool) {
    match override_path.filter(|path| !path.as_os_str().is_empty()) {
        Some(path) => (path, true),
        None => (hole_common::protocol::default_bridge_socket_path(), false),
    }
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

/// The path-free failure reason surfaced when a Windows update cutover wedges —
/// its driver died mid-swap with the marker still present. GUI-set (not a bridge
/// death reason), so it flows through `map_status_response` unchanged and cannot
/// leak PII.
pub(crate) const UPDATE_FAILED: &str = "The update didn't finish and the connection was lost.";

/// Resolves the cutover DRIVER's liveness from its marker identity: `Some(true)`
/// alive, `Some(false)` confirmed dead, `None` unassessed. Injected so `BridgeLink`
/// stays testable and the masking decision stays `#[cfg]`-free.
pub type DriverLiveness = std::sync::Arc<dyn Fn(&hole_common::update_marker::MarkerInfo) -> Option<bool> + Send + Sync>;

/// Windows: the driver is alive iff its PID is a running process whose creation
/// time matches (exit-state + exact-equality). A stored `0` is a poisoned/absent
/// identity → `None` (unassessed, never confirmed-dead). Off Windows there is no
/// trackable persistent driver → `None`.
fn production_driver_liveness() -> DriverLiveness {
    #[cfg(target_os = "windows")]
    {
        std::sync::Arc::new(|m: &hole_common::update_marker::MarkerInfo| {
            if m.driver_start_unix_ms == 0 {
                return None;
            }
            Some(hole_common::process::process_matches_and_alive(
                m.driver_pid,
                m.driver_start_unix_ms,
            ))
        })
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::sync::Arc::new(|_m| None)
    }
}

pub struct BridgeLink {
    socket_path: PathBuf,
    /// SERVICE log dir where the privileged bridge writes the update-in-progress
    /// marker. Cached at construction; overridable for tests (skuld shares a
    /// process, so per-test markers must not collide on the real system dir).
    service_log_dir: PathBuf,
    client: tokio::sync::Mutex<Option<BridgeClient>>,
    cell: ProxyStateCell,
    self_heal: SelfHealHook,
    /// Resolves the cutover driver's liveness (Part B). Production self-wires
    /// `production_driver_liveness`; tests inject a stub.
    driver_liveness: DriverLiveness,
}

impl BridgeLink {
    pub fn new(socket_path: PathBuf, self_heal: SelfHealHook) -> Self {
        Self::with_service_log_dir(socket_path, hole_common::update_marker::service_log_dir(), self_heal)
    }

    /// Construct with an explicit service log dir (tests inject a temp dir so
    /// per-test markers don't collide across the shared skuld process).
    pub fn with_service_log_dir(socket_path: PathBuf, service_log_dir: PathBuf, self_heal: SelfHealHook) -> Self {
        Self::with_service_log_dir_and_liveness(socket_path, service_log_dir, self_heal, production_driver_liveness())
    }

    /// Construct with an explicit service log dir AND driver-liveness resolver.
    /// Tests inject a stub liveness so the mask/unmask/failure arms are driven
    /// without a real process to probe.
    pub fn with_service_log_dir_and_liveness(
        socket_path: PathBuf,
        service_log_dir: PathBuf,
        self_heal: SelfHealHook,
        driver_liveness: DriverLiveness,
    ) -> Self {
        Self {
            socket_path,
            service_log_dir,
            client: tokio::sync::Mutex::new(None),
            cell: ProxyStateCell::new(),
            self_heal,
            driver_liveness,
        }
    }

    pub fn cell(&self) -> &ProxyStateCell {
        &self.cell
    }

    /// Read the cutover marker and (if present) resolve its driver's liveness,
    /// fresh per exchange so the masking window opens and closes with the marker.
    fn cutover_state(&self) -> (Option<hole_common::update_marker::MarkerInfo>, Option<bool>) {
        let marker = hole_common::update_marker::read(&self.service_log_dir);
        let driver_alive = marker.as_ref().and_then(|m| (self.driver_liveness)(m));
        (marker, driver_alive)
    }

    /// Commit an exchange's observation under the current cutover decision. On a
    /// wedged cutover (`UnmaskFailed` + not running) surface `UPDATE_FAILED` —
    /// but only if the marker FILE is still present at commit: a swept marker
    /// means the successor won (a completed cutover), so pass through. Any other
    /// resolved observation retracts a stale `UPDATE_FAILED`.
    fn commit_observation(
        &self,
        decision: CutoverDecision,
        running: bool,
        result: &Result<BridgeResponse, ClientError>,
    ) {
        if !running && decision == CutoverDecision::UnmaskFailed {
            // "Successor won" ⇒ the marker FILE is gone. Use `exists()`, not
            // `read()` (which also returns None for a present-but-corrupt marker)
            // — a present-but-unparsable marker with a dead driver is a real
            // wedge, not a completed cutover, so it must still surface the failure.
            if self
                .service_log_dir
                .join(hole_common::update_marker::MARKER_FILE)
                .exists()
            {
                self.cell.commit_update_failed(UPDATE_FAILED);
                return;
            }
            tracing::debug!("cutover marker file gone before commit; treating as a completed cutover");
        }
        // A resolved observation retracts any stale wedge failure.
        self.cell.clear_update_failed(UPDATE_FAILED);
        match observed_lockdown(result) {
            Some((le, la)) => self.cell.commit_status(running, observed_error(result), le, la),
            None => self.cell.commit(running),
        }
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
        let (marker, driver_alive) = self.cutover_state();
        let decision = cutover_decision(marker.as_ref(), driver_alive);
        let result = Self::send_locked(&mut guard, &self.socket_path, req).await;
        if let Some(running) = observed_running(kind, &result, matches!(decision, CutoverDecision::Mask)) {
            self.commit_observation(decision, running, &result);
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
        let (marker, driver_alive) = self.cutover_state();
        let decision = cutover_decision(marker.as_ref(), driver_alive);
        let status = Self::send_locked(&mut guard, &self.socket_path, BridgeRequest::Status).await;
        self.note_mismatch(&status);
        if let Some(running) = observed_running(ReqKind::Status, &status, matches!(decision, CutoverDecision::Mask)) {
            self.commit_observation(decision, running, &status);
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ProxySnapshot {
    pub seq: u64,
    pub running: bool,
    /// Reason for the most recent running transition, when the bridge reported
    /// one (#470). Carried on BOTH the poll and the `proxy-state-changed` event
    /// so whichever channel wins the death-seq race surfaces the same string.
    /// Only ever a path-free sentinel or `None`: the bridge's out-of-band-death
    /// reason (set by `commit_status`; cleared by `commit`) OR the GUI-set
    /// `UPDATE_FAILED` for a wedged update cutover (set by `commit_update_failed`;
    /// cleared by `clear_update_failed`). A toast of this value cannot leak PII —
    /// see `commands::map_status_response`.
    pub error: Option<String>,
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
            error: None,
            lockdown_enabled: false,
            lockdown_active: false,
        });
        Self { tx }
    }

    /// Commit an observed running state. Bumps `seq` (and wakes watchers)
    /// only when the value actually changes. Preserves the lockdown fields
    /// (the non-Status paths that call this only know `running`) and clears
    /// `error`: a non-Status running edge (Start/Stop/Cancel) is user-initiated
    /// and carries no death reason (#470).
    pub fn commit(&self, running: bool) {
        self.tx.send_if_modified(|snap| {
            if snap.running == running {
                return false;
            }
            *snap = ProxySnapshot {
                seq: snap.seq + 1,
                running,
                error: None,
                lockdown_enabled: snap.lockdown_enabled,
                lockdown_active: snap.lockdown_active,
            };
            true
        });
    }

    /// Commit a full Status observation (running + error + lockdown). Bumps
    /// `seq` (waking watchers) when `running` or a lockdown field changes. Used
    /// by the `Status` arm so all commit atomically under the one client lock.
    /// `error` rides the same write — it is meaningful only alongside a running
    /// edge (a death), so it is not part of the change check.
    pub fn commit_status(&self, running: bool, error: Option<String>, lockdown_enabled: bool, lockdown_active: bool) {
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
                error,
                lockdown_enabled,
                lockdown_active,
            };
            true
        });
    }

    /// Commit a wedged-cutover failure: Disconnected + the path-free reason.
    /// Idempotent — re-committing the same failure does not bump `seq`.
    pub fn commit_update_failed(&self, reason: &'static str) {
        self.tx.send_if_modified(|snap| {
            if !snap.running && snap.error.as_deref() == Some(reason) {
                return false;
            }
            *snap = ProxySnapshot {
                seq: snap.seq + 1,
                running: false,
                error: Some(reason.to_string()),
                lockdown_enabled: snap.lockdown_enabled,
                lockdown_active: snap.lockdown_active,
            };
            true
        });
    }

    /// Clear the sticky wedge reason from the backend snapshot once the cutover
    /// resolves, even if `running` is unchanged, so subsequent `get_proxy_status`
    /// polls no longer carry the stale error. The toast itself is transient (fired
    /// once on the true→false death edge and faded); this is snapshot hygiene, not
    /// a toast-dismiss. `commit`/`commit_status` don't key change-detection on
    /// `error`, so this dedicated clear is what retracts it.
    pub fn clear_update_failed(&self, reason: &'static str) {
        self.tx.send_if_modified(|snap| {
            if snap.error.as_deref() != Some(reason) {
                return false;
            }
            snap.seq += 1;
            snap.error = None;
            true
        });
    }

    pub fn snapshot(&self) -> ProxySnapshot {
        self.tx.borrow().clone()
    }

    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<ProxySnapshot> {
        self.tx.subscribe()
    }
}

// Cutover masking decision (Part B) ===================================================================================

/// What the GUI should do with an exchange's observation while a cutover marker
/// is (or is not) present, given the cutover DRIVER's liveness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CutoverDecision {
    /// No cutover in flight (or it resolved) — commit the observation as usual.
    PassThrough,
    /// A cutover is in flight and the driver is alive (or unassessed) — hold the
    /// last snapshot so the restart gap is not a surprise Disconnected.
    Mask,
    /// A cutover marker is present but the driver is CONFIRMED dead — the cutover
    /// is abandoned; unmask and surface the wedged-update failure.
    UnmaskFailed,
}

/// Single source of truth for the cutover masking decision. `driver_alive`:
/// `Some(true)` alive, `Some(false)` confirmed dead, `None` unassessed (macOS or
/// a poisoned/absent identity). No marker ⇒ PassThrough regardless of liveness.
pub(crate) fn cutover_decision(
    marker: Option<&hole_common::update_marker::MarkerInfo>,
    driver_alive: Option<bool>,
) -> CutoverDecision {
    match (marker, driver_alive) {
        (None, _) => CutoverDecision::PassThrough,
        (Some(_), Some(false)) => CutoverDecision::UnmaskFailed,
        (Some(_), _) => CutoverDecision::Mask,
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

/// What a completed bridge exchange proves about `running`, if anything.
///
/// - Stop+Error commits nothing: the bridge takes the running slot before
///   teardown (`ProxyManager::stop`), so its own Status already reports
///   false — the caller follows up with a Status instead of guessing.
/// - PermissionDenied commits nothing: a connect-phase DACL rejection
///   says nothing about the tunnel.
/// - Transport errors on tracked kinds commit false: an unreachable
///   bridge tunnels nothing (the mapping `get_proxy_status` always used).
/// - While the cutover mask is active (a marker present with a live/unassessed
///   driver) both a transport error AND a reachable running:false commit
///   nothing: the bridge is mid-restart, so the gap is expected, not a
///   Disconnected — hold the last snapshot. The mask is dropped (decision
///   PassThrough) once the marker is swept or the driver is confirmed dead.
pub(crate) fn observed_running(
    kind: ReqKind,
    result: &Result<BridgeResponse, ClientError>,
    update_in_progress: bool,
) -> Option<bool> {
    use ReqKind::*;
    match (kind, result) {
        (Other, _) => None,
        (_, Err(ClientError::PermissionDenied)) => None,
        // A version mismatch triggers self-heal; do not flip `running` during
        // the self-heal window (must precede the `(_, Err(_))` catch-all).
        (_, Err(ClientError::VersionMismatch { .. })) => None,
        // Concurrent start (409): another start owns the running slot, so this says nothing.
        (_, Err(ClientError::ConcurrentStart)) => None,
        // A cutover is in progress (the bridge is mid-restart). A transport
        // error here is the expected gap, not a Disconnected — hold the last
        // snapshot. Must precede the `(_, Err(_))` catch-all, like the
        // VersionMismatch arm: keying on VersionMismatch alone is too late, as
        // it arrives only after the new bridge answers.
        (_, Err(_)) if update_in_progress => None,
        (_, Err(_)) => Some(false),
        // A reachable running:false DURING a cutover is held (no surprise
        // Disconnected — e.g. the proxy self-dies via `check_health` while the old
        // bridge still serves); released once the marker is swept (the decision is
        // then PassThrough, not Mask). Must precede the general Status-Ok arm.
        (Status, Ok(BridgeResponse::Status { running: false, .. })) if update_in_progress => None,
        (Status, Ok(BridgeResponse::Status { running, .. })) => Some(*running),
        (Start, Ok(BridgeResponse::Ack)) => Some(true),
        (Start, Ok(BridgeResponse::StartFailed(e))) => match e {
            // A failed start is rolled back bridge-side.
            StartError::Cancelled | StartError::NetworkBlocked | StartError::Failed { .. } => Some(false),
            StartError::AlreadyRunning => Some(true),
        },
        (Stop, Ok(BridgeResponse::Ack)) => Some(false),
        (Stop, Ok(BridgeResponse::Error { .. })) => None,
        (_, Ok(_)) => None,
    }
}

/// The error a Status exchange revealed, if any. Only a `Status` Ok carries it
/// (#470); every other exchange yields None. `StatusResponse.error` is the
/// bridge's path-free `death_reason` (NOT the PII-bearing `last_error`; see
/// `ProxyManager::DEATH_REASON`), so this can never carry PII to the toast.
pub(crate) fn observed_error(result: &Result<BridgeResponse, ClientError>) -> Option<String> {
    match result {
        Ok(BridgeResponse::Status { error, .. }) => error.clone(),
        _ => None,
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
