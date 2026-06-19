//! IPC server — HTTP/1.1 REST API over local Unix domain socket.

use tun_engine::routing::Routing;

use crate::proxy::{Proxy, ProxyError};
use crate::proxy_manager::{ProxyManager, ProxyState};
use crate::server_test::{run_server_test, TestConfig};
use crate::socket::LocalListener;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use hole_common::protocol::{
    DiagnosticsResponse, EmptyResponse, ErrorResponse, LockdownRequest, MetricsResponse, ProxyConfig, StatusResponse,
    TestServerRequest, TestServerResponse, UpdateApplyRequest, VersionResponse, CANCELLED_MESSAGE, ROUTE_CANCEL,
    ROUTE_DIAGNOSTICS, ROUTE_LOCKDOWN, ROUTE_METRICS, ROUTE_RELOAD, ROUTE_START, ROUTE_STATUS, ROUTE_STOP,
    ROUTE_TEST_SERVER, ROUTE_UPDATE_APPLY, ROUTE_VERSION,
};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
#[allow(unused_imports)]
use tracing::warn;
use tracing::{debug, error, info};

// IPC state ===========================================================================================================

/// State for tracking the in-flight start's cancellation token, plus a
/// "pre-armed" flag that consumes a Cancel arriving before any Start has
/// registered its token. Held in a `std::sync::Mutex` because all access is
/// a trivial read/write of a small struct, never held across `.await`, and
/// the sync lock avoids any coupling with the async proxy mutex.
#[derive(Default)]
pub struct StartCancelState {
    /// Token of the currently-in-flight start, if any. Set by `handle_start`
    /// before calling `pm.start_cancellable`; cleared on exit.
    pub token: Option<CancellationToken>,
    /// Cancel request arrived while no start was in flight. Consumed by the
    /// very next `handle_start` invocation, which returns `Cancelled`
    /// without even attempting to start. Handles the race where a cancel
    /// reaches the bridge before `handle_start` has stored its token.
    pub pending: bool,
}

/// Shared state for IPC handlers, holding the proxy manager and the
/// start-cancellation handoff struct.
pub struct IpcState<P: Proxy, R: Routing> {
    pub proxy: Arc<Mutex<ProxyManager<P, R>>>,
    // std::sync::Mutex — never held across .await. See StartCancelState docs.
    pub start_cancel: Arc<std::sync::Mutex<StartCancelState>>,
    /// This bridge's build version, stamped on every response
    /// (`X-Hole-Bridge-Version`) and served at `/v1/version` so a
    /// freshly-updated GUI can detect a still-old bridge.
    pub version: String,
    /// Service log dir — where the cutover marker is written (GUI-readable).
    pub log_dir: PathBuf,
    /// Service state dir — the same-volume parent for the cutover staging.
    pub state_dir: PathBuf,
}

// Server ==============================================================================================================

/// HTTP/1.1 REST server over a local Unix domain socket.
///
/// The socket file is removed when the server is dropped (best-effort cleanup).
/// Stale socket files from previous runs are removed before binding.
pub struct IpcServer {
    listener: LocalListener,
    router: axum::Router,
    socket_path: PathBuf,
}

impl IpcServer {
    /// Bind to the given Unix domain socket path.
    ///
    /// Removes any stale socket file, creates parent directories, binds with
    /// restrictive initial permissions (umask on macOS, DACL on Windows), and
    /// then applies the final OS-level access control (adding the `hole` group).
    pub fn bind_with_dirs<P: Proxy + 'static, R: Routing + 'static>(
        path: &Path,
        proxy: Arc<Mutex<ProxyManager<P, R>>>,
        version: &str,
        log_dir: PathBuf,
        state_dir: PathBuf,
    ) -> std::io::Result<Self> {
        #[cfg(not(test))]
        let listener = LocalListener::bind_restricted(path)?;
        #[cfg(test)]
        let listener = LocalListener::bind(path)?;

        #[cfg(not(test))]
        apply_socket_permissions(path);

        let state = Arc::new(IpcState {
            proxy,
            start_cancel: Arc::new(std::sync::Mutex::new(StartCancelState::default())),
            version: version.to_owned(),
            log_dir,
            state_dir,
        });
        let router = build_router(state, version);
        Ok(Self {
            listener,
            router,
            socket_path: path.to_owned(),
        })
    }

    /// Test-only shim: production calls `bind_with_dirs`. The cutover dirs
    /// default to a fresh temp dir so per-test markers/staging don't collide
    /// across the shared skuld process.
    #[cfg(test)]
    pub fn bind<P: Proxy + 'static, R: Routing + 'static>(
        path: &Path,
        proxy: Arc<Mutex<ProxyManager<P, R>>>,
        version: &str,
    ) -> std::io::Result<Self> {
        let tmp = tempfile::tempdir()?.keep();
        Self::bind_with_dirs(path, proxy, version, tmp.clone(), tmp)
    }

    /// Accept and handle one client connection, then return.
    /// Useful for testing.
    pub async fn run_once(self) -> std::io::Result<()> {
        let stream = self.listener.accept().await?;
        // Connection errors (client disconnect, shutdown) are non-fatal.
        let _ = serve_connection(TokioIo::new(stream), self.router.clone()).await;
        Ok(())
    }

    /// Accept exactly `n` client connections (in parallel), then return when
    /// all have finished. Test-only helper used by the cancellation tests
    /// that need multiple concurrent connections — using `run()` indefinitely
    /// adds noticeable accept-poll churn on Windows (50 ms `spawn_blocking`
    /// loop) which can starve other parallel tests on slow CI runners.
    #[cfg(test)]
    pub async fn run_n(self, n: usize) -> std::io::Result<()> {
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..n {
            let stream = self.listener.accept().await?;
            let router = self.router.clone();
            tasks.spawn(async move {
                let _ = serve_connection(TokioIo::new(stream), router).await;
            });
        }
        while tasks.join_next().await.is_some() {}
        Ok(())
    }

    /// Run the server loop, accepting connections indefinitely.
    /// Each connection is handled in a separate task.
    pub async fn run(self) -> std::io::Result<()> {
        info!("IPC server listening");
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            // Reap completed tasks to avoid unbounded memory growth
            while let Some(result) = tasks.try_join_next() {
                if let Err(e) = result {
                    error!(error = %e, "connection handler panicked");
                }
            }

            match self.listener.accept().await {
                Ok(stream) => {
                    info!("IPC client connected");
                    let router = self.router.clone();
                    tasks.spawn(async move {
                        if let Err(e) = serve_connection(TokioIo::new(stream), router).await {
                            debug!(error = %e, "HTTP connection ended");
                        }
                        info!("IPC client disconnected");
                    });
                }
                Err(e) => {
                    error!(error = %e, "failed to accept IPC connection");
                }
            }
        }
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Serve HTTP/1.1 on a single connection using the given axum router.
async fn serve_connection<I>(io: TokioIo<I>, router: axum::Router) -> Result<(), hyper::Error>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static,
{
    let service = hyper::service::service_fn(move |req: http::Request<Incoming>| {
        let router = router.clone();
        async move {
            let resp = match router.oneshot(req.map(axum::body::Body::new)).await {
                Ok(resp) => resp,
                Err(e) => match e {},
            };
            Ok::<_, Infallible>(resp)
        }
    });
    hyper::server::conn::http1::Builder::new()
        .serve_connection(io, service)
        .await
}

// Router ==============================================================================================================

fn build_router<P: Proxy + 'static, R: Routing + 'static>(state: Arc<IpcState<P, R>>, version: &str) -> axum::Router {
    // Stamped on every response — including handler errors and routing 404s,
    // which axum has already converted to a `Response` before this layer runs.
    let header_val =
        axum::http::HeaderValue::from_str(version).unwrap_or_else(|_| axum::http::HeaderValue::from_static("unknown"));
    axum::Router::new()
        .route(ROUTE_STATUS, axum::routing::get(handle_status::<P, R>))
        .route(ROUTE_START, axum::routing::post(handle_start::<P, R>))
        .route(ROUTE_STOP, axum::routing::post(handle_stop::<P, R>))
        .route(ROUTE_CANCEL, axum::routing::post(handle_cancel::<P, R>))
        .route(ROUTE_RELOAD, axum::routing::post(handle_reload::<P, R>))
        .route(ROUTE_METRICS, axum::routing::get(handle_metrics::<P, R>))
        .route(ROUTE_DIAGNOSTICS, axum::routing::get(handle_diagnostics::<P, R>))
        .route(ROUTE_TEST_SERVER, axum::routing::post(handle_test_server::<P, R>))
        .route(ROUTE_VERSION, axum::routing::get(handle_version::<P, R>))
        .route(ROUTE_LOCKDOWN, axum::routing::post(handle_lockdown::<P, R>))
        .route(ROUTE_UPDATE_APPLY, axum::routing::post(handle_update_apply::<P, R>))
        .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024))
        .layer(axum::middleware::map_response(
            move |mut resp: axum::response::Response| {
                let header_val = header_val.clone();
                async move {
                    resp.headers_mut().insert("x-hole-bridge-version", header_val);
                    resp
                }
            },
        ))
        .with_state(state)
}

// Handlers ============================================================================================================

async fn handle_status<P: Proxy + 'static, R: Routing + 'static>(
    State(state): State<Arc<IpcState<P, R>>>,
) -> Json<StatusResponse> {
    let mut pm = state.proxy.lock().await;
    pm.check_health();
    Json(StatusResponse {
        running: pm.state() == ProxyState::Running,
        uptime_secs: pm.uptime_secs(),
        error: pm.last_error().map(|s| s.to_string()),
        invalid_filters: pm.invalid_filters(),
        udp_proxy_available: pm.udp_proxy_available(),
        ipv6_bypass_available: pm.ipv6_bypass_available(),
        lockdown_enabled: pm.lockdown_enabled(),
        lockdown_active: pm.lockdown_active(),
    })
}

async fn handle_start<P: Proxy + 'static, R: Routing + 'static>(
    State(state): State<Arc<IpcState<P, R>>>,
    Json(config): Json<ProxyConfig>,
) -> Result<Json<EmptyResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Register the cancellation token BEFORE taking the proxy mutex. If a
    // pre-armed cancel is already queued, consume it and return immediately
    // without even attempting the start. If a concurrent start is already
    // in flight, reject this one — the slot is single-occupancy because a
    // Cancel targets exactly one in-flight start.
    #[allow(clippy::disallowed_methods)]
    // IPC root: every bridge cancel scope descends from this token. See clippy.toml CancellationToken::new rule.
    let token = CancellationToken::new();
    {
        let mut cs = state.start_cancel.lock().expect("start_cancel poisoned");
        if cs.pending {
            cs.pending = false;
            info!("start request consumed pre-armed cancel");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: CANCELLED_MESSAGE.to_string(),
                }),
            ));
        }
        if cs.token.is_some() {
            // A previous handle_start has already registered its token but
            // not yet cleared it (still running or blocked on proxy.lock()).
            // Overwriting the slot would orphan the earlier start from any
            // future Cancel — the Cancel would signal this new token
            // instead — so we reject the duplicate with 409 Conflict rather
            // than silently corrupting the slot.
            warn!("concurrent start request rejected — another start is already in flight");
            return Err((
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    message: "start already in progress".to_string(),
                }),
            ));
        }
        debug_assert!(cs.token.is_none(), "start_cancel token slot invariant");
        cs.token = Some(token.clone());
    }

    let result = {
        let mut pm = state.proxy.lock().await;
        pm.start_cancellable(&config, token).await
    };

    // Clear the token slot regardless of outcome so the next start starts
    // with a clean slate. A Cancel arriving during this tiny window between
    // start_cancellable returning and us clearing the slot would cancel a
    // token that is already done — harmless.
    {
        let mut cs = state.start_cancel.lock().expect("start_cancel poisoned");
        cs.token = None;
    }

    match result {
        Ok(()) => Ok(Json(EmptyResponse {})),
        Err(ProxyError::Cancelled) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                message: CANCELLED_MESSAGE.to_string(),
            }),
        )),
        Err(e) => {
            error!(error = %e, "proxy start failed");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { message: e.to_string() }),
            ))
        }
    }
}

/// Signal the in-flight start's `CancellationToken` if one is registered,
/// or pre-arm a cancel for the next start otherwise. Always 200 Ack — the
/// client's intent is recorded regardless.
async fn handle_cancel<P: Proxy + 'static, R: Routing + 'static>(
    State(state): State<Arc<IpcState<P, R>>>,
) -> Json<EmptyResponse> {
    let mut cs = state.start_cancel.lock().expect("start_cancel poisoned");
    if let Some(t) = &cs.token {
        info!("cancelling in-flight proxy start");
        t.cancel();
    } else {
        info!("no start in flight — pre-arming cancel for next start");
        cs.pending = true;
    }
    Json(EmptyResponse {})
}

/// Set the standing kill switch intent (last-writer-wins absolute set). Any
/// authorized caller may toggle it. The bridge is the authority; the GUI only
/// sends intent. The intent takes effect on the next start/stop — this handler
/// does NOT engage/disengage a live cover.
async fn handle_lockdown<P: Proxy + 'static, R: Routing + 'static>(
    State(state): State<Arc<IpcState<P, R>>>,
    Json(req): Json<LockdownRequest>,
) -> Result<Json<EmptyResponse>, (StatusCode, Json<ErrorResponse>)> {
    let pm = state.proxy.lock().await;
    match pm.set_lockdown_intent(req.enabled) {
        Ok(()) => {
            info!(enabled = req.enabled, "lockdown intent set");
            Ok(Json(EmptyResponse {}))
        }
        Err(e) => {
            error!(error = %e, "failed to set lockdown intent");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { message: e.to_string() }),
            ))
        }
    }
}

async fn handle_update_apply<P: Proxy + 'static, R: Routing + 'static>(
    State(state): State<Arc<IpcState<P, R>>>,
    Json(req): Json<UpdateApplyRequest>,
) -> Result<Json<EmptyResponse>, (StatusCode, Json<ErrorResponse>)> {
    let log_dir = &state.log_dir;

    // Single-occupancy: refuse a second cutover.
    if crate::cutover::apply::cutover_in_progress(log_dir) {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                message: "a cutover is already in progress".into(),
            }),
        ));
    }

    let lockdown_on = { state.proxy.lock().await.lockdown_enabled() };

    // Consent seam: a lockdown-off update without explicit consent is refused
    // with 403 — a client precondition failure (the caller must supply consent),
    // not a server fault.
    match crate::cutover::apply::consent_gate(lockdown_on, req.consent) {
        Ok(()) => {}
        Err(crate::cutover::apply::ConsentError::Required) => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    message: "a lockdown-off update requires explicit consent".into(),
                }),
            ));
        }
    }

    // macOS destination pre-flight (before the marker): the GUI-supplied `.app`
    // swap target is a hint, never a trust anchor — the bridge anchors it to a
    // genuine `com.hole.app` bundle and a swap-capable volume. A bad target or an
    // unswappable volume is a 400 (caller precondition on the destination,
    // distinct from a payload-bytes failure), so it precedes the payload stage.
    // Windows skips it (the SCM install dir is canonical).
    #[cfg(target_os = "macos")]
    let app_dest = match crate::cutover::apply::preflight_app_dest(req.app_dest.as_deref().map(std::path::Path::new)) {
        Ok(dest) => Some(dest),
        Err(e) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    message: format!("invalid update destination: {e}"),
                }),
            ));
        }
    };
    #[cfg(not(target_os = "macos"))]
    let app_dest: Option<std::path::PathBuf> = None;

    // Marker FIRST — the atomic single-occupancy CLAIM, BEFORE resolving or
    // touching the shared private staging dir. `write_new` is `create-new`: two
    // concurrent requests cannot both win (the 409 read-check above is only a
    // fast-path; this is the race-free guard), so ONLY the marker-winner ever
    // stages a payload. A loser 409s here and never touches the shared staging
    // dir — otherwise its `stage_payload` (which clears+rewrites the fixed dir)
    // could clobber the winner's already-verified copy mid-extract, reopening the
    // verify/use TOCTOU via a privileged write on the loser's behalf.
    let marker = hole_common::update_marker::MarkerInfo {
        version: hole_common::update_marker::MARKER_VERSION,
        from_version: state.version.clone(),
        to_version: req.target_version.clone(),
        pid: std::process::id(),
        started_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    if let Err(e) = hole_common::update_marker::write_new(log_dir, &marker) {
        let (code, message) = if e.kind() == std::io::ErrorKind::AlreadyExists {
            (StatusCode::CONFLICT, "a cutover is already in progress".to_string())
        } else {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("cutover marker write failed: {e}"),
            )
        };
        return Err((code, Json(ErrorResponse { message })));
    }

    // Stage the caller-supplied payload into a bridge-private, non-attacker-
    // writable directory, then verify and extract ONLY that copy — never
    // `req.payload_path` again. This closes the verify/extract TOCTOU: a
    // hole-group member can pass a genuinely-signed payload (verify passes) and
    // overwrite the file before extract opens it; copying first makes the verified
    // bytes the extracted bytes. The marker claimed above guarantees a single
    // occupant, so the fixed staging path is never raced. The copy and the marker
    // are cleared on every exit path below.
    let private_dir = match crate::cutover::extract::private_payload_dir(&state.state_dir) {
        Ok(d) => d,
        Err(e) => {
            let _ = hole_common::update_marker::clear(log_dir);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: format!("could not resolve private payload dir: {e}"),
                }),
            ));
        }
    };

    // Stage + re-verify on a blocking thread (filesystem copy + minisign/SHA-256),
    // off the async worker. The GUI is untrusted in the bridge's model, so a
    // verify failure is a corruption/tamper event the user must see distinctly
    // (422), while a staging I/O failure is a server fault (500).
    let source = std::path::PathBuf::from(&req.payload_path);
    let stage_dir = private_dir.clone();
    let asset_name = req.asset_name.clone();
    let sha256sums = req.sha256sums.clone();
    let sha256sums_minisig = req.sha256sums_minisig.clone();
    let staged_copy = tokio::task::spawn_blocking(move || {
        let copy = crate::cutover::extract::stage_payload(&source, &stage_dir).map_err(StageError::Io)?;
        crate::cutover::extract::reverify(&copy, &asset_name, &sha256sums, &sha256sums_minisig)
            .map_err(StageError::Verify)?;
        Ok::<_, StageError>(copy)
    })
    .await;
    let payload = match staged_copy {
        Ok(Ok(copy)) => copy,
        Ok(Err(StageError::Verify(e))) => {
            let _ = hole_common::update_marker::clear(log_dir);
            let _ = std::fs::remove_dir_all(&private_dir);
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(ErrorResponse {
                    message: format!("payload verification failed: {e}"),
                }),
            ));
        }
        Ok(Err(StageError::Io(e))) => {
            let _ = hole_common::update_marker::clear(log_dir);
            let _ = std::fs::remove_dir_all(&private_dir);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: format!("payload staging failed: {e}"),
                }),
            ));
        }
        Err(e) => {
            let _ = hole_common::update_marker::clear(log_dir);
            let _ = std::fs::remove_dir_all(&private_dir);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: format!("payload staging task panicked: {e}"),
                }),
            ));
        }
    };

    // Extract the bare binaries from the PRIVATE copy onto the destination volume.
    // The extract shells out to a blocking `msiexec`/`hdiutil`, so run it on a
    // blocking thread to keep it off the async worker. A failure clears the marker
    // so the GUI does not mask Disconnected forever.
    let state_dir = state.state_dir.clone();
    let extracted = tokio::task::spawn_blocking(move || crate::cutover::extract::extract(&payload, &state_dir)).await;
    let staged = match extracted {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            let _ = hole_common::update_marker::clear(log_dir);
            let _ = std::fs::remove_dir_all(&private_dir);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: format!("update extraction failed: {e}"),
                }),
            ));
        }
        Err(e) => {
            let _ = hole_common::update_marker::clear(log_dir);
            let _ = std::fs::remove_dir_all(&private_dir);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: format!("update extraction task panicked: {e}"),
                }),
            ));
        }
    };

    // Kick off the actor and return 200 BEFORE any self-restart. Windows spawns
    // a detached child (returns naturally); macOS runs the actor on a detached
    // task that SIGTERMs THIS process only after this 200 is on the wire.
    if let Err(e) = crate::cutover::apply::spawn_actor(staged, &req.target_version, app_dest.as_deref(), log_dir) {
        let _ = hole_common::update_marker::clear(log_dir);
        let _ = std::fs::remove_dir_all(&private_dir);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                message: format!("cutover failed to start: {e}"),
            }),
        ));
    }

    // Best-effort: the extracted images now live on the destination volume, so the
    // private copy has served its purpose. The next cutover's `stage_payload` also
    // clears any leftover, so a failure here is harmless.
    let _ = std::fs::remove_dir_all(&private_dir);

    info!(target_version = %req.target_version, "update cutover kicked off");
    Ok(Json(EmptyResponse {}))
}

/// Distinguishes a payload verify failure (422 — corruption/tamper) from a
/// staging I/O failure (500 — server fault) so the handler maps each to its own
/// HTTP status after the combined stage+verify blocking step.
enum StageError {
    Io(std::io::Error),
    Verify(hole_common::verify::VerifyError),
}

async fn handle_stop<P: Proxy + 'static, R: Routing + 'static>(
    State(state): State<Arc<IpcState<P, R>>>,
) -> Result<Json<EmptyResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut pm = state.proxy.lock().await;
    match pm.stop().await {
        Ok(()) => Ok(Json(EmptyResponse {})),
        Err(e) => {
            error!(error = %e, "proxy stop failed");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { message: e.to_string() }),
            ))
        }
    }
}

async fn handle_reload<P: Proxy + 'static, R: Routing + 'static>(
    State(state): State<Arc<IpcState<P, R>>>,
    Json(config): Json<ProxyConfig>,
) -> Result<Json<EmptyResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut pm = state.proxy.lock().await;
    match pm.reload(&config).await {
        Ok(()) => Ok(Json(EmptyResponse {})),
        Err(e) => {
            error!(error = %e, "proxy reload failed");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { message: e.to_string() }),
            ))
        }
    }
}

// New handlers ========================================================================================================

async fn handle_metrics<P: Proxy + 'static, R: Routing + 'static>(
    State(state): State<Arc<IpcState<P, R>>>,
) -> Json<MetricsResponse> {
    let mut pm = state.proxy.lock().await;
    pm.check_health();
    let filter = if pm.state() == ProxyState::Running {
        Some(hole_common::protocol::FilterMetrics::default())
    } else {
        None
    };
    // Stopped or crashed (check_health cleared `running`) → None → all
    // four traffic fields zero.
    let traffic = pm.sample_traffic().unwrap_or_default();
    Json(MetricsResponse {
        bytes_in: traffic.totals.bytes_in,
        bytes_out: traffic.totals.bytes_out,
        speed_in_bps: traffic.speed_in_bps,
        speed_out_bps: traffic.speed_out_bps,
        uptime_secs: pm.uptime_secs(),
        filter,
    })
}

async fn handle_diagnostics<P: Proxy + 'static, R: Routing + 'static>(
    State(state): State<Arc<IpcState<P, R>>>,
) -> Json<DiagnosticsResponse> {
    let pm = state.proxy.lock().await;

    // App is "ok" by convention: the bridge cannot directly observe the GUI
    // process, but if it weren't running we wouldn't have received this
    // request either. The GUI's fallback path (map_diagnostics_response) is
    // the only place this can be non-ok, and it sets it when the IPC call
    // itself fails.
    let app = "ok".to_string();

    // Bridge is "error" when ProxyManager has a recorded last_error from a
    // failed start/reload/stop, and "ok" otherwise. The IPC server itself is
    // alive (we got here), but the *bridge work* may have failed silently
    // before; reporting "ok" unconditionally would mask a bridge-work
    // failure the live IPC server cannot otherwise reveal.
    let bridge = if pm.last_error().is_some() {
        "error".to_string()
    } else {
        "ok".to_string()
    };

    // Network: does the host have a default gateway? Best-effort local
    // check; does not actually probe the gateway. Routes through
    // `ProxyManager::default_gateway` (delegating to `Routing`) so tests
    // hit `MockRouting`'s stub rather than the host OS.
    let network = match pm.default_gateway() {
        Ok(_) => "ok".to_string(),
        Err(_) => "error".to_string(),
    };

    // vpn_server and internet are computed by the GUI from the selected
    // ServerEntry's persisted validation state (see ui/diagnostics.ts). The
    // wire fields are kept for backward compat but always "unknown" here.
    let vpn_server = "unknown".to_string();
    let internet = "unknown".to_string();

    Json(DiagnosticsResponse {
        app,
        bridge,
        network,
        vpn_server,
        internet,
    })
}

async fn handle_test_server<P: Proxy + 'static, R: Routing + 'static>(
    State(_state): State<Arc<IpcState<P, R>>>,
    Json(req): Json<TestServerRequest>,
) -> Json<TestServerResponse> {
    let cfg = TestConfig::production();
    let outcome = run_server_test(&req.entry, &cfg).await;
    Json(TestServerResponse { outcome })
}

async fn handle_version<P: Proxy + 'static, R: Routing + 'static>(
    State(state): State<Arc<IpcState<P, R>>>,
) -> Json<VersionResponse> {
    Json(VersionResponse {
        version: state.version.clone(),
    })
}

// Security ============================================================================================================

/// Base SDDL for socket access control: SYSTEM + Administrators only.
/// Used as the restrictive initial DACL (with `P` flag) in `socket.rs`,
/// and as the base for the final DACL (with `hole` group appended) here.
#[cfg(target_os = "windows")]
pub(crate) const SDDL_BASE: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)";

/// Apply a DACL defined by an SDDL string to a filesystem object.
///
/// When `protect` is true, the DACL is set as protected, blocking inherited
/// ACEs from the parent directory. This is used for the initial restrictive
/// DACL in `socket.rs` (SYSTEM + Administrators only, before `listen()`).
///
/// When `protect` is false, inherited ACEs are preserved. This is used for
/// the final DACL in `apply_socket_permissions` (adding the `hole` group).
#[cfg(target_os = "windows")]
pub fn set_dacl_from_sddl(path: &Path, sddl: &str, protect: bool) -> std::io::Result<()> {
    use windows::core::HSTRING;
    use windows::Win32::Foundation::LocalFree;
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        GetSecurityDescriptorDacl, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, UNPROTECTED_DACL_SECURITY_INFORMATION,
    };

    let sddl_wide = HSTRING::from(sddl);
    let path_wide = HSTRING::from(path.as_os_str());

    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `sddl_wide` is a valid HSTRING kept alive for the call.
    // `sd` is an out-parameter that Windows allocates via LocalAlloc on success;
    // we free it with LocalFree at the end of this function on all paths.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &sddl_wide, 1, // SDDL_REVISION_1
            &mut sd, None,
        )
    }
    .map_err(|e| std::io::Error::other(format!("failed to parse SDDL: {e}")))?;

    let mut dacl_present = false.into();
    let mut dacl = std::ptr::null_mut();
    let mut dacl_defaulted = false.into();
    // SAFETY: `sd` was successfully returned by ConvertStringSecurityDescriptorToSecurityDescriptorW
    // and has not been freed. The out-parameters are stack locals with correct types.
    // `dacl` points into `sd`'s memory and remains valid until `sd` is freed.
    let result = unsafe { GetSecurityDescriptorDacl(sd, &mut dacl_present, &mut dacl, &mut dacl_defaulted) };

    if let Err(e) = result {
        // SAFETY: `sd.0` was allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW
        // via LocalAlloc. Transmute converts the opaque PSECURITY_DESCRIPTOR pointer to
        // HLOCAL, which is the same pointer type — no bits change.
        unsafe {
            let _ = LocalFree(Some(std::mem::transmute::<
                *mut std::ffi::c_void,
                windows::Win32::Foundation::HLOCAL,
            >(sd.0)));
        }
        return Err(std::io::Error::other(format!("failed to extract DACL: {e}")));
    }

    if !bool::from(dacl_present) {
        // SAFETY: same LocalFree pattern as above.
        unsafe {
            let _ = LocalFree(Some(std::mem::transmute::<
                *mut std::ffi::c_void,
                windows::Win32::Foundation::HLOCAL,
            >(sd.0)));
        }
        return Err(std::io::Error::other("SDDL security descriptor has no DACL"));
    }

    // When protect is true, block inherited ACEs from the parent directory.
    // When false, explicitly re-enable inheritance (needed to undo a prior
    // protected DACL set during socket creation).
    let security_info = DACL_SECURITY_INFORMATION
        | if protect {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        };

    // SAFETY: `path_wide` is alive for the call. `dacl` points into the still-live
    // `sd` allocation. Owner/group pointers are correctly None.
    let result = unsafe {
        SetNamedSecurityInfoW(
            &path_wide,
            SE_FILE_OBJECT,
            security_info,
            None,
            None,
            Some(dacl.cast()),
            None,
        )
    };

    // SAFETY: same as the early-return LocalFree above — `sd.0` was allocated by
    // Windows via LocalAlloc and is freed exactly once here.
    unsafe {
        let _ = LocalFree(Some(std::mem::transmute::<
            *mut std::ffi::c_void,
            windows::Win32::Foundation::HLOCAL,
        >(sd.0)));
    }

    result
        .ok()
        .map_err(|e| std::io::Error::other(format!("failed to set ACL: {e}")))
}

/// Apply OS-level access control to the socket file.
///
/// This is the second phase of socket permission setup. The first phase
/// (in `socket.rs`) applies a restrictive DACL/umask during socket creation
/// to prevent a TOCTOU race. This function then sets the final permissions,
/// adding the `hole` group on both platforms.
///
/// On Windows: sets a DACL restricting access to SYSTEM, Administrators, and the `hole` group.
/// If an `installer-user-sid` file exists (written by `install_bridge` in `setup.rs`),
/// the SID it contains is also added to the DACL, then the file is deleted. This is a
/// workaround for the Windows token snapshot limitation: process tokens are immutable
/// snapshots of group memberships captured at logon time, so a newly-added group
/// membership is not reflected in any running process's token until the user logs out
/// and back in. Adding the user's own SID directly to the DACL provides immediate
/// access without requiring re-login. The per-user SID is cleaned up on the next
/// bridge restart (when the group membership will have taken effect after re-login).
///
/// On macOS: sets ownership to root:hole with mode 0660.
#[cfg(all(target_os = "windows", not(test)))]
fn apply_socket_permissions(path: &Path) {
    let mut extra_sids = Vec::new();
    let sid_file = installer_user_sid_path();
    if let Ok(sid) = std::fs::read_to_string(&sid_file) {
        let sid = sid.trim().to_string();
        if !sid.is_empty() {
            info!(sid = %sid, "including installer user SID in socket DACL");
            extra_sids.push(sid);
        }
        // Delete the file after reading — the per-user SID is a temporary bridge
        // that is no longer needed after the bridge restarts (group membership
        // will be in the token after re-login).
        let _ = std::fs::remove_file(&sid_file);
    }
    let extra_refs: Vec<&str> = extra_sids.iter().map(|s| s.as_str()).collect();
    let sddl = build_sddl(&extra_refs);
    if let Err(e) = set_dacl_from_sddl(path, &sddl, false) {
        warn!("failed to set socket permissions: {e}");
    }
}

/// Path to the file where the installing user's SID is stored temporarily.
///
/// Written by [`prepare_ipc_access`], read and deleted by
/// `apply_socket_permissions()` on bridge startup.
#[cfg(target_os = "windows")]
pub fn installer_user_sid_path() -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into()))
        .join("hole")
        .join("installer-user-sid")
}

/// Set up IPC access control so that the current interactive user can
/// talk to the bridge once it's running. Idempotent.
///
/// Specifically: creates the `hole` group if missing, adds the current
/// interactive user to it, and on Windows writes that user's SID to the
/// `installer-user-sid` file so the next `apply_socket_permissions` call
/// includes it in the socket DACL (working around the Windows token-snapshot
/// limitation).
///
/// Used by both `install_bridge` (where it's called once before service
/// registration) and by `bridge grant-access` (where it's called by the
/// dev workflow before starting the foreground bridge).
///
/// # Testing
///
/// This function is not covered by a unit test. Its idempotence is a
/// property of the primitives it composes: `group::create_group` is
/// idempotent (macOS: verifies post-failure with `getgrnam(3)`;
/// Windows: detects error code 1379) and `group::add_user_to_group`
/// is idempotent (macOS: `dseditgroup -o edit -a` is naturally
/// idempotent; Windows: detects error code 1378). `std::fs::write` on
/// the SID file path unconditionally overwrites. An end-to-end test
/// would require elevation (to actually call `dseditgroup` /
/// `net localgroup`), so we don't add one — elevation is a runtime
/// dependency, not a test-harness dependency. Integration coverage is
/// provided by the install-service Verification step.
pub fn prepare_ipc_access() -> std::io::Result<()> {
    crate::group::create_group()?;
    let user = crate::group::installing_username()?;
    crate::group::add_user_to_group(&user)?;
    info!(user = %user, group = %crate::group::GROUP_NAME, "prepared IPC access");

    #[cfg(target_os = "windows")]
    {
        let sid = crate::group::lookup_sid(&user)?;
        let sid_path = installer_user_sid_path();
        if let Some(parent) = sid_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&sid_path, &sid)?;
        info!(sid = %sid, path = %sid_path.display(), "wrote installer user SID");
    }
    Ok(())
}

/// Check that a string looks like a valid Windows SID (e.g. `S-1-5-21-...`).
///
/// Only allows the pattern `S-` followed by dash-separated decimal numbers. This prevents
/// SDDL injection via crafted strings containing `)` or other SDDL metacharacters.
#[cfg(target_os = "windows")]
pub(crate) fn is_valid_sid_string(s: &str) -> bool {
    s.starts_with("S-") && s.len() > 3 && s[2..].bytes().all(|b| b.is_ascii_digit() || b == b'-')
}

/// Build the SDDL string for the socket file DACL.
///
/// Always includes SYSTEM + Administrators + the `hole` group (if it exists).
/// Additional per-user SIDs can be appended via `extra_sids` — this is used
/// as a temporary workaround for the Windows token snapshot limitation (see
/// [`apply_socket_permissions`] and the doc comment on `handle_grant_access`
/// in `cli.rs`).
#[cfg(target_os = "windows")]
pub fn build_sddl(extra_sids: &[&str]) -> String {
    let base = SDDL_BASE;

    let mut sddl = match crate::group::group_sid() {
        Ok(sid) => {
            info!(sid = %sid, "restricting IPC to SYSTEM + Administrators + hole group");
            format!("{base}(A;;GA;;;{sid})")
        }
        Err(e) => {
            warn!("'hole' group not found ({e}), IPC restricted to admin-only");
            base.to_string()
        }
    };

    for sid in extra_sids {
        if is_valid_sid_string(sid) {
            sddl.push_str(&format!("(A;;GA;;;{sid})"));
        } else {
            warn!(sid = %sid, "ignoring malformed SID string in DACL");
        }
    }

    sddl
}

/// Set socket file ownership to root:hole and mode 0660 on macOS.
///
/// This is the second phase of socket permission setup. The first phase
/// (umask guard in `socket.rs`) creates the socket with mode 0600. This
/// function then sets ownership to root:hole and widens the mode to 0660.
#[cfg(all(target_os = "macos", not(test)))]
fn apply_socket_permissions(path: &Path) {
    use std::ffi::CString;

    let path_str = match path.to_str() {
        Some(s) => s,
        None => {
            warn!("socket path is not valid UTF-8");
            return;
        }
    };

    let c_path = match CString::new(path_str) {
        Ok(p) => p,
        Err(e) => {
            warn!("invalid socket path for permissions: {e}");
            return;
        }
    };

    // Compile-time check: GROUP_NAME must not contain interior null bytes.
    const _: () = {
        let bytes = crate::group::GROUP_NAME.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            assert!(bytes[i] != 0, "GROUP_NAME must not contain null bytes");
            i += 1;
        }
    };

    // Look up the 'hole' group GID
    let group_name = CString::new(crate::group::GROUP_NAME).expect("GROUP_NAME verified at compile time");
    // SAFETY: `group_name` is a valid null-terminated CString kept alive for the
    // call. getgrnam returns a pointer into a libc-owned process-wide static
    // buffer; per POSIX it is not thread-safe (see also `group::os::group_exists`).
    // We read `gr_gid` below before any other libc call could overwrite that
    // buffer, and the bridge's apply-socket-permissions path is single-threaded
    // at this point.
    let grp = unsafe { libc::getgrnam(group_name.as_ptr()) };

    if grp.is_null() {
        warn!("'hole' group not found, restricting socket to root-only");
        // SAFETY: `c_path` is a valid null-terminated CString. chmod on a valid
        // path is always safe to call.
        unsafe {
            libc::chmod(c_path.as_ptr(), 0o600);
        }
        return;
    }

    // SAFETY: `grp` was checked non-null above and points to valid static storage
    // from getgrnam. We read `gr_gid` immediately before any call that could
    // invalidate the static buffer.
    let gid = unsafe { (*grp).gr_gid };
    info!(gid = gid, "setting socket ownership to root:hole, mode 0660");

    // SAFETY: `c_path` is a valid null-terminated CString for the path argument.
    // `gid` is a valid group ID obtained from getgrnam. chown/chmod return 0 on
    // success and -1 on failure; we check the return value.
    unsafe {
        if libc::chown(c_path.as_ptr(), 0, gid) != 0 {
            warn!("chown failed, falling back to root-only socket");
            libc::chmod(c_path.as_ptr(), 0o600);
            return;
        }
        if libc::chmod(c_path.as_ptr(), 0o660) != 0 {
            warn!("chmod failed, socket may have incorrect permissions");
        }
    }
}

#[cfg(test)]
#[path = "ipc_tests.rs"]
mod ipc_tests;
