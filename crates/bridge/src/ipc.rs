// IPC server — HTTP/1.1 REST API over local Unix domain socket.

use crate::proxy::ProxyError;
use crate::proxy_manager::{ProxyBackend, ProxyManager, ProxyState};
use crate::server_test::{run_server_test, TestConfig};
use crate::socket::LocalListener;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use hole_common::protocol::{
    DiagnosticsResponse, EmptyResponse, ErrorResponse, MetricsResponse, ProxyConfig, PublicIpResponse, StatusResponse,
    TestServerRequest, TestServerResponse, CANCELLED_MESSAGE, ROUTE_CANCEL, ROUTE_DIAGNOSTICS, ROUTE_METRICS,
    ROUTE_PUBLIC_IP, ROUTE_RELOAD, ROUTE_START, ROUTE_STATUS, ROUTE_STOP, ROUTE_TEST_SERVER,
};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
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

/// Shared state for IPC handlers, holding the proxy manager, IP cache, and
/// the start-cancellation handoff struct.
pub struct IpcState<B: ProxyBackend> {
    pub proxy: Arc<Mutex<ProxyManager<B>>>,
    pub ip_cache: Arc<tokio::sync::Mutex<Option<(PublicIpResponse, Instant)>>>,
    // std::sync::Mutex — never held across .await. See StartCancelState docs.
    pub start_cancel: Arc<std::sync::Mutex<StartCancelState>>,
}

/// IP cache time-to-live.
const IP_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(60);

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
    pub fn bind<B: ProxyBackend + 'static>(path: &Path, proxy: Arc<Mutex<ProxyManager<B>>>) -> std::io::Result<Self> {
        #[cfg(not(test))]
        let listener = LocalListener::bind_restricted(path)?;
        #[cfg(test)]
        let listener = LocalListener::bind(path)?;

        #[cfg(not(test))]
        apply_socket_permissions(path);

        let state = Arc::new(IpcState {
            proxy,
            ip_cache: Arc::new(tokio::sync::Mutex::new(None)),
            start_cancel: Arc::new(std::sync::Mutex::new(StartCancelState::default())),
        });
        let router = build_router(state);
        Ok(Self {
            listener,
            router,
            socket_path: path.to_owned(),
        })
    }

    /// Accept and handle one client connection, then return.
    /// Useful for testing.
    pub async fn run_once(self) -> std::io::Result<()> {
        let stream = self.listener.accept().await?;
        // Connection errors (client disconnect, shutdown) are non-fatal.
        let _ = serve_connection(TokioIo::new(stream), self.router.clone()).await;
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

fn build_router<B: ProxyBackend + 'static>(state: Arc<IpcState<B>>) -> axum::Router {
    axum::Router::new()
        .route(ROUTE_STATUS, axum::routing::get(handle_status::<B>))
        .route(ROUTE_START, axum::routing::post(handle_start::<B>))
        .route(ROUTE_STOP, axum::routing::post(handle_stop::<B>))
        .route(ROUTE_CANCEL, axum::routing::post(handle_cancel::<B>))
        .route(ROUTE_RELOAD, axum::routing::post(handle_reload::<B>))
        .route(ROUTE_METRICS, axum::routing::get(handle_metrics::<B>))
        .route(ROUTE_DIAGNOSTICS, axum::routing::get(handle_diagnostics::<B>))
        .route(ROUTE_PUBLIC_IP, axum::routing::get(handle_public_ip::<B>))
        .route(ROUTE_TEST_SERVER, axum::routing::post(handle_test_server::<B>))
        .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024))
        .with_state(state)
}

// Handlers ============================================================================================================

async fn handle_status<B: ProxyBackend + 'static>(State(state): State<Arc<IpcState<B>>>) -> Json<StatusResponse> {
    let mut pm = state.proxy.lock().await;
    pm.check_health();
    Json(StatusResponse {
        running: pm.state() == ProxyState::Running,
        uptime_secs: pm.uptime_secs(),
        error: pm.last_error().map(|s| s.to_string()),
    })
}

async fn handle_start<B: ProxyBackend + 'static>(
    State(state): State<Arc<IpcState<B>>>,
    Json(config): Json<ProxyConfig>,
) -> Result<Json<EmptyResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Register the cancellation token BEFORE taking the proxy mutex. If a
    // pre-armed cancel is already queued, consume it and return immediately
    // without even attempting the start. If a concurrent start is already
    // in flight, reject this one — the slot is single-occupancy because a
    // Cancel targets exactly one in-flight start.
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
async fn handle_cancel<B: ProxyBackend + 'static>(State(state): State<Arc<IpcState<B>>>) -> Json<EmptyResponse> {
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

async fn handle_stop<B: ProxyBackend + 'static>(
    State(state): State<Arc<IpcState<B>>>,
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

async fn handle_reload<B: ProxyBackend + 'static>(
    State(state): State<Arc<IpcState<B>>>,
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

async fn handle_metrics<B: ProxyBackend + 'static>(State(state): State<Arc<IpcState<B>>>) -> Json<MetricsResponse> {
    let mut pm = state.proxy.lock().await;
    pm.check_health();
    Json(MetricsResponse {
        bytes_in: 0,
        bytes_out: 0,
        speed_in_bps: 0,
        speed_out_bps: 0,
        uptime_secs: pm.uptime_secs(),
    })
}

async fn handle_diagnostics<B: ProxyBackend + 'static>(
    State(state): State<Arc<IpcState<B>>>,
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
    // before; reporting "ok" unconditionally would mask exactly the kind of
    // bug class that motivated this change. See issue #142.
    let bridge = if pm.last_error().is_some() {
        "error".to_string()
    } else {
        "ok".to_string()
    };

    // Network: does the host have a default gateway? Best-effort local
    // check; does not actually probe the gateway.
    let network = match pm.backend().default_gateway() {
        Ok(_) => "ok".to_string(),
        Err(_) => "error".to_string(),
    };

    // vpn_server and internet are computed by the GUI from the selected
    // ServerEntry's persisted validation state (see ui/sidebar.ts). The
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

async fn handle_test_server<B: ProxyBackend + 'static>(
    State(_state): State<Arc<IpcState<B>>>,
    Json(req): Json<TestServerRequest>,
) -> Json<TestServerResponse> {
    let cfg = TestConfig::production();
    let outcome = run_server_test(&req.entry, &cfg).await;
    Json(TestServerResponse { outcome })
}

async fn handle_public_ip<B: ProxyBackend + 'static>(
    State(state): State<Arc<IpcState<B>>>,
) -> Result<Json<PublicIpResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Check cache first.
    {
        let cache = state.ip_cache.lock().await;
        if let Some((ref cached, instant)) = *cache {
            if instant.elapsed() < IP_CACHE_TTL {
                return Ok(Json(cached.clone()));
            }
        }
    }

    // Cache miss or expired — fetch from external service.
    // ureq is blocking, so run in a blocking thread.
    let result = tokio::task::spawn_blocking(|| -> Result<PublicIpResponse, String> {
        let agent = ureq::Agent::new_with_defaults();
        let body: serde_json::Value = agent
            .get("https://ipinfo.io/json")
            .call()
            .map_err(|e| format!("IP lookup failed: {e}"))?
            .body_mut()
            .read_json()
            .map_err(|e| format!("parse error: {e}"))?;

        let ip = body["ip"]
            .as_str()
            .ok_or_else(|| "missing 'ip' field".to_string())?
            .to_string();
        let country_code = body["country"]
            .as_str()
            .ok_or_else(|| "missing 'country' field".to_string())?
            .to_string();

        Ok(PublicIpResponse { ip, country_code })
    })
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                message: format!("task join error: {e}"),
            }),
        )
    })?
    .map_err(|e| (StatusCode::BAD_GATEWAY, Json(ErrorResponse { message: e })))?;

    // Update cache.
    {
        let mut cache = state.ip_cache.lock().await;
        *cache = Some((result.clone(), Instant::now()));
    }

    Ok(Json(result))
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
/// property of the primitives it composes: `group::create_group` and
/// `group::add_user_to_group` are documented as idempotent on
/// "already exists" errors (see their implementations in `group.rs`),
/// and `std::fs::write` on the SID file path unconditionally overwrites.
/// An end-to-end test would require elevation (to actually call
/// `dseditgroup` / `net localgroup`), so we don't add one — elevation is
/// a runtime dependency, not a test-harness dependency. Integration
/// coverage is provided by the install-service Verification step.
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
    // call. getgrnam returns a pointer to static (thread-local) storage which we
    // read immediately and do not cache.
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
