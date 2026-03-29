// IPC server — HTTP/1.1 REST API over local Unix domain socket.

use crate::proxy_manager::{ProxyBackend, ProxyManager, ProxyState};
use crate::socket::LocalListener;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use hole_common::protocol::{
    EmptyResponse, ErrorResponse, ProxyConfig, StatusResponse, ROUTE_RELOAD, ROUTE_START, ROUTE_STATUS, ROUTE_STOP,
};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;
#[allow(unused_imports)]
use tracing::warn;
use tracing::{debug, error, info};

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

        let router = build_router(proxy);
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

fn build_router<B: ProxyBackend + 'static>(proxy: Arc<Mutex<ProxyManager<B>>>) -> axum::Router {
    axum::Router::new()
        .route(ROUTE_STATUS, axum::routing::get(handle_status::<B>))
        .route(ROUTE_START, axum::routing::post(handle_start::<B>))
        .route(ROUTE_STOP, axum::routing::post(handle_stop::<B>))
        .route(ROUTE_RELOAD, axum::routing::post(handle_reload::<B>))
        .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024))
        .with_state(proxy)
}

// Handlers ============================================================================================================

async fn handle_status<B: ProxyBackend + 'static>(
    State(proxy): State<Arc<Mutex<ProxyManager<B>>>>,
) -> Json<StatusResponse> {
    let mut pm = proxy.lock().await;
    pm.check_health();
    Json(StatusResponse {
        running: pm.state() == ProxyState::Running,
        uptime_secs: pm.uptime_secs(),
        error: pm.last_error().map(|s| s.to_string()),
    })
}

async fn handle_start<B: ProxyBackend + 'static>(
    State(proxy): State<Arc<Mutex<ProxyManager<B>>>>,
    Json(config): Json<ProxyConfig>,
) -> Result<Json<EmptyResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut pm = proxy.lock().await;
    match pm.start(&config).await {
        Ok(()) => Ok(Json(EmptyResponse {})),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { message: e.to_string() }),
        )),
    }
}

async fn handle_stop<B: ProxyBackend + 'static>(
    State(proxy): State<Arc<Mutex<ProxyManager<B>>>>,
) -> Result<Json<EmptyResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut pm = proxy.lock().await;
    match pm.stop().await {
        Ok(()) => Ok(Json(EmptyResponse {})),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { message: e.to_string() }),
        )),
    }
}

async fn handle_reload<B: ProxyBackend + 'static>(
    State(proxy): State<Arc<Mutex<ProxyManager<B>>>>,
    Json(config): Json<ProxyConfig>,
) -> Result<Json<EmptyResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut pm = proxy.lock().await;
    match pm.reload(&config).await {
        Ok(()) => Ok(Json(EmptyResponse {})),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { message: e.to_string() }),
        )),
    }
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
pub(crate) fn set_dacl_from_sddl(path: &Path, sddl: &str, protect: bool) -> std::io::Result<()> {
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
/// On macOS: sets ownership to root:hole with mode 0660.
#[cfg(all(target_os = "windows", not(test)))]
fn apply_socket_permissions(path: &Path) {
    let sddl = build_sddl();
    if let Err(e) = set_dacl_from_sddl(path, &sddl, false) {
        warn!("failed to set socket permissions: {e}");
    }
}

/// Build the SDDL string for the socket file DACL.
#[cfg(all(target_os = "windows", not(test)))]
fn build_sddl() -> String {
    let base = SDDL_BASE;

    match crate::group::group_sid() {
        Ok(sid) => {
            info!(sid = %sid, "restricting IPC to SYSTEM + Administrators + hole group");
            format!("{base}(A;;GA;;;{sid})")
        }
        Err(e) => {
            warn!("'hole' group not found ({e}), IPC restricted to admin-only");
            base.to_string()
        }
    }
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
