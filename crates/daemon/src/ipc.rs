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
    /// Removes any stale socket file, creates parent directories, binds,
    /// and applies OS-level access control to the socket file.
    pub fn bind<B: ProxyBackend + 'static>(path: &Path, proxy: Arc<Mutex<ProxyManager<B>>>) -> std::io::Result<Self> {
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
            let resp = router.oneshot(req.map(axum::body::Body::new)).await.unwrap();
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

/// Apply OS-level access control to the socket file.
///
/// On Windows: sets a DACL restricting access to SYSTEM, Administrators, and the `hole` group.
/// On macOS: sets ownership to root:hole with mode 0660.
#[cfg(all(target_os = "windows", not(test)))]
fn apply_socket_permissions(path: &Path) {
    use windows::core::HSTRING;
    use windows::Win32::Foundation::LocalFree;
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{GetSecurityDescriptorDacl, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};

    let sddl = build_sddl();
    let sddl_wide = HSTRING::from(&sddl);
    let path_wide = HSTRING::from(path.as_os_str());

    let mut sd = PSECURITY_DESCRIPTOR::default();
    let result = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &sddl_wide, 1, // SDDL_REVISION_1
            &mut sd, None,
        )
    };

    if let Err(e) = result {
        warn!("failed to parse SDDL for socket permissions: {e}");
        return;
    }

    // Extract DACL from the security descriptor
    let mut dacl_present = false.into();
    let mut dacl = std::ptr::null_mut();
    let mut dacl_defaulted = false.into();
    let result = unsafe { GetSecurityDescriptorDacl(sd, &mut dacl_present, &mut dacl, &mut dacl_defaulted) };

    if let Err(e) = result {
        warn!("failed to extract DACL from security descriptor: {e}");
        unsafe {
            let _ = LocalFree(Some(std::mem::transmute::<
                *mut std::ffi::c_void,
                windows::Win32::Foundation::HLOCAL,
            >(sd.0)));
        }
        return;
    }

    // Apply DACL to the socket file
    let err = unsafe {
        SetNamedSecurityInfoW(
            &path_wide,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl.cast()),
            None,
        )
    };

    if err.is_err() {
        warn!("failed to set socket file ACL: {err:?}");
    }

    unsafe {
        let _ = LocalFree(Some(std::mem::transmute::<
            *mut std::ffi::c_void,
            windows::Win32::Foundation::HLOCAL,
        >(sd.0)));
    }
}

/// Build the SDDL string for the socket file DACL.
#[cfg(all(target_os = "windows", not(test)))]
fn build_sddl() -> String {
    // Base: SYSTEM + Administrators
    let base = "D:(A;;GA;;;SY)(A;;GA;;;BA)";

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

    // Look up the 'hole' group GID
    let group_name = CString::new(crate::group::GROUP_NAME).unwrap();
    let grp = unsafe { libc::getgrnam(group_name.as_ptr()) };

    if grp.is_null() {
        warn!("'hole' group not found, restricting socket to root-only");
        unsafe {
            libc::chmod(c_path.as_ptr(), 0o600);
        }
        return;
    }

    let gid = unsafe { (*grp).gr_gid };
    info!(gid = gid, "setting socket ownership to root:hole, mode 0660");

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
