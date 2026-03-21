// IPC server — HTTP/1.1 REST API over local socket.

use crate::proxy_manager::{ProxyBackend, ProxyManager, ProxyState};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use hole_common::protocol::{
    EmptyResponse, ErrorResponse, ProxyConfig, StatusResponse, ROUTE_RELOAD, ROUTE_START, ROUTE_STATUS, ROUTE_STOP,
};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use interprocess::local_socket::{tokio::Listener, traits::tokio::Listener as ListenerTrait, ListenerOptions};
use std::convert::Infallible;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;
#[cfg(not(test))]
use tracing::warn;
use tracing::{debug, error, info};

// Constants =====

/// Re-export: socket name (Windows) or path (macOS).
#[cfg(target_os = "windows")]
pub use hole_common::protocol::DAEMON_SOCKET_NAME as SOCKET_NAME;
#[cfg(target_os = "macos")]
pub use hole_common::protocol::DAEMON_SOCKET_PATH as SOCKET_PATH;

// Server =====

pub struct IpcServer {
    listener: Listener,
    router: axum::Router,
}

impl IpcServer {
    /// Bind to the IPC named pipe (Windows).
    #[cfg(target_os = "windows")]
    pub fn bind<B: ProxyBackend + 'static>(name: &str, proxy: Arc<Mutex<ProxyManager<B>>>) -> std::io::Result<Self> {
        use interprocess::local_socket::{GenericNamespaced, ToNsName};

        let ns_name = name
            .to_ns_name::<GenericNamespaced>()
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        let opts = ListenerOptions::new().name(ns_name);
        #[cfg(not(test))]
        let opts = apply_security_descriptor(opts);
        let listener = opts.create_tokio()?;

        let router = build_router(proxy);
        Ok(Self { listener, router })
    }

    /// Bind to the IPC Unix domain socket (macOS).
    #[cfg(target_os = "macos")]
    pub fn bind<B: ProxyBackend + 'static>(path: &str, proxy: Arc<Mutex<ProxyManager<B>>>) -> std::io::Result<Self> {
        use interprocess::local_socket::{GenericFilePath, ToFsName};

        // Remove stale socket (standard practice, same as Docker)
        let _ = std::fs::remove_file(path);

        let fs_name = path
            .to_fs_name::<GenericFilePath>()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let listener = ListenerOptions::new().name(fs_name).create_tokio()?;

        // Set socket ownership and permissions post-bind
        #[cfg(not(test))]
        apply_socket_permissions(path);

        let router = build_router(proxy);
        Ok(Self { listener, router })
    }

    /// Accept and handle one client connection, then return.
    /// Useful for testing.
    pub async fn run_once(self) -> std::io::Result<()> {
        let stream = self.listener.accept().await?;
        let io = TokioIo::new(stream);
        let router = self.router;
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
            .map_err(|e| std::io::Error::other(e.to_string()))?;
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
                        let io = TokioIo::new(stream);
                        let service = hyper::service::service_fn(move |req: http::Request<Incoming>| {
                            let router = router.clone();
                            async move {
                                let resp = router.oneshot(req.map(axum::body::Body::new)).await.unwrap();
                                Ok::<_, Infallible>(resp)
                            }
                        });
                        if let Err(e) = hyper::server::conn::http1::Builder::new()
                            .serve_connection(io, service)
                            .await
                        {
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

// Router =====

fn build_router<B: ProxyBackend + 'static>(proxy: Arc<Mutex<ProxyManager<B>>>) -> axum::Router {
    axum::Router::new()
        .route(ROUTE_STATUS, axum::routing::get(handle_status::<B>))
        .route(ROUTE_START, axum::routing::post(handle_start::<B>))
        .route(ROUTE_STOP, axum::routing::post(handle_stop::<B>))
        .route(ROUTE_RELOAD, axum::routing::post(handle_reload::<B>))
        .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024))
        .with_state(proxy)
}

// Handlers =====

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

// Security =====

/// Apply a Windows DACL to the named pipe, restricting access to SYSTEM,
/// Administrators, and the `hole` group.
#[cfg(all(target_os = "windows", not(test)))]
fn apply_security_descriptor(opts: ListenerOptions<'_>) -> ListenerOptions<'_> {
    use interprocess::os::windows::local_socket::ListenerOptionsExt;

    let sddl = build_sddl();
    match security_descriptor_from_sddl(&sddl) {
        Ok(sd) => opts.security_descriptor(sd),
        Err(e) => {
            warn!("failed to set pipe security descriptor: {e}");
            opts
        }
    }
}

/// Build the SDDL string for the named pipe DACL.
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

/// Parse an SDDL string into a SecurityDescriptor.
#[cfg(all(target_os = "windows", not(test)))]
fn security_descriptor_from_sddl(
    sddl: &str,
) -> std::io::Result<interprocess::os::windows::security_descriptor::SecurityDescriptor> {
    use interprocess::os::windows::security_descriptor::SecurityDescriptor;
    use widestring::U16CString;

    let wide = U16CString::from_str(sddl).map_err(|e| std::io::Error::other(format!("invalid SDDL string: {e}")))?;
    SecurityDescriptor::deserialize(&wide)
        .map_err(|e| std::io::Error::other(format!("failed to deserialize SDDL: {e}")))
}

/// Set socket file ownership to root:hole and mode 0660 on macOS.
#[cfg(all(target_os = "macos", not(test)))]
fn apply_socket_permissions(path: &str) {
    use std::ffi::CString;

    let c_path = match CString::new(path) {
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
