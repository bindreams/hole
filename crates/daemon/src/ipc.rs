// IPC server — local socket listener + request handling.

use crate::proxy_manager::{ProxyBackend, ProxyManager, ProxyState};
use hole_common::protocol::{DaemonRequest, DaemonResponse};
use interprocess::local_socket::{
    tokio::{Listener, Stream},
    traits::tokio::Listener as ListenerTrait,
    ListenerOptions,
};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

// Constants =====

const MAX_MESSAGE_SIZE: u32 = 1024 * 1024; // 1 MiB

/// Re-export: socket name (Windows) or path (macOS).
#[cfg(target_os = "windows")]
pub use hole_common::protocol::DAEMON_SOCKET_NAME as SOCKET_NAME;
#[cfg(target_os = "macos")]
pub use hole_common::protocol::DAEMON_SOCKET_PATH as SOCKET_PATH;

// Server =====

pub struct IpcServer<B: ProxyBackend> {
    listener: Listener,
    proxy: Arc<Mutex<ProxyManager<B>>>,
}

impl<B: ProxyBackend + 'static> IpcServer<B> {
    /// Bind to the IPC socket/pipe.
    ///
    /// On macOS: filesystem Unix domain socket at `path`.
    /// On Windows: namespaced named pipe with `name`.
    #[cfg(target_os = "windows")]
    pub fn bind(name: &str, proxy: Arc<Mutex<ProxyManager<B>>>) -> std::io::Result<Self> {
        use interprocess::local_socket::{GenericNamespaced, ToNsName};

        let ns_name = name
            .to_ns_name::<GenericNamespaced>()
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        let opts = ListenerOptions::new().name(ns_name);
        #[cfg(not(test))]
        let opts = apply_security_descriptor(opts);
        let listener = opts.create_tokio()?;

        Ok(Self { listener, proxy })
    }

    /// Bind to the IPC socket.
    ///
    /// Uses a filesystem Unix domain socket. Removes stale socket file before binding.
    #[cfg(target_os = "macos")]
    pub fn bind(path: &str, proxy: Arc<Mutex<ProxyManager<B>>>) -> std::io::Result<Self> {
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

        Ok(Self { listener, proxy })
    }

    /// Accept and handle one client connection, then return.
    /// Useful for testing.
    pub async fn run_once(self) -> std::io::Result<()> {
        let stream = self.listener.accept().await?;
        handle_connection(stream, self.proxy).await;
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
                    let proxy = Arc::clone(&self.proxy);
                    tasks.spawn(async move {
                        handle_connection(stream, proxy).await;
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

// Connection handler =====

async fn handle_connection<B: ProxyBackend>(mut stream: Stream, proxy: Arc<Mutex<ProxyManager<B>>>) {
    loop {
        // Read length prefix
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                debug!("client disconnected (EOF)");
                return;
            }
            Err(e) => {
                warn!(error = %e, "error reading from client");
                return;
            }
        }

        let msg_len = u32::from_be_bytes(len_buf);
        if msg_len > MAX_MESSAGE_SIZE {
            warn!(msg_len, "message too large, dropping connection");
            let _ = send_error(&mut stream, "message too large").await;
            return;
        }

        // Read body
        let mut body = vec![0u8; msg_len as usize];
        if let Err(e) = stream.read_exact(&mut body).await {
            warn!(error = %e, "error reading message body");
            return;
        }

        // Parse request
        let response = match serde_json::from_slice::<DaemonRequest>(&body) {
            Ok(req) => {
                debug!(?req, "received request");
                dispatch(req, &proxy).await
            }
            Err(e) => {
                warn!(error = %e, "invalid request");
                DaemonResponse::Error {
                    message: format!("invalid request: {e}"),
                }
            }
        };

        // Send response
        if let Err(e) = send_response(&mut stream, &response).await {
            warn!(error = %e, "error sending response");
            return;
        }
    }
}

async fn dispatch<B: ProxyBackend>(req: DaemonRequest, proxy: &Mutex<ProxyManager<B>>) -> DaemonResponse {
    match req {
        DaemonRequest::Status => {
            let mut pm = proxy.lock().await;
            pm.check_health();
            let running = pm.state() == ProxyState::Running;
            let uptime_secs = pm.uptime_secs();
            let error = pm.last_error().map(|s| s.to_string());
            DaemonResponse::Status {
                running,
                uptime_secs,
                error,
            }
        }
        DaemonRequest::Start { config } => {
            let mut pm = proxy.lock().await;
            match pm.start(&config).await {
                Ok(()) => DaemonResponse::Ack,
                Err(e) => DaemonResponse::Error { message: e.to_string() },
            }
        }
        DaemonRequest::Stop => {
            let mut pm = proxy.lock().await;
            match pm.stop().await {
                Ok(()) => DaemonResponse::Ack,
                Err(e) => DaemonResponse::Error { message: e.to_string() },
            }
        }
        DaemonRequest::Reload { config } => {
            let mut pm = proxy.lock().await;
            match pm.reload(&config).await {
                Ok(()) => DaemonResponse::Ack,
                Err(e) => DaemonResponse::Error { message: e.to_string() },
            }
        }
    }
}

// Wire helpers =====

async fn send_response(stream: &mut Stream, resp: &DaemonResponse) -> std::io::Result<()> {
    let json = serde_json::to_vec(resp).map_err(|e| std::io::Error::other(e.to_string()))?;
    let len = (json.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(&json).await?;
    Ok(())
}

async fn send_error(stream: &mut Stream, message: &str) -> std::io::Result<()> {
    send_response(
        stream,
        &DaemonResponse::Error {
            message: message.to_string(),
        },
    )
    .await
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
