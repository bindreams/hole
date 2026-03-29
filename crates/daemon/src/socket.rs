//! Platform-agnostic AF_UNIX listener and stream for local IPC.
//!
//! On macOS: wraps `tokio::net::UnixListener` / `UnixStream` directly.
//! On Windows: uses `socket2` to create AF_UNIX sockets, with `spawn_blocking`
//! for accept (IOCP-based async I/O works on any Winsock handle).

use std::io;
use std::path::Path;

// macOS ===============================================================================================================

#[cfg(target_os = "macos")]
mod imp {
    use std::io;
    use std::path::Path;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    pub struct LocalListener {
        inner: tokio::net::UnixListener,
    }

    pub struct LocalStream {
        inner: tokio::net::UnixStream,
    }

    /// RAII guard that sets a restrictive umask and restores the original on drop.
    /// Panic-safe: the original umask is restored even if the guarded code panics.
    ///
    /// # Thread safety
    /// `umask()` is process-wide (POSIX). While the guard is active, any other
    /// thread creating files will inherit the restrictive mask. This is acceptable
    /// because `bind()` is called once during daemon startup before the async
    /// server loop starts, and the window is limited to a single `bind()` syscall.
    struct UmaskGuard(libc::mode_t);

    impl UmaskGuard {
        fn set(mask: libc::mode_t) -> Self {
            // SAFETY: umask is a simple process-wide bitmask with no failure mode.
            Self(unsafe { libc::umask(mask) })
        }
    }

    impl Drop for UmaskGuard {
        fn drop(&mut self) {
            // SAFETY: restoring the previously saved umask value.
            unsafe { libc::umask(self.0); }
        }
    }

    impl LocalListener {
        pub fn bind(path: &Path) -> io::Result<Self> {
            let _ = std::fs::remove_file(path);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            // Set restrictive umask so the socket is created with mode 0600
            // (owner-only). This prevents a TOCTOU race: without the umask,
            // the socket would be world-accessible until apply_socket_permissions()
            // runs in ipc.rs. The guard restores the original umask on drop.
            let _guard = UmaskGuard::set(0o177);
            let inner = tokio::net::UnixListener::bind(path)?;
            Ok(Self { inner })
        }

        /// On macOS, identical to `bind()` — the umask guard is always applied.
        /// This method exists for cross-platform API parity with the Windows
        /// implementation, where `bind_restricted` applies a DACL between
        /// `bind()` and `listen()`.
        pub fn bind_restricted(path: &Path) -> io::Result<Self> {
            Self::bind(path)
        }

        pub async fn accept(&self) -> io::Result<LocalStream> {
            let (stream, _addr) = self.inner.accept().await?;
            Ok(LocalStream { inner: stream })
        }
    }

    impl LocalStream {
        pub async fn connect(path: &Path) -> io::Result<Self> {
            let inner = tokio::net::UnixStream::connect(path).await?;
            Ok(Self { inner })
        }
    }

    impl AsyncRead for LocalStream {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for LocalStream {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    impl Unpin for LocalStream {}
}

// Windows =============================================================================================================

#[cfg(target_os = "windows")]
mod imp {
    use socket2::{Domain, SockAddr, Socket, Type};
    use std::io;
    use std::os::windows::io::{FromRawSocket, IntoRawSocket};
    use std::path::Path;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use std::time::Duration;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    pub struct LocalListener {
        inner: Arc<Socket>,
    }

    pub struct LocalStream {
        inner: tokio::net::TcpStream,
    }

    impl LocalListener {
        pub fn bind(path: &Path) -> io::Result<Self> {
            Self::bind_inner(path, false)
        }

        /// Bind with a restrictive DACL (SYSTEM + Administrators only) applied
        /// between `bind()` and `listen()`. No connections are possible before
        /// `listen()`, so this eliminates the TOCTOU race where the socket
        /// inherits a permissive DACL from the parent directory. The final
        /// DACL (adding the `hole` group) is applied later by
        /// `apply_socket_permissions()` in `ipc.rs`.
        pub fn bind_restricted(path: &Path) -> io::Result<Self> {
            Self::bind_inner(path, true)
        }

        fn bind_inner(path: &Path, restrict: bool) -> io::Result<Self> {
            // Remove stale socket file (ignore "not found"; warn on other errors)
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => {
                    tracing::warn!(error = %e, "failed to remove stale socket file");
                }
            }

            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
            let addr = SockAddr::unix(path)?;
            socket.bind(&addr)?;
            if restrict {
                // Use the shared base SDDL with P (protected) prefix to block
                // inherited ACEs from the parent directory.
                let sddl = crate::ipc::SDDL_BASE.replacen("D:", "D:P", 1);
                if let Err(e) = crate::ipc::set_dacl_from_sddl(path, &sddl, true) {
                    let _ = std::fs::remove_file(path);
                    return Err(e);
                }
            }
            socket.listen(128)?;
            // Non-blocking so accept() returns immediately with WouldBlock
            // when no connection is pending. This prevents spawn_blocking
            // from holding the blocking thread pool during shutdown.
            socket.set_nonblocking(true)?;
            Ok(Self {
                inner: Arc::new(socket),
            })
        }

        pub async fn accept(&self) -> io::Result<LocalStream> {
            loop {
                let socket = Arc::clone(&self.inner);
                match tokio::task::spawn_blocking(move || socket.accept()).await {
                    Ok(Ok((client, _addr))) => {
                        client.set_nonblocking(true)?;
                        let raw = client.into_raw_socket();
                        // SAFETY: raw socket is a valid AF_UNIX socket. TcpStream is used
                        // only for async I/O (read/write) which works on any Winsock handle
                        // via IOCP.
                        let std_stream = unsafe { std::net::TcpStream::from_raw_socket(raw) };
                        let tokio_stream = tokio::net::TcpStream::from_std(std_stream)?;
                        return Ok(LocalStream { inner: tokio_stream });
                    }
                    Ok(Err(e)) if e.kind() == io::ErrorKind::WouldBlock => {
                        // No pending connection — sleep briefly and retry.
                        // The sleep yields to tokio, allowing task cancellation
                        // on server shutdown.
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                    Ok(Err(e)) => return Err(e),
                    Err(e) => return Err(io::Error::other(format!("accept task panicked: {e}"))),
                }
            }
        }
    }

    impl LocalStream {
        pub async fn connect(path: &Path) -> io::Result<Self> {
            let path = path.to_owned();
            let stream = tokio::task::spawn_blocking(move || -> io::Result<std::net::TcpStream> {
                let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
                let addr = SockAddr::unix(&path)?;
                socket.connect(&addr)?;
                socket.set_nonblocking(true)?;
                let raw = socket.into_raw_socket();
                // SAFETY: same as accept — AF_UNIX socket used for I/O only.
                Ok(unsafe { std::net::TcpStream::from_raw_socket(raw) })
            })
            .await
            .map_err(|e| io::Error::other(format!("connect task panicked: {e}")))??;

            let tokio_stream = tokio::net::TcpStream::from_std(stream)?;
            Ok(Self { inner: tokio_stream })
        }
    }

    impl AsyncRead for LocalStream {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for LocalStream {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    impl Unpin for LocalStream {}
}

pub use imp::{LocalListener, LocalStream};

/// Bind a listener at the given path, removing any stale socket file first.
/// Creates parent directories if they don't exist.
pub fn bind(path: &Path) -> io::Result<LocalListener> {
    LocalListener::bind(path)
}

/// Like [`bind`], but applies restrictive OS-level permissions during creation.
///
/// On macOS, identical to `bind()` (umask guard is always applied).
/// On Windows, applies a protected DACL (SYSTEM + Administrators only) between
/// `bind()` and `listen()` to prevent a TOCTOU race on socket permissions.
#[allow(dead_code)]
pub(crate) fn bind_restricted(path: &Path) -> io::Result<LocalListener> {
    LocalListener::bind_restricted(path)
}

/// Connect to a listener at the given path.
pub async fn connect(path: &Path) -> io::Result<LocalStream> {
    LocalStream::connect(path).await
}

#[cfg(test)]
#[path = "socket_tests.rs"]
mod socket_tests;
