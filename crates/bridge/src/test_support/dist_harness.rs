//! Dist-directory-backed e2e test harness for the bridge.
//!
//! Spawns a real `hole bridge run` subprocess from a staged dist directory
//! (`target/<profile>/dist/bin/`) and exposes a small IPC client that can
//! send [`BridgeRequest`]s to it. Each test gets its own socket path and
//! state directory so parallel tests don't collide.
//!
//! ## Why a subprocess instead of in-process `ProxyManager`
//!
//! The production bridge resolves its plugin binary by looking next to
//! `current_exe()`. Under `cargo test` the test binary lives at
//! `target/<profile>/deps/hole_bridge-<hash>.exe`, which does not have
//! `v2ray-plugin` as a sibling. The dist directory IS the production
//! layout, so spawning from it exercises the real plugin resolution path
//! without any test-only seams in production code. See PR #164 follow-up
//! plan for the full rationale.
//!
//! ## Lifetime
//!
//! Each `DistHarness` owns:
//! - an ephemeral socket path under `std::env::temp_dir()`
//! - a per-test state-dir tempdir
//! - a spawned bridge child process
//! - a pre-connected HTTP/1.1 client ready to send `BridgeRequest`s
//!
//! Drop kills the child and cleans up the temp dirs. Clean shutdown via
//! `BridgeRequest::Stop` + wait is available via [`DistHarness::shutdown`]
//! for tests that need to observe post-stop state (e.g. state-file
//! cleanup).

use crate::socket::LocalStream;
use bytes::Bytes;
use hole_common::protocol::{
    BridgeRequest, BridgeResponse, DiagnosticsResponse, ErrorResponse, MetricsResponse, PublicIpResponse,
    StatusResponse, TestServerRequest, TestServerResponse, ROUTE_CANCEL, ROUTE_DIAGNOSTICS, ROUTE_METRICS,
    ROUTE_PUBLIC_IP, ROUTE_RELOAD, ROUTE_START, ROUTE_STATUS, ROUTE_STOP, ROUTE_TEST_SERVER,
};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

const MAX_RESPONSE_SIZE: usize = 1024 * 1024;

/// Error returned by [`DistHarness`] operations. Test-only, panic-friendly
/// (every error branch in a test just calls `.expect()` or `.unwrap()`).
#[derive(Debug)]
pub(crate) struct HarnessError(pub String);

impl std::fmt::Display for HarnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for HarnessError {}

// Individual From impls for the error types we actually wrap. A blanket
// `From<E: Display>` impl would conflict with `impl From<T> for T` from
// core.
impl From<std::io::Error> for HarnessError {
    fn from(e: std::io::Error) -> Self {
        HarnessError(e.to_string())
    }
}
impl From<serde_json::Error> for HarnessError {
    fn from(e: serde_json::Error) -> Self {
        HarnessError(e.to_string())
    }
}
impl From<http::Error> for HarnessError {
    fn from(e: http::Error) -> Self {
        HarnessError(e.to_string())
    }
}
impl From<hyper::Error> for HarnessError {
    fn from(e: hyper::Error) -> Self {
        HarnessError(e.to_string())
    }
}

/// A running `hole bridge run` subprocess + a connected IPC client.
///
/// See the module-level doc for lifetime and shutdown semantics.
pub(crate) struct DistHarness {
    /// Ephemeral per-test socket path. Cleaned up on drop.
    pub socket_path: PathBuf,
    /// Per-test state directory. Held for the harness lifetime so tests
    /// can read `bridge-routes.json` (and so the tempdir is cleaned up
    /// on drop).
    pub state_dir: TempDir,
    /// Log directory override for the subprocess. Held to keep it alive
    /// and out of the default log path.
    _log_dir: TempDir,
    child: Option<Child>,
    /// Client is wrapped in `Option` so `Drop` can `take()` it and
    /// dispatch a final `BridgeRequest::Stop` via a short-lived tokio
    /// runtime. After `shutdown()` (or the initial construction
    /// failure path), this is `None`.
    client: Option<BridgeIpcClient>,
}

impl DistHarness {
    /// Stage nothing and spawn a fresh bridge subprocess pointing at a
    /// per-test socket + state dir. `dist_bin_dir` must already contain
    /// `hole[.exe]` and its sibling runtime files — callers get this
    /// from the process-scoped `dist_dir` skuld fixture.
    ///
    /// Blocks until the bridge's IPC socket is connectable (or the
    /// spawn-ready budget expires).
    pub(crate) async fn spawn(dist_bin_dir: &Path) -> Result<Self, HarnessError> {
        let hole_exe = dist_bin_dir.join(if cfg!(windows) { "hole.exe" } else { "hole" });
        if !hole_exe.is_file() {
            return Err(HarnessError(format!("hole binary missing from dist dir: {hole_exe:?}")));
        }

        let state_dir = tempfile::tempdir()?;
        let log_dir = tempfile::tempdir()?;
        let socket_path = Self::mint_socket_path()?;

        let mut cmd = Command::new(&hole_exe);
        cmd.arg("bridge")
            .arg("run")
            .arg("--socket-path")
            .arg(&socket_path)
            .arg("--state-dir")
            .arg(state_dir.path())
            .arg("--log-dir")
            .arg(log_dir.path())
            .stdin(Stdio::null())
            // Inherit stdout/stderr so any startup panics or tracing
            // output reach the test harness's own captured output.
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        let mut child = cmd
            .spawn()
            .map_err(|e| HarnessError(format!("failed to spawn {hole_exe:?}: {e}")))?;

        // Wait for the socket to become connectable before returning.
        // If the subprocess has already exited, surface that instead of
        // waiting the full 10s timeout.
        if let Err(e) = wait_for_socket_or_exit(&socket_path, &mut child, Duration::from_secs(10)).await {
            // Try to reap the child so we don't leave a zombie if it's
            // still limping along.
            let _ = child.kill();
            let _ = child.wait();
            return Err(HarnessError(format!(
                "bridge subprocess never bound {socket_path:?}: {e}"
            )));
        }

        let client = BridgeIpcClient::connect(&socket_path)
            .await
            .map_err(|e| HarnessError(format!("IPC handshake failed: {e}")))?;

        Ok(Self {
            socket_path,
            state_dir,
            _log_dir: log_dir,
            child: Some(child),
            client: Some(client),
        })
    }

    /// Send a `BridgeRequest` over IPC and await the response.
    pub(crate) async fn send(&mut self, req: BridgeRequest) -> Result<BridgeResponse, HarnessError> {
        match self.client.as_mut() {
            Some(c) => c.send(req).await,
            None => Err(HarnessError("DistHarness client already consumed by shutdown()".into())),
        }
    }

    /// Mint an ephemeral socket path that fits within OS-specific limits.
    ///
    /// Both platforms use AF_UNIX sockets (see `crates/bridge/src/socket.rs`),
    /// so the path is a regular filesystem path in both cases — not a
    /// Windows named pipe.
    ///
    /// On macOS `sun_path` is capped at 104 bytes, so the standard
    /// `/private/var/folders/...` tempdir path is too long — we bind in
    /// `/tmp` with a randomized name instead. On Windows we use
    /// `%TEMP%\hole-e2e-<pid>-<rand>.sock`; Windows AF_UNIX paths have
    /// the same `sun_path` length cap (108 bytes), but system-level
    /// `%TEMP%` is typically `C:\Users\<user>\AppData\Local\Temp\` which
    /// fits.
    fn mint_socket_path() -> Result<PathBuf, HarnessError> {
        let name = format!("hole-e2e-{}-{}.sock", std::process::id(), rand_suffix());
        #[cfg(windows)]
        {
            Ok(std::env::temp_dir().join(name))
        }
        #[cfg(not(windows))]
        {
            Ok(PathBuf::from("/tmp").join(name))
        }
    }
}

impl Drop for DistHarness {
    fn drop(&mut self) {
        // Drop order matters for test isolation. In particular, if a
        // TUN-mode test panics mid-assertion, the subprocess still has
        // routes installed — killing it with SIGTERM/TerminateProcess
        // does NOT run `ProxyManager::stop()`, which means the
        // `RouteGuard::drop` path (which tears down the
        // `route add 127.0.0.1 via <tun-gw>` bypass) never runs, and
        // localhost stays globally redirected through TUN for the rest
        // of the test binary's lifetime.
        //
        // So we must send `BridgeRequest::Stop` and wait for the
        // bridge to actually exit before falling back to kill. Because
        // `Drop` is synchronous and the test's tokio runtime may
        // already be torn down at this point, we spin up a tiny
        // one-shot runtime in a dedicated thread to drive the async
        // Stop + reconnect.
        let client = self.client.take();
        let Some(mut child) = self.child.take() else {
            // `shutdown()` already consumed or construction failed.
            return;
        };

        if let Some(client) = client {
            // Move client into a worker thread that drives a short
            // current-thread runtime. Return the `bool` "did we exit
            // cleanly?" back so the outer scope knows whether to fall
            // back to kill.
            let clean = std::thread::scope(|scope| {
                let child_ref = &mut child;
                scope
                    .spawn(move || -> bool {
                        let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() else {
                            return false;
                        };
                        rt.block_on(async move {
                            let mut client = client;
                            if client.send(BridgeRequest::Stop).await.is_err() {
                                return false;
                            }
                            drop(client);

                            let deadline = std::time::Instant::now() + Duration::from_secs(10);
                            loop {
                                match child_ref.try_wait() {
                                    Ok(Some(_)) => return true,
                                    Ok(None) if std::time::Instant::now() >= deadline => return false,
                                    Ok(None) => tokio::time::sleep(Duration::from_millis(25)).await,
                                    Err(_) => return false,
                                }
                            }
                        })
                    })
                    .join()
                    .unwrap_or(false)
            });

            if !clean {
                // Clean shutdown failed or timed out — force-kill the
                // subprocess so we don't leave zombies for the next
                // test run.
                let _ = child.kill();
                let _ = child.wait();
            }
        } else {
            // No client (construction failure path). Just kill.
            let _ = child.kill();
            let _ = child.wait();
        }

        // Remove the socket file (Unix only — Windows AF_UNIX sockets
        // are freed on close).
        #[cfg(not(windows))]
        {
            let _ = std::fs::remove_file(&self.socket_path);
        }
    }
}

/// Generate a short random suffix for the socket path.
fn rand_suffix() -> String {
    use rand::Rng;
    let n: u32 = rand::rng().random();
    format!("{n:08x}")
}

/// Poll-connect to the bridge socket until it becomes connectable, the
/// child process exits unexpectedly, or the deadline expires.
async fn wait_for_socket_or_exit(path: &Path, child: &mut Child, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    let mut last_err: String = String::new();
    while Instant::now() < deadline {
        // Short-circuit if the subprocess has already exited — no point
        // waiting the full timeout.
        if let Ok(Some(exit)) = child.try_wait() {
            return Err(format!(
                "bridge subprocess exited before binding socket: {exit:?}; last connect error: {last_err}"
            ));
        }
        match LocalStream::connect(path).await {
            Ok(_) => return Ok(()),
            Err(e) => {
                last_err = e.to_string();
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
    Err(format!("timeout after {timeout:?}; last error: {last_err}"))
}

// BridgeIpcClient =====================================================================================================

/// Minimal HTTP/1.1 IPC client for e2e tests.
///
/// Mirrors `crates/hole/src/bridge_client.rs` but lives inside the bridge
/// crate's `#[cfg(test)]` tree to avoid creating a crate dependency cycle
/// (`hole` already depends on `hole-bridge`; we can't reverse that).
struct BridgeIpcClient {
    sender: http1::SendRequest<Full<Bytes>>,
    conn_task: tokio::task::JoinHandle<()>,
}

impl Drop for BridgeIpcClient {
    fn drop(&mut self) {
        self.conn_task.abort();
    }
}

impl BridgeIpcClient {
    async fn connect(path: &Path) -> Result<Self, HarnessError> {
        let stream = LocalStream::connect(path).await?;
        let io = TokioIo::new(stream);
        let (sender, conn) = http1::handshake::<_, Full<Bytes>>(io).await?;
        let conn_task = tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(Self { sender, conn_task })
    }

    async fn send(&mut self, req: BridgeRequest) -> Result<BridgeResponse, HarnessError> {
        match req {
            BridgeRequest::Status => {
                let resp = self.http_get(ROUTE_STATUS).await?;
                if resp.status().is_success() {
                    let body = read_body(resp).await?;
                    let status: StatusResponse = serde_json::from_slice(&body)?;
                    Ok(BridgeResponse::Status {
                        running: status.running,
                        uptime_secs: status.uptime_secs,
                        error: status.error,
                        invalid_filters: status.invalid_filters,
                        udp_proxy_available: status.udp_proxy_available,
                        ipv6_bypass_available: status.ipv6_bypass_available,
                    })
                } else {
                    parse_bridge_error(resp).await
                }
            }
            BridgeRequest::Start { config } => {
                let body = serde_json::to_vec(&config)?;
                let resp = self.http_post(ROUTE_START, body).await?;
                if resp.status().is_success() {
                    Ok(BridgeResponse::Ack)
                } else {
                    parse_bridge_error(resp).await
                }
            }
            BridgeRequest::Stop => {
                let resp = self.http_post(ROUTE_STOP, Vec::new()).await?;
                if resp.status().is_success() {
                    Ok(BridgeResponse::Ack)
                } else {
                    parse_bridge_error(resp).await
                }
            }
            BridgeRequest::Cancel => {
                let resp = self.http_post(ROUTE_CANCEL, Vec::new()).await?;
                if resp.status().is_success() {
                    Ok(BridgeResponse::Ack)
                } else {
                    parse_bridge_error(resp).await
                }
            }
            BridgeRequest::Reload { config } => {
                let body = serde_json::to_vec(&config)?;
                let resp = self.http_post(ROUTE_RELOAD, body).await?;
                if resp.status().is_success() {
                    Ok(BridgeResponse::Ack)
                } else {
                    parse_bridge_error(resp).await
                }
            }
            BridgeRequest::Metrics => {
                let resp = self.http_get(ROUTE_METRICS).await?;
                if resp.status().is_success() {
                    let body = read_body(resp).await?;
                    let metrics: MetricsResponse = serde_json::from_slice(&body)?;
                    Ok(BridgeResponse::Metrics {
                        bytes_in: metrics.bytes_in,
                        bytes_out: metrics.bytes_out,
                        speed_in_bps: metrics.speed_in_bps,
                        speed_out_bps: metrics.speed_out_bps,
                        uptime_secs: metrics.uptime_secs,
                        filter: metrics.filter,
                    })
                } else {
                    parse_bridge_error(resp).await
                }
            }
            BridgeRequest::Diagnostics => {
                let resp = self.http_get(ROUTE_DIAGNOSTICS).await?;
                if resp.status().is_success() {
                    let body = read_body(resp).await?;
                    let diag: DiagnosticsResponse = serde_json::from_slice(&body)?;
                    Ok(BridgeResponse::Diagnostics {
                        app: diag.app,
                        bridge: diag.bridge,
                        network: diag.network,
                        vpn_server: diag.vpn_server,
                        internet: diag.internet,
                    })
                } else {
                    parse_bridge_error(resp).await
                }
            }
            BridgeRequest::PublicIp => {
                let resp = self.http_get(ROUTE_PUBLIC_IP).await?;
                if resp.status().is_success() {
                    let body = read_body(resp).await?;
                    let pip: PublicIpResponse = serde_json::from_slice(&body)?;
                    Ok(BridgeResponse::PublicIp {
                        ip: pip.ip,
                        country_code: pip.country_code,
                    })
                } else {
                    parse_bridge_error(resp).await
                }
            }
            BridgeRequest::TestServer { entry } => {
                let req_body = TestServerRequest { entry };
                let body = serde_json::to_vec(&req_body)?;
                let resp = self.http_post(ROUTE_TEST_SERVER, body).await?;
                if resp.status().is_success() {
                    let body = read_body(resp).await?;
                    let parsed: TestServerResponse = serde_json::from_slice(&body)?;
                    Ok(BridgeResponse::TestServerResult {
                        outcome: parsed.outcome,
                    })
                } else {
                    parse_bridge_error(resp).await
                }
            }
        }
    }

    async fn http_get(&mut self, path: &str) -> Result<http::Response<hyper::body::Incoming>, HarnessError> {
        let req = http::Request::builder()
            .method("GET")
            .uri(path)
            .header("host", "localhost")
            .body(Full::new(Bytes::new()))?;
        self.sender.ready().await?;
        #[allow(clippy::disallowed_methods)] // ready() called above
        Ok(self.sender.send_request(req).await?)
    }

    async fn http_post(
        &mut self,
        path: &str,
        body: Vec<u8>,
    ) -> Result<http::Response<hyper::body::Incoming>, HarnessError> {
        let req = http::Request::builder()
            .method("POST")
            .uri(path)
            .header("host", "localhost")
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body)))?;
        self.sender.ready().await?;
        #[allow(clippy::disallowed_methods)] // ready() called above
        Ok(self.sender.send_request(req).await?)
    }
}

async fn read_body(resp: http::Response<hyper::body::Incoming>) -> Result<Bytes, HarnessError> {
    let limited = http_body_util::Limited::new(resp.into_body(), MAX_RESPONSE_SIZE);
    limited
        .collect()
        .await
        .map(|c| c.to_bytes())
        .map_err(|e| HarnessError(e.to_string()))
}

async fn parse_bridge_error(resp: http::Response<hyper::body::Incoming>) -> Result<BridgeResponse, HarnessError> {
    let status = resp.status();
    if status.is_server_error() {
        match read_body(resp).await {
            Ok(body) => {
                let err: ErrorResponse = serde_json::from_slice(&body).unwrap_or(ErrorResponse {
                    message: "unknown error".to_string(),
                });
                Ok(BridgeResponse::Error { message: err.message })
            }
            Err(_) => Ok(BridgeResponse::Error {
                message: "failed to read error response".to_string(),
            }),
        }
    } else {
        Err(HarnessError(format!("unexpected HTTP status: {status}")))
    }
}
