use crate::proxy::{Proxy, ProxyError, RunningProxy, TrafficTotals};
use crate::proxy_manager::ProxyManager;
use bytes::Bytes;
use hole_common::protocol::{StatusResponse, ROUTE_STATUS};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use tokio::io::AsyncBufReadExt as _;
use tokio::task::JoinHandle;
use tun_engine::gateway::GatewayInfo;
use tun_engine::routing::Routing;
use tun_engine::RoutingError;

#[skuld::test]
fn sweep_wiring_reports_and_deletes_bridge_marker() {
    // HONESTY NOTE (plan §Task 7 Step 2, review S6): this test asserts that
    // the bridge crate can reach `tombstone::sweep` and that the sweep
    // CONTRACT (breadcrumb + marker deletion) holds in the bridge's tracing
    // context. It does NOT assert that foreground.rs / macos.rs / windows.rs
    // actually CALL sweep at the right point in the startup sequence — that
    // PLACEMENT is verified by code review, exactly as the sibling
    // recover_routes / recover_plugins / recover_dns_config call placements
    // are likewise untested (the entry-point bodies block on server.run()).
    use garter::test_utils::WaitableWriter;
    use garter::tracing_test::set_default_in_current_thread;

    let log_dir = tempfile::tempdir().expect("tempdir");
    let marker = log_dir.path().join("crash-bridge-123.marker");
    std::fs::write(
        &marker,
        "tombstone-marker v1\nkind=bridge\npid=123\ntid=0\ncode=0xc0000005\nfault_addr=0x0\ntime=1\n",
    )
    .unwrap();

    let writer = WaitableWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .with_ansi(false)
        .with_target(true)
        .finish();
    let _g = set_default_in_current_thread(subscriber);
    let rx = writer.wait_for("native crash detected in previous run");

    // This is the exact call the foreground/service entry points make.
    tombstone::sweep(log_dir.path());

    rx.recv().expect("breadcrumb emitted");
    assert!(!marker.exists(), "marker deleted");
}

// Minimal stub types used only for the foreground-run IPC smoke test.
// None of their methods are exercised by this test — we only construct
// the ProxyManager so `IpcServer::bind` can be bound and the status
// endpoint queried. A shared test-support module would be overkill for
// one use.

struct StubProxy;

impl Proxy for StubProxy {
    type Running = StubRunning;
    async fn start(&self, _config: shadowsocks_service::config::Config) -> Result<StubRunning, ProxyError> {
        Ok(StubRunning {
            handle: Some(tokio::spawn(async { std::future::pending::<io::Result<()>>().await })),
        })
    }
}

struct StubRunning {
    handle: Option<JoinHandle<io::Result<()>>>,
}

impl RunningProxy for StubRunning {
    fn is_alive(&self) -> bool {
        self.handle.as_ref().is_some_and(|h| !h.is_finished())
    }
    async fn stop(mut self) -> Result<(), ProxyError> {
        if let Some(h) = self.handle.take() {
            h.abort();
        }
        Ok(())
    }
    fn traffic_totals(&self) -> TrafficTotals {
        TrafficTotals::default()
    }
}

impl Drop for StubRunning {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

struct StubRouting {
    state_dir: PathBuf,
}

impl StubRouting {
    fn new(state_dir: PathBuf) -> Self {
        Self { state_dir }
    }
}

impl Routing for StubRouting {
    type Installed = StubRoutes;
    type Cover = StubCover;
    fn install(&self, _: &str, _: IpAddr, _: IpAddr, _: &str) -> Result<StubRoutes, RoutingError> {
        Ok(StubRoutes {
            _state_dir: self.state_dir.clone(),
        })
    }
    fn default_gateway(&self) -> Result<GatewayInfo, RoutingError> {
        Ok(GatewayInfo {
            gateway_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            interface_name: "StubIf".into(),
            interface_index: 1,
            ipv6_available: false,
        })
    }
    fn install_failclosed_cover(&self, _: IpAddr) -> Result<StubCover, RoutingError> {
        Ok(StubCover)
    }
}

struct StubRoutes {
    // Unused; held only to mirror production's state-dir-owning routes type.
    _state_dir: PathBuf,
}

struct StubCover;

impl Drop for StubCover {
    fn drop(&mut self) {}
}

fn test_socket_path(suffix: &str) -> PathBuf {
    std::env::temp_dir().join(format!("hole-fg-test-{}-{suffix}.sock", std::process::id()))
}

#[skuld::test]
fn foreground_run_accepts_ipc_and_shuts_down() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let path = test_socket_path("fg-ipc");
        let state_dir = tempfile::tempdir().unwrap().keep();

        // Use a channel to trigger graceful shutdown (simulates Ctrl+C)
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        // Signaled once IpcServer::bind has returned Ok — i.e. the socket
        // is listening and connects will succeed. No poll-retry needed.
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();

        let path_clone = path.clone();
        let server_handle = tokio::spawn(async move {
            let proxy = std::sync::Arc::new(tokio::sync::Mutex::new(ProxyManager::new(
                StubProxy,
                StubRouting::new(state_dir),
            )));
            let proxy_shutdown = std::sync::Arc::clone(&proxy);

            let server = crate::ipc::IpcServer::bind(&path_clone, proxy, "test").unwrap();
            // Server is bound; let the test side connect.
            let _ = ready_tx.send(());

            tokio::select! {
                result = server.run() => {
                    if let Err(e) = result {
                        tracing::error!(error = %e, "IPC server error");
                    }
                }
                _ = shutdown_rx => {
                    tracing::info!("test shutdown signal received");
                }
            }

            // This is the graceful shutdown path we want to verify runs
            let mut pm = proxy_shutdown.lock().await;
            pm.stop().await.unwrap();
        });

        // Park until the server task signals the IPC socket is bound.
        // Deterministic, no poll-retry.
        ready_rx.await.expect("server task dropped ready sender before bind");
        let stream = crate::socket::LocalStream::connect(&path)
            .await
            .expect("connect to freshly-bound IPC socket");
        let io = TokioIo::new(stream);
        let (mut sender, conn) = http1::handshake(io).await.unwrap();
        let _conn = tokio::spawn(async move {
            let _ = conn.await;
        });

        // Query status
        sender.ready().await.unwrap();
        #[allow(clippy::disallowed_methods)]
        let resp = sender
            .send_request(
                http::Request::builder()
                    .method("GET")
                    .uri(ROUTE_STATUS)
                    .header("host", "localhost")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let status: StatusResponse = serde_json::from_slice(&body).unwrap();
        assert!(!status.running);

        // Trigger graceful shutdown and verify the task completes cleanly
        shutdown_tx.send(()).unwrap();
        // Await the server task directly; deterministic, the framework
        // timeout surfaces a hang as "test took too long".
        server_handle.await.expect("server task panicked");
    });
}

#[skuld::test]
fn ready_notify_connects_and_writes_token() {
    // HONESTY NOTE: this pins `notify_ready`'s CONTRACT; the PLACEMENT
    // (called in `run_inner` right after `IpcServer::bind` returns, i.e.
    // after `apply_socket_permissions`) is verified by code review, like
    // the sibling recovery-call placements. (`apply_socket_permissions`
    // is `#[cfg(not(test))]` inside `IpcServer::bind`, so the
    // after-permissions ordering cannot be asserted in a test build even
    // in principle.)
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let spec = format!("{}/sekrit-token", listener.local_addr().unwrap());
        super::notify_ready(&spec).await;
        let (conn, _) = listener.accept().await.unwrap();
        let mut lines = tokio::io::BufReader::new(conn).lines();
        let line = lines.next_line().await.unwrap();
        assert_eq!(line.as_deref(), Some("sekrit-token"));
    });
}

#[skuld::test]
fn ready_notify_tolerates_malformed_spec_and_dead_listener() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        // Best-effort contract: neither panics nor errors — the supervisor's
        // own deadline is the failure signal (spec §Bridge changes).
        super::notify_ready("no-slash-here").await;
        super::notify_ready("127.0.0.1:1/dead-listener-token").await;
    });
}

/// CTRL_BREAK must resolve shutdown_signal (the Windows analog of the
/// sigterm_resolves_shutdown_signal test below it). Runs the bridge test
/// binary as a kill-group child (=> CREATE_NEW_PROCESS_GROUP) and delivers
/// the real console signal.
#[cfg(windows)]
#[skuld::test]
fn ctrl_break_resolves_shutdown_signal() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let exe = std::env::current_exe().unwrap();
        let mut cmd = tokio::process::Command::new(exe);
        cmd.env(crate::foreground_child_hook::MODE_ENV, "1");
        cmd.stdin(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::piped());
        cmd.kill_on_drop(true);
        let mut gc = kill_group::GroupedChild::spawn(&mut cmd, kill_group::Nesting::Mark).unwrap();
        let stdout = gc.child.stdout.take().unwrap();
        let mut lines = tokio::io::BufReader::new(stdout).lines();
        // Rendezvous: the child prints only after handlers are installed.
        assert_eq!(lines.next_line().await.unwrap().as_deref(), Some("HANDLER-READY"));
        gc.signal_group_term().unwrap();
        let status = gc.child.wait().await.unwrap();
        assert!(
            status.success(),
            "CTRL_BREAK must resolve shutdown_signal; got {status:?}"
        );
    });
}

// dev-console's SIGTERM (relayed by sudo) must trigger graceful `pm.stop()`
// instead of an ungraceful default-disposition kill that leaks routes/DNS
// (bindreams/hole#452). `shutdown_signal()` installs the SIGTERM handler
// SYNCHRONOUSLY when called (Step 3), so raising the signal immediately
// after is non-fatal and is observed by the returned future — deterministic,
// no spawn/poll race (a prior spawn+yield_now form raced and killed the test
// process with SIGTERM's default disposition on iteration 0). macOS-gated to
// match libc's dependency gating; test-hole's only POSIX hosts are macOS, and
// nextest isolates each test in its own process so the raise can't disturb
// siblings.
#[cfg(target_os = "macos")]
#[skuld::test]
fn sigterm_resolves_shutdown_signal() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        // Installs the SIGTERM handler NOW (eager, not on first poll).
        let fut = super::shutdown_signal();
        // SAFETY: raising a signal to our own process is sound.
        assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
        // Resolves on the delivered SIGTERM; bounded by the framework timeout
        // (allowed external-event failure-bound), not a self-chosen sleep.
        fut.await;
    });
}
