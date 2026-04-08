// Proxy lifecycle manager — start/stop/reload orchestration.

use crate::gateway::GatewayInfo;
use crate::guards::{StateFileGuard, TaskHandleGuard};
use crate::proxy::{build_ss_config, ProxyError, TUN_DEVICE_NAME};
use crate::routing::RouteGuard;
use hole_common::protocol::ProxyConfig;
use shadowsocks_service::config::Config;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Instant;
use tokio::task::JoinHandle;
use tracing::{error, info};

// StartedState ========================================================================================================

/// Everything `start_inner` produces on success. Held by value until the
/// outer `start` commits it into `self`, so that cancelling `start_inner`
/// mid-flight (dropping the future) runs every guard's `Drop` without ever
/// touching the `ProxyManager` fields.
struct StartedState {
    task_handle: JoinHandle<std::io::Result<()>>,
    route_guard: RouteGuard,
    server_ip: IpAddr,
    started_at: Instant,
}

// State ===============================================================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProxyState {
    Stopped,
    Running,
}

// Backend trait =======================================================================================================

pub trait ProxyBackend: Send + Sync {
    fn start_ss(
        &self,
        config: Config,
    ) -> impl std::future::Future<Output = Result<JoinHandle<std::io::Result<()>>, ProxyError>> + Send;

    fn setup_routes(
        &self,
        tun_name: &str,
        server_ip: IpAddr,
        gateway: IpAddr,
        interface_name: &str,
    ) -> Result<(), ProxyError>;
    fn teardown_routes(&self, tun_name: &str, server_ip: IpAddr, interface_name: &str) -> Result<(), ProxyError>;
    fn default_gateway(&self) -> Result<GatewayInfo, ProxyError>;
}

// Real backend ========================================================================================================

pub struct RealBackend;

impl ProxyBackend for RealBackend {
    async fn start_ss(&self, config: Config) -> Result<JoinHandle<std::io::Result<()>>, ProxyError> {
        let server = shadowsocks_service::local::Server::new(config)
            .await
            .map_err(ProxyError::Runtime)?;
        Ok(tokio::spawn(async move { server.run().await }))
    }

    fn setup_routes(
        &self,
        tun_name: &str,
        server_ip: IpAddr,
        gateway: IpAddr,
        interface_name: &str,
    ) -> Result<(), ProxyError> {
        crate::routing::setup_routes(tun_name, server_ip, gateway, interface_name)
            .map_err(|e| ProxyError::RouteSetup(e.to_string()))
    }

    fn teardown_routes(&self, tun_name: &str, server_ip: IpAddr, interface_name: &str) -> Result<(), ProxyError> {
        crate::routing::teardown_routes(tun_name, server_ip, interface_name)
            .map_err(|e| ProxyError::RouteSetup(e.to_string()))
    }

    fn default_gateway(&self) -> Result<GatewayInfo, ProxyError> {
        crate::gateway::get_default_gateway_info().map_err(|e| ProxyError::Gateway(e.to_string()))
    }
}

// ProxyManager ========================================================================================================

pub struct ProxyManager<B: ProxyBackend = RealBackend> {
    backend: B,
    /// Directory where the route-recovery state file lives while a proxy is
    /// active. Owned by the manager so the constructor does not need to do
    /// I/O (see `start()` for the write-ordering contract).
    state_dir: PathBuf,
    task_handle: Option<JoinHandle<std::io::Result<()>>>,
    route_guard: Option<RouteGuard>,
    server_ip: Option<IpAddr>,
    started_at: Option<Instant>,
    last_error: Option<String>,
    state: ProxyState,
}

impl<B: ProxyBackend> ProxyManager<B> {
    pub fn new(backend: B, state_dir: PathBuf) -> Self {
        Self {
            backend,
            state_dir,
            task_handle: None,
            route_guard: None,
            server_ip: None,
            started_at: None,
            last_error: None,
            state: ProxyState::Stopped,
        }
    }

    pub fn state(&self) -> ProxyState {
        self.state
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started_at.map(|t| t.elapsed().as_secs()).unwrap_or(0)
    }

    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    pub async fn start(&mut self, config: &ProxyConfig) -> Result<(), ProxyError> {
        if self.state == ProxyState::Running {
            return Err(ProxyError::AlreadyRunning);
        }

        // `start_inner` is an associated function — it does NOT touch
        // `self`. All partial state lives in local variables wrapped in
        // RAII guards, and only on `Ok` is the resulting `StartedState`
        // committed into `self` here in the outer function. This makes
        // the whole call drop-safe: if the future returned by
        // `start_inner` is dropped at any `.await` point, every live
        // guard runs its `Drop` and `self` is left in its pre-start
        // state. See Phase 4 for where this property is exploited by
        // `tokio::select!`-based cancellation.
        match Self::start_inner(&self.backend, config, &self.state_dir).await {
            Ok(started) => {
                let server_ip = started.server_ip;
                self.task_handle = Some(started.task_handle);
                self.route_guard = Some(started.route_guard);
                self.server_ip = Some(started.server_ip);
                self.started_at = Some(started.started_at);
                self.last_error = None;
                self.state = ProxyState::Running;
                info!(server_ip = %server_ip, "proxy started");
                Ok(())
            }
            Err(e) => {
                self.last_error = Some(e.to_string());
                Err(e)
            }
        }
    }

    /// Produce a `StartedState` without touching `self`. All partial
    /// state is owned by local RAII guards so that dropping this future
    /// at any `.await` point unwinds cleanly:
    ///
    /// 1. `StateFileGuard` — clears `bridge-routes.json` if dropped
    ///    before `RouteGuard` takes over state-file cleanup.
    /// 2. `TaskHandleGuard` — aborts the shadowsocks-service task if
    ///    dropped before commit.
    /// 3. `RouteGuard` — on drop tears down routes AND clears the state
    ///    file (`RouteGuard::drop` handles both), so once it is
    ///    constructed, `StateFileGuard` is committed to avoid a
    ///    double-clear race.
    ///
    /// CRITICAL ORDERING: the route-state file is persisted BEFORE any
    /// routing mutation. A panic or SIGKILL between `setup_routes` and
    /// `RouteGuard` construction would otherwise leak routes with no
    /// on-disk record, defeating crash recovery on next startup. The
    /// guard discipline above maintains this invariant under drop as
    /// well as under explicit error returns.
    async fn start_inner(backend: &B, config: &ProxyConfig, state_dir: &Path) -> Result<StartedState, ProxyError> {
        // Build shadowsocks config (sync, no partial state).
        let ss_config: Config = build_ss_config(config)?;

        // Pre-load wintun.dll explicitly so we can give a descriptive
        // error if it's missing. shadowsocks-service uses the bare
        // "wintun.dll" name via tun-0.8.6, which becomes LoadLibraryExW
        // with default search order. By loading the DLL here first
        // (with an absolute path), the OS loader-table services the
        // later bare-name lookup from the same process via base-name
        // dedup. See crates/bridge/src/wintun.rs.
        //
        // No routes have been touched yet at this point, so we don't
        // need to roll anything back on failure.
        #[cfg(target_os = "windows")]
        crate::wintun::ensure_loaded()?;

        // Resolve server hostname to IP.
        let server_ip = resolve_server_ip(&config.server.server, config.server.server_port).await?;

        // Detect default gateway and interface.
        let gw_info = backend.default_gateway()?;

        // Persist the route-recovery state. From here on, if the future
        // is dropped or an error is returned, `StateFileGuard::drop`
        // clears the file.
        let persisted_state = crate::route_state::RouteState {
            version: crate::route_state::SCHEMA_VERSION,
            tun_name: TUN_DEVICE_NAME.to_owned(),
            server_ip,
            interface_name: gw_info.interface_name.clone(),
        };
        crate::route_state::save(state_dir, &persisted_state)
            .map_err(|e| ProxyError::RouteSetup(format!("failed to persist route-state: {e}")))?;
        let state_file_guard = StateFileGuard::new(state_dir.to_owned());

        // Start shadowsocks-service (no route mutation yet). Wrap in a
        // TaskHandleGuard so the spawned task is aborted if we drop or
        // return an error before commit.
        let task_guard = TaskHandleGuard::new(backend.start_ss(ss_config).await?);

        // Set up routes. On failure both `task_guard` and
        // `state_file_guard` are dropped in reverse-declaration order,
        // cleaning up the ss task and the state file. `teardown_routes`
        // is NOT called explicitly: if `setup_routes` itself fails,
        // nothing has been installed; if it partially installed and
        // then errored, the backend is expected to clean up its own
        // partial state (the existing contract — see `RealBackend`).
        backend.setup_routes(TUN_DEVICE_NAME, server_ip, gw_info.gateway_ip, &gw_info.interface_name)?;

        // Routes are installed. RouteGuard takes over both route
        // teardown and state-file clearing (see RouteGuard::drop), so
        // disarm StateFileGuard to avoid double-clearing the file on
        // success paths.
        let route_guard = RouteGuard::new(
            TUN_DEVICE_NAME.to_owned(),
            server_ip,
            gw_info.interface_name,
            state_dir.to_owned(),
        );
        state_file_guard.commit();

        // Extract the task handle from the guard now that routes are
        // committed. The handle moves into StartedState and will be
        // owned by the ProxyManager after the outer `start` commits.
        let task_handle = task_guard.commit();

        Ok(StartedState {
            task_handle,
            route_guard,
            server_ip,
            started_at: Instant::now(),
        })
    }

    pub async fn stop(&mut self) -> Result<(), ProxyError> {
        if self.state == ProxyState::Stopped {
            return Ok(());
        }

        // Abort the ss task
        if let Some(handle) = self.task_handle.take() {
            handle.abort();
            // Wait for it to finish (will return Err(JoinError::Cancelled))
            let _ = handle.await;
        }

        // Drop route guard (tears down routes via RAII)
        self.route_guard.take();

        self.server_ip = None;
        self.started_at = None;
        // Clear any error from a previous failed start. A clean stop is the
        // user's signal that the bridge is in a good state again — keeping
        // the stale error would make `handle_diagnostics` report
        // `bridge = "error"` indefinitely. See issue #142.
        self.last_error = None;
        self.state = ProxyState::Stopped;

        info!("proxy stopped");
        Ok(())
    }

    pub async fn reload(&mut self, config: &ProxyConfig) -> Result<(), ProxyError> {
        self.stop().await?;
        self.start(config).await
    }

    /// Check if the ss task has exited unexpectedly and update state.
    pub fn check_health(&mut self) {
        if self.state == ProxyState::Running {
            if let Some(ref handle) = self.task_handle {
                if handle.is_finished() {
                    error!("proxy task exited unexpectedly");
                    self.last_error = Some("proxy task exited unexpectedly".into());
                    self.task_handle.take();
                    self.route_guard.take();
                    self.server_ip = None;
                    self.started_at = None;
                    self.state = ProxyState::Stopped;
                }
            }
        }
    }
}

// DNS resolution ======================================================================================================

async fn resolve_server_ip(host: &str, port: u16) -> Result<IpAddr, ProxyError> {
    // Try parsing as IP address first (return as-is, including IPv6 literals)
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }

    // DNS lookup — prefer IPv4 to ensure bypass route compatibility with IPv4 gateway
    let addrs: Vec<_> = tokio::net::lookup_host(format!("{host}:{port}"))
        .await
        .map_err(|e| ProxyError::DnsResolution {
            host: host.to_owned(),
            source: e,
        })?
        .collect();

    let addr = addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .ok_or_else(|| ProxyError::DnsResolution {
            host: host.to_owned(),
            source: std::io::Error::other("no addresses returned"),
        })?;

    Ok(addr.ip())
}

#[cfg(test)]
#[path = "proxy_manager_tests.rs"]
mod proxy_manager_tests;
