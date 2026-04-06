// Proxy lifecycle manager — start/stop/reload orchestration.

use crate::gateway::GatewayInfo;
use crate::proxy::{build_ss_config, ProxyError, TUN_DEVICE_NAME};
use crate::routing::RouteGuard;
use hole_common::protocol::ProxyConfig;
use shadowsocks_service::config::Config;
use std::net::IpAddr;
use std::time::Instant;
use tokio::task::JoinHandle;
use tracing::{error, info};

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

// No-TUN backend (development) ========================================================================================

/// Development backend that skips TUN/routing/shadowsocks.
/// All operations succeed with no side effects.
pub struct NoTunBackend;

impl ProxyBackend for NoTunBackend {
    async fn start_ss(&self, _config: Config) -> Result<JoinHandle<std::io::Result<()>>, ProxyError> {
        Ok(tokio::spawn(async {
            std::future::pending::<()>().await;
            Ok(())
        }))
    }

    fn setup_routes(&self, _: &str, _: IpAddr, _: IpAddr, _: &str) -> Result<(), ProxyError> {
        Ok(())
    }

    fn teardown_routes(&self, _: &str, _: IpAddr, _: &str) -> Result<(), ProxyError> {
        Ok(())
    }

    fn default_gateway(&self) -> Result<GatewayInfo, ProxyError> {
        Ok(GatewayInfo {
            gateway_ip: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            interface_name: "none".into(),
        })
    }
}

// ProxyManager ========================================================================================================

pub struct ProxyManager<B: ProxyBackend = RealBackend> {
    backend: B,
    task_handle: Option<JoinHandle<std::io::Result<()>>>,
    route_guard: Option<RouteGuard>,
    server_ip: Option<IpAddr>,
    started_at: Option<Instant>,
    last_error: Option<String>,
    state: ProxyState,
}

impl<B: ProxyBackend> ProxyManager<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend,
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

        // Build shadowsocks config
        let ss_config = build_ss_config(config)?;

        // Resolve server hostname to IP
        let server_ip = resolve_server_ip(&config.server.server, config.server.server_port).await?;

        // Detect default gateway and interface
        let gw_info = self.backend.default_gateway()?;

        // Start shadowsocks-service
        let handle = self.backend.start_ss(ss_config).await.inspect_err(|e| {
            self.last_error = Some(e.to_string());
        })?;

        // Set up routes — if this fails, abort the ss task
        if let Err(e) =
            self.backend
                .setup_routes(TUN_DEVICE_NAME, server_ip, gw_info.gateway_ip, &gw_info.interface_name)
        {
            handle.abort();
            self.last_error = Some(e.to_string());
            return Err(e);
        }

        self.task_handle = Some(handle);
        self.route_guard = Some(RouteGuard::new(
            TUN_DEVICE_NAME.to_owned(),
            server_ip,
            gw_info.interface_name,
        ));
        self.server_ip = Some(server_ip);
        self.started_at = Some(Instant::now());
        self.last_error = None;
        self.state = ProxyState::Running;

        info!(server_ip = %server_ip, "proxy started");
        Ok(())
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
