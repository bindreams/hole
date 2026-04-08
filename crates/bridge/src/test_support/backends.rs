//! Test-only `ProxyBackend` implementations.
//!
//! [`SocksOnlyBackend`] wraps [`crate::proxy_manager::RealBackend`] but
//! rewrites the shadowsocks `Config` in `start_ss` to drop any TUN local
//! instance, and no-ops the routing methods. This lets SOCKS5-mode tests
//! run on an unelevated dev machine without touching the host TUN/route
//! tables, while still exercising the real `shadowsocks_service::local::Server`.
//!
//! Why the rewrite is needed: [`crate::proxy::build_ss_config`]
//! unconditionally pushes both a TUN and a SOCKS5 local. The TUN adapter is
//! created inside `shadowsocks_service::local::Server::new` (i.e. inside
//! `RealBackend::start_ss`), not inside `ProxyBackend::setup_routes` — so a
//! backend that only no-ops the routing methods still fails to start
//! unelevated because it tries to open the TUN adapter.

use crate::gateway::GatewayInfo;
use crate::proxy::ProxyError;
use crate::proxy_manager::{ProxyBackend, RealBackend};
use shadowsocks_service::config::{Config, ProtocolType};
use std::net::IpAddr;
use tokio::task::JoinHandle;

pub(crate) struct SocksOnlyBackend {
    inner: RealBackend,
}

impl SocksOnlyBackend {
    pub(crate) fn new() -> Self {
        Self { inner: RealBackend }
    }
}

impl ProxyBackend for SocksOnlyBackend {
    fn start_ss(
        &self,
        mut config: Config,
    ) -> impl std::future::Future<Output = Result<JoinHandle<std::io::Result<()>>, ProxyError>> + Send {
        // Drop any TUN local instance before delegating. After this filter,
        // only the SOCKS5 local remains, so `shadowsocks_service::local::Server`
        // never tries to open a TUN adapter.
        config
            .local
            .retain(|local| !matches!(local.config.protocol, ProtocolType::Tun));
        self.inner.start_ss(config)
    }

    fn setup_routes(
        &self,
        _tun_name: &str,
        _server_ip: IpAddr,
        _gateway: IpAddr,
        _interface_name: &str,
    ) -> Result<(), ProxyError> {
        // No-op: SOCKS5-mode tests don't touch the host route table.
        Ok(())
    }

    fn teardown_routes(&self, _tun_name: &str, _server_ip: IpAddr, _interface_name: &str) -> Result<(), ProxyError> {
        Ok(())
    }

    fn default_gateway(&self) -> Result<GatewayInfo, ProxyError> {
        // Synthetic TEST-NET-1 gateway. The value is never actually used
        // because `setup_routes` is a no-op, but `ProxyManager::start`
        // queries the gateway before calling `setup_routes`, so we have to
        // return *something* that parses as an `IpAddr`.
        Ok(GatewayInfo {
            gateway_ip: "192.0.2.1".parse().unwrap(),
            interface_name: "test-net".to_string(),
        })
    }
}
