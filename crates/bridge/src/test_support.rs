//! Hole-specific test infrastructure for bridge integration tests.
//!
//! The shared shadowsocks-server / cert / sentinel harness was lifted into the
//! `plugin-e2e` crate (#435) so the plugin suites and Hole's bridge tests share
//! one copy; the `ssserver_*` skuld fixtures here wrap those harness functions.
//! What remains in this module is Hole-specific: the `DistHarness` (spawns
//! `hole bridge run`), the `HttpTarget` TUN sentinel, SOCKS5/HTTP-CONNECT
//! clients, and net discovery. Consumed by `*_tests.rs` files across the crate.
//!
//! **Convention deviation**: this module is registered directly from
//! `lib.rs` rather than via the project-wide `#[path = "foo_tests.rs"] mod
//! foo_tests;` sibling-source pattern, because there is no business-logic
//! counterpart — it is pure cross-cutting test infrastructure used by
//! multiple `*_tests.rs` files (`server_test_tests.rs`,
//! `proxy_manager_e2e_tests.rs`, ...). The `#[cfg(test)]` gate lives on the
//! `mod test_support;` declaration in `lib.rs`.
#![allow(dead_code)]

pub(crate) mod dist_fixture;
pub(crate) mod dist_harness;
pub(crate) mod dist_harness_panic_hook_tests;
pub(crate) mod http_connect_client;
pub(crate) mod http_target;
pub(crate) mod log_capture;
pub(crate) mod mock_dns;
pub(crate) mod net_discovery;
pub(crate) mod port_alloc;
pub(crate) mod reap_child;
pub(crate) mod refusing_connector;
pub(crate) mod skuld_fixtures;
pub(crate) mod socks5_client;
pub(crate) mod socks5_dns_upstream;
pub(crate) mod udp_echo;

/// The cause text inside [`mock_gateway_failure`].
pub(crate) const MOCK_GATEWAY_CAUSE: &str = "mock default-net cause";

/// A root cause that only `source()` carries; see [`io_error_hiding`].
pub(crate) const MOCK_ROOT_CAUSE: &str = "mock root cause";

/// An error whose `Display` omits its cause, as the typed errors this crate logs
/// do; only `source()` reaches `root`.
#[derive(Debug)]
pub(crate) struct CauseOmitted {
    root: std::io::Error,
}

impl std::fmt::Display for CauseOmitted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the wrapper's own sentence")
    }
}

impl std::error::Error for CauseOmitted {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.root)
    }
}

/// An `io::Error` whose `Display` omits `root_cause`; it is reachable only
/// through `source()`, which is where `util::error_chain` finds it.
pub(crate) fn io_error_hiding(root_cause: &str) -> std::io::Error {
    std::io::Error::other(CauseOmitted {
        root: std::io::Error::other(root_cause.to_owned()),
    })
}

/// A gateway failure shaped like macOS's: the route query failed with an
/// OS-level cause that `Display` deliberately omits.
pub(crate) fn mock_gateway_failure() -> tun_engine::RoutingError {
    tun_engine::RoutingError::Gateway(tun_engine::gateway::GatewayError::RouteQueryFailed {
        code: 0,
        source: std::io::Error::other(MOCK_GATEWAY_CAUSE),
    })
}

/// Build a fresh tokio runtime for one test. Mirrors `ipc_tests::rt()`.
///
/// Lives at the module root because it's useful to every test file.
pub(crate) fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().unwrap()
}
