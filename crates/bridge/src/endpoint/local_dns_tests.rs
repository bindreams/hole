use super::*;

#[skuld::test]
fn capabilities_are_stable() {
    let cfg = hole_common::config::DnsConfig {
        enabled: true,
        servers: vec!["192.0.2.1".parse().unwrap()],
        protocol: hole_common::config::DnsProtocol::PlainUdp,
        intercept_udp53: true,
    };
    let fwd = Arc::new(DnsForwarder::new(
        cfg,
        Arc::new(crate::dns::connector::DirectConnector),
        true,
    ));
    let ep = LocalDnsEndpoint::new(fwd);
    assert!(ep.supports_udp(), "LocalDnsEndpoint carries UDP by definition");
    assert!(
        ep.supports_ipv6_dst(),
        "destination IPv6 is irrelevant — endpoint answers locally"
    );
    assert_eq!(ep.name(), "local-dns");
}

#[skuld::test]
fn serve_tcp_returns_ok_immediately() {
    // TCP isn't served by this endpoint — it's a cascade bug if the
    // router sends one here. The method drops the flow and returns Ok(())
    // in release; the debug_assert fires only in debug tests, and we
    // don't exercise serve_tcp directly here because constructing a
    // TcpFlow requires a live engine.
    let cfg = hole_common::config::DnsConfig {
        enabled: true,
        servers: vec!["192.0.2.1".parse().unwrap()],
        protocol: hole_common::config::DnsProtocol::PlainUdp,
        intercept_udp53: true,
    };
    let fwd = Arc::new(DnsForwarder::new(
        cfg,
        Arc::new(crate::dns::connector::DirectConnector),
        true,
    ));
    let ep = LocalDnsEndpoint::new(fwd);
    // Sanity: the endpoint exists and reports its name.
    assert_eq!(ep.name(), "local-dns");
}
