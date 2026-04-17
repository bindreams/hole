use super::{discover_dns_servers, UpstreamResolver};

#[skuld::test]
fn discover_dns_servers_returns_at_least_one() {
    let servers = discover_dns_servers().unwrap();
    assert!(!servers.is_empty(), "should find at least one DNS server");
}

#[skuld::test]
fn upstream_resolver_resolves_known_domain() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let servers = discover_dns_servers().unwrap();
        let resolver = UpstreamResolver::new(&servers);
        let ips = resolver.resolve("example.com").await.unwrap();
        assert!(!ips.is_empty(), "example.com should resolve");
    });
}
