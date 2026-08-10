//! ECH-config DoH source for the plugin chain.
//!
//! ex-ray fetches the ECHConfigList itself, over a Go HTTP client that dials
//! whatever host the `ech-doh` URL names via `internet.DialSystem`. A hostname
//! URL would cost a plaintext system-DNS lookup — the channel the private DoH
//! bootstrap exists to avoid — so the URL is always IP-literal. It also names
//! the resolver that answered the bootstrap rather than the first configured
//! one, because ex-ray takes a single URL and does no failover.
//!
//! The bridge's own DoT/DoH transports are different: they dial the configured
//! IP and use the provider hostname only for SNI and the `Host:` header, which
//! leaks nothing to a system resolver.

use std::net::IpAddr;

use hole_common::config::DnsConfig;

/// Which resolver the ECH lookup is pinned to — and when none is, why.
///
/// Anything but `Answered` names an endpoint nothing has demonstrated this host
/// can reach. The reasons stay distinct because they are not equally benign,
/// and each is reported in its own words: `NoQueryNeeded` means no query was
/// ever issued, while `SecureBootstrapFailed` means every configured resolver
/// failed to complete a DoH exchange at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinSource {
    /// This resolver returned a well-formed reply over its DoH channel. What it
    /// said about the proxy hostname is beside the point: serving the ECH lookup
    /// needs only that the resolver is reachable and its certificate verified.
    Answered(IpAddr),
    /// The proxy server entry was a literal IP, so no resolver was consulted.
    NoQueryNeeded,
    /// No configured resolver completed a DoH exchange at all, and
    /// `allow_insecure_bootstrap` let the OS resolver resolve the server instead.
    SecureBootstrapFailed,
    /// A covered retry's cached resolver is no longer listed in `dns.servers`.
    ResolverDeselected,
}

/// The port implied by [`doh_url_for_ip`]'s bare `https://` scheme (RFC
/// 9110's default port for `https`, since the URL never carries an explicit
/// one) — the ONE port ex-ray's ECH-config fetch can ever dial for a URL this
/// module builds. `doh_url_for_ip_ports_to_the_https_default` pins this with
/// an executable assertion against the URL crate's own scheme-default table,
/// not just prose. `tun-engine`'s fail-closed cover mirrors this value as
/// `RESOLVER_PERMIT_PORT` (`crates/tun-engine/src/routing/failclosed.rs`) —
/// a separate declaration, not an import: `tun-engine` sits BELOW
/// `hole-bridge` in the crate dependency graph, so it cannot import from
/// here.
pub const DOH_PORT: u16 = 443;

/// DoH endpoint URL that pins the resolver by IP: `https://<ip>/dns-query`,
/// IPv6 bracketed per RFC 3986 §3.2.2. It names no host, so a client dials
/// `ip` directly and verifies the certificate against an IP SAN — it has
/// nothing to resolve and cannot fall back to the system resolver.
pub fn doh_url_for_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => format!("https://{v4}/dns-query"),
        IpAddr::V6(v6) => format!("https://[{v6}]/dns-query"),
    }
}

/// Whether `url`'s authority is a name rather than an IP literal. A name is
/// what costs the plaintext system-DNS lookup this module exists to avoid, so
/// it is the test for whether replacing a URL removes a leak or merely swaps
/// one endpoint for another. Anything not demonstrably an IP literal counts as
/// a name — an unparseable or host-less URL included, since a plugin would hand
/// whatever it read to its resolver.
pub fn authority_is_a_name(url: &str) -> bool {
    !matches!(
        url::Url::parse(url).ok().and_then(|u| u.host_str().map(String::from)),
        Some(host) if host.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>().is_ok()
    )
}

/// The `ech-doh` Hole offers, and how its resolver was chosen. The reason is
/// carried rather than reduced to "pinned": each one warrants a different line
/// in the log, and only [`PinSource::Answered`] outranks a value the config
/// already carries whose authority is not a name (see [`authority_is_a_name`]).
///
/// `resolver` is the exact address `url` names — Hole constructed `url` from
/// it (`doh_url_for_ip`), never a guess. The fail-closed cover permits
/// exactly this address regardless of `source`: it always comes from the
/// user's OWN configured `dns.servers`, so permitting it is config-authorship
/// trust, not a claim that THIS attempt personally dialed it — `Answered`
/// and `SecureBootstrapFailed` did (`resolve_via_doh` dials every configured
/// resolver even on total failure); `NoQueryNeeded` dialed nothing at all
/// (a literal-IP server short-circuits before the loop), and
/// `ResolverDeselected`'s fallback may name an address only a PRIOR resolve
/// dialed, or never dialed this bridge process at all. See
/// `Routing::install_failclosed_cover`'s doc for why config-authorship alone
/// is judged sufficient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchDoh {
    pub url: String,
    pub resolver: IpAddr,
    pub source: PinSource,
}

impl EchDoh {
    /// Whether a resolver demonstrated it serves DoH from this host. Used
    /// ONLY to break a tie against an operator's own `ech-doh` already in
    /// `plugin_opts` (`crate::proxy::plugin::hole_ech_doh_outranks`) — NOT to
    /// gate the fail-closed cover's permit, which reads `resolver` directly
    /// regardless of pin state (see `EchDoh`'s doc).
    pub fn is_pinned(&self) -> bool {
        self.source.verified_ip().is_some()
    }
}

impl PinSource {
    /// The address this pin has demonstrated reachable via a verified DoH
    /// exchange, if any. Only `Answered` names one; see `EchDoh::is_pinned`'s
    /// doc for how this is used.
    pub fn verified_ip(self) -> Option<IpAddr> {
        match self {
            PinSource::Answered(ip) => Some(ip),
            _ => None,
        }
    }
}

/// The `ech-doh=<url>` value: the pinned resolver, or a configured one when
/// there is no pin. `None` only when nothing is configured — omitting the key
/// makes ex-ray refuse to start under `ech=always`, so an unverified endpoint
/// still beats leaving it out.
///
/// Unpinned, the fallback prefers IPv4 — the same bias the bootstrap applies
/// when picking the server address. A positional `first()` would nail the URL to
/// one address family on a path where nothing demonstrated the host has it, and
/// ex-ray cannot fail over to the other.
pub fn ech_doh_url(dns: &DnsConfig, source: PinSource) -> Option<EchDoh> {
    let resolver = source.verified_ip().or_else(|| {
        dns.servers
            .iter()
            .find(|ip| ip.is_ipv4())
            .or_else(|| dns.servers.first())
            .copied()
    });
    resolver.map(|ip| EchDoh {
        url: doh_url_for_ip(ip),
        resolver: ip,
        source,
    })
}

/// Re-check a pin against the resolver set of the config now being started. A
/// covered retry reuses a cached pin without re-resolving, so a resolver the
/// user deselected in between would otherwise keep receiving the ECH lookup —
/// which carries the destination hostname.
pub fn revalidate(source: PinSource, servers: &[IpAddr]) -> PinSource {
    match source {
        PinSource::Answered(ip) if !servers.contains(&ip) => PinSource::ResolverDeselected,
        other => other,
    }
}

#[cfg(test)]
#[path = "ech_tests.rs"]
mod ech_tests;
