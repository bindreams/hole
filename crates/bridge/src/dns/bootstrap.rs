//! DoH bootstrap resolver: resolve the proxy server's hostname to an IP over
//! DoH using the user's configured `dns.servers`, BEFORE the tunnel exists —
//! so the OS resolver is never consulted for the proxy endpoint.
//!
//! Reuses the in-tunnel DoH machinery (`DnsForwarder` + `DirectConnector`):
//! same TLS config, same provider SNI table, same DoH POST framing — but a
//! DIRECT connector (the SOCKS5 tunnel is not up at bootstrap time).
//!
//! Query build/parse goes through `hickory-proto` (the crate the in-TUN
//! `LocalDnsEndpoint` path already links) rather than hand-rolling wire format.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use hole_common::config::{DnsConfig, DnsProtocol};

use crate::dns::connector::DirectConnector;
use crate::dns::ech::PinSource;
use crate::dns::forwarder::{DnsForwarder, ForwardFailure, UpstreamCause};

/// Typed bootstrap-resolution failure. `Display` strings are PII-FREE by
/// construction — no hostname, no resolver IP, no filesystem path — so the
/// `ProxyError::DohBootstrap` that wraps this is safe to surface verbatim to a
/// toast (the detail lands in `bridge.log` via the call-site WARN and the
/// forwarder's `upstream failed` WARN). They are also EXISTENTIAL: several
/// resolvers are tried and only the strongest finding is reported, so no string
/// may claim something about all of them.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone, Copy)]
pub enum BootstrapError {
    /// The hostname is not a valid DNS name (bad label length / encoding).
    #[error("server hostname is not a valid DNS name")]
    InvalidName,
    /// A resolver's TLS certificate did not verify against our pinned roots.
    #[error("a secure DNS resolver presented a certificate that could not be verified — something on this network may be intercepting encrypted connections")]
    CertificateRejected,
    /// Distinct from `NoAnswer`: the resolver responded, but the bytes do not
    /// parse as DNS at all (see `parse_addrs`).
    #[error("a secure DNS resolver returned a reply that is not valid DNS")]
    MalformedReply,
    /// A resolver replied, but with no usable A/AAAA record (SERVFAIL,
    /// NXDOMAIN, or an empty answer section).
    #[error("could not resolve the proxy server address via secure DNS")]
    NoAnswer,
    /// A resolver was reached, but the exchange broke at the TLS or HTTP layer
    /// for a reason other than certificate trust.
    #[error("the connection to a secure DNS resolver failed")]
    Transport,
    /// A resolver did not complete within the per-upstream budget.
    #[error("a secure DNS resolver did not respond in time")]
    Timeout,
    #[error("could not reach a secure DNS resolver")]
    Unreachable,
}

impl BootstrapError {
    /// Report priority when resolvers fail differently — highest wins, ties
    /// keep the first observed. A resolver that ANSWERED outranks one that
    /// failed to connect: an answer is evidence about the hostname, a failed
    /// connect is only evidence about that one resolver.
    ///
    /// `CertificateRejected` is the deliberate exception: nothing was answered,
    /// yet it names a third party on the path rather than describing our own
    /// reach, so it outranks every answered outcome. Do not "correct" it down
    /// to match the rule above — that would delete the interception signal.
    pub(crate) fn rank(self) -> u8 {
        match self {
            Self::InvalidName => 7, // Short-circuits before the loop; never folded.
            Self::CertificateRejected => 6,
            Self::MalformedReply => 5,
            Self::NoAnswer => 4,
            Self::Transport => 3,
            Self::Timeout => 2,
            Self::Unreachable => 1,
        }
    }
}

/// Map one round-trip failure onto the reported bootstrap error. Total, with no
/// escape hatch: the seam's type admits exactly these six causes.
fn classify(cause: UpstreamCause) -> BootstrapError {
    match cause {
        UpstreamCause::CertificateRejected => BootstrapError::CertificateRejected,
        UpstreamCause::Unreachable => BootstrapError::Unreachable,
        UpstreamCause::Timeout => BootstrapError::Timeout,
        UpstreamCause::TlsFailed | UpstreamCause::BadResponse | UpstreamCause::Io => BootstrapError::Transport,
    }
}

/// Keep `e` if it outranks what we have. Ties keep the first observed.
fn fold_worst(worst: &mut Option<BootstrapError>, e: BootstrapError) {
    if worst.is_none_or(|w| e.rank() > w.rank()) {
        *worst = Some(e);
    }
}

/// A resolver answered with bytes that are not DNS. Logged the moment it
/// happens, even if a later query rescues the resolve — deliberately unlike the
/// answered-but-empty case, which is deferred to the failure tail: an empty
/// answer is ordinary, a non-DNS body is evidence of something rewriting the
/// response and is worth recording either way. `DnsForwarder` already logs its
/// `Err` paths in full; this reply arrives on its `Ok` path, so nothing else
/// records it.
/// Hostname-free — the resolver IP is config, the hostname is not.
fn note_unparseable_reply(server: IpAddr, rtype: RecordType, len: usize) -> BootstrapError {
    tracing::warn!(%server, ?rtype, reply_len = len, "DoH bootstrap: resolver reply is not parseable DNS");
    BootstrapError::MalformedReply
}

/// Build an A-record query for `name` with transaction id `tx_id`.
pub fn build_a_query(name: &str, tx_id: u16) -> Result<Vec<u8>, BootstrapError> {
    build_query(name, tx_id, RecordType::A)
}

/// Build an AAAA-record query for `name` with transaction id `tx_id`.
pub fn build_aaaa_query(name: &str, tx_id: u16) -> Result<Vec<u8>, BootstrapError> {
    build_query(name, tx_id, RecordType::AAAA)
}

fn build_query(name: &str, tx_id: u16, rtype: RecordType) -> Result<Vec<u8>, BootstrapError> {
    let name = Name::from_ascii(format!("{}.", name.trim_end_matches('.'))).map_err(|_| BootstrapError::InvalidName)?;
    // 3-arg `new`; header fields are pub on Metadata, set via `msg.metadata.*`.
    let mut msg = Message::new(tx_id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(name, rtype));
    msg.to_vec().map_err(|_| BootstrapError::InvalidName)
}

/// A resolver's parsed reply.
#[derive(Debug, PartialEq, Eq)]
pub struct DnsReply {
    /// Every A / AAAA address the answer section carried.
    pub addrs: Vec<IpAddr>,
    /// The resolver said the name does not exist AT ALL (NXDOMAIN) — a verdict
    /// about the hostname itself. An empty NOERROR answer is not this: it
    /// speaks only for the record type queried, so an A query returning it
    /// tells us nothing about whether an AAAA exists.
    pub name_missing: bool,
}

/// Parse a wire-format DNS reply. `None` when the bytes do not parse as DNS at
/// all — a resolver answering non-DNS is a finding of its own, not the same as
/// an answerless reply.
pub fn parse_addrs(reply: &[u8]) -> Option<DnsReply> {
    let msg = Message::from_vec(reply).ok()?;
    Some(DnsReply {
        // `record.data` is the pub RData field; `RData::ip_addr()` yields
        // Some(IpAddr) for A/AAAA, None otherwise — no variant match needed.
        addrs: msg.answers.iter().filter_map(|rec| rec.data.ip_addr()).collect(),
        name_missing: msg.response_code == hickory_proto::op::ResponseCode::NXDomain,
    })
}

// Resolver ============================================================================================================

/// One DoH round-trip seam, mockable in tests. The production impl runs the
/// query through a `DnsForwarder` pinned to one resolver IP over a DIRECT
/// connector (tunnel not up); the forwarder derives the DoH URL/SNI internally
/// from `server` via its provider table.
#[async_trait]
pub trait DohQuerier: Send + Sync {
    /// Return the wire-format reply, or why this resolver produced none. A
    /// reply that parses but carries no address is `Ok` — "the resolver
    /// answered" and "the answer was empty" are different findings.
    ///
    /// `UpstreamCause`, not the forwarder's `ForwardFailure`: this seam is ONE
    /// query to ONE resolver, so the walk-level "nothing attempted" and
    /// "malformed query" outcomes are not expressible here and no implementer
    /// can invent them.
    async fn query(&self, server: IpAddr, wire: &[u8]) -> Result<Vec<u8>, UpstreamCause>;
}

/// Forwarder config for one bootstrap round-trip: exactly this resolver, over
/// DoH. The single definition the test queriers reuse, so a change here cannot
/// leave them exercising a shape production no longer has.
fn single_resolver_cfg(server: IpAddr) -> DnsConfig {
    DnsConfig {
        enabled: true,
        servers: vec![server],
        protocol: DnsProtocol::Https,
        allow_insecure_bootstrap: false,
    }
}

/// Run one round-trip through a single-resolver forwarder, narrowing the
/// forwarder's WALK-level failure to this seam's per-query one. `try_forward`
/// is the entry point rather than `forward` because `forward`'s SERVFAIL
/// synthesis would erase which resolver failed and why.
async fn single_round_trip(fwd: &DnsForwarder, wire: &[u8]) -> Result<Vec<u8>, UpstreamCause> {
    match fwd.try_forward(wire, crate::dns::forwarder::UPSTREAM_TIMEOUT).await {
        Ok(reply) => Ok(reply),
        Err(ForwardFailure::Upstream(cause)) => Err(cause),
        // `single_resolver_cfg` supplies exactly one never-skipped server and
        // every caller builds `wire` with `build_query`, so the walk cannot
        // report "nothing attempted" or "malformed query".
        Err(other) => {
            // `debug_assert!` alone would make this silent in release, where
            // the degraded `Unreachable` is indistinguishable from a real
            // connect failure — log first so a broken invariant is visible.
            tracing::error!(
                ?other,
                "single-resolver forward reported an outcome this seam cannot express"
            );
            debug_assert!(false, "single-resolver forward reported {other:?}");
            Err(UpstreamCause::Unreachable)
        }
    }
}

/// Production querier: a `DnsForwarder` over a `DirectConnector`, restricted to
/// a single resolver per call.
struct ForwarderQuerier;

#[async_trait]
impl DohQuerier for ForwarderQuerier {
    async fn query(&self, server: IpAddr, wire: &[u8]) -> Result<Vec<u8>, UpstreamCause> {
        // ipv6_bypass_available=true: bootstrap runs before the tunnel, on the
        // host's real stack, so do not suppress IPv6 resolvers.
        let fwd = DnsForwarder::new(single_resolver_cfg(server), Arc::new(DirectConnector), true);
        single_round_trip(&fwd, wire).await
    }
}

/// What one query leg concluded. Both legs classify identically; only what they
/// do with the conclusion differs, so the classification lives here once.
enum LegOutcome {
    /// A usable address of the family this leg asked for.
    Address(IpAddr),
    /// The resolver answered without one. `name_missing` is its NXDOMAIN
    /// verdict — conclusive about the hostname, unlike an empty NOERROR.
    Answered { name_missing: bool },
    /// No usable reply: the round trip failed, or the bytes were not DNS.
    Failed(BootstrapError),
}

/// Run one query leg against `server` and classify the result. `want` selects
/// the address family this leg asked for.
async fn run_leg(
    querier: &Arc<dyn DohQuerier>,
    server: IpAddr,
    wire: &[u8],
    rtype: RecordType,
    want: fn(&IpAddr) -> bool,
) -> LegOutcome {
    match querier.query(server, wire).await {
        Ok(reply) => match parse_addrs(&reply) {
            Some(parsed) => match parsed.addrs.into_iter().find(want) {
                Some(ip) => LegOutcome::Address(ip),
                None => LegOutcome::Answered {
                    name_missing: parsed.name_missing,
                },
            },
            None => LegOutcome::Failed(note_unparseable_reply(server, rtype, reply.len())),
        },
        Err(cause) => LegOutcome::Failed(classify(cause)),
    }
}

/// A completed bootstrap: the proxy server's address, and which resolver — if
/// any — answered. A caller that needs a resolver known to be reachable from
/// this host must read `via`, not `dns.servers.first()`: this function fails
/// over past dead entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bootstrapped {
    pub server_ip: IpAddr,
    pub via: PinSource,
}

/// Resolve `host` to an IP over the configured DoH `dns.servers`. See the task
/// interface for the fail-closed / `allow_insecure_bootstrap` contract.
pub async fn resolve_via_doh(host: &str, dns: &DnsConfig) -> Result<Bootstrapped, BootstrapError> {
    resolve_via_doh_with(host, dns, Arc::new(ForwarderQuerier)).await
}

/// `resolve_via_doh` with an injected querier (test seam).
pub async fn resolve_via_doh_with(
    host: &str,
    dns: &DnsConfig,
    querier: Arc<dyn DohQuerier>,
) -> Result<Bootstrapped, BootstrapError> {
    // A literal IP needs no resolution — return as-is.
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(Bootstrapped {
            server_ip: ip,
            via: PinSource::NoQueryNeeded,
        });
    }

    // Fixed tx ids: DoH carries the query over an authenticated TLS channel, so
    // transport security — not the 16-bit id — is what defeats off-path spoofing.
    // Build both queries once: a builder failure is an InvalidName (malformed
    // hostname), surfaced as-is rather than masked as NoAnswer by the loop.
    let a_query = build_a_query(host, 0x0001)?;
    let aaaa_query = build_aaaa_query(host, 0x0002)?;

    let mut v6_fallback: Option<Bootstrapped> = None;
    // A resolver that returned a well-formed reply over its verified DoH channel
    // is reachable for DoH, whatever it said about THIS hostname — and that is
    // all the ECH lookup needs from it. Kept so the insecure tail can still pin.
    let mut reachable: Option<IpAddr> = None;
    let mut worst: Option<BootstrapError> = None;
    for &server in &dns.servers {
        // Fold `NoAnswer` only on NXDOMAIN or once BOTH legs answered emptily —
        // a single empty leg proves nothing (e.g. an AAAA-only host's A leg) and
        // folding it there would outrank a real Transport/Timeout/Unreachable
        // finding from the other leg (see `rank`).
        let mut a_answered = false;
        match run_leg(&querier, server, &a_query, RecordType::A, IpAddr::is_ipv4).await {
            // IPv4 preferred for bypass-route compatibility.
            LegOutcome::Address(ip) => {
                return Ok(Bootstrapped {
                    server_ip: ip,
                    via: PinSource::Answered(server),
                })
            }
            LegOutcome::Answered { name_missing } => {
                a_answered = true;
                reachable.get_or_insert(server);
                if name_missing {
                    fold_worst(&mut worst, BootstrapError::NoAnswer);
                }
            }
            LegOutcome::Failed(e) => fold_worst(&mut worst, e),
        }
        if v6_fallback.is_none() {
            match run_leg(&querier, server, &aaaa_query, RecordType::AAAA, IpAddr::is_ipv6).await {
                LegOutcome::Address(ip) => {
                    v6_fallback = Some(Bootstrapped {
                        server_ip: ip,
                        via: PinSource::Answered(server),
                    })
                }
                LegOutcome::Answered { name_missing } => {
                    reachable.get_or_insert(server);
                    if a_answered || name_missing {
                        fold_worst(&mut worst, BootstrapError::NoAnswer);
                    }
                }
                LegOutcome::Failed(e) => fold_worst(&mut worst, e),
            }
        }
    }

    if let Some(bootstrapped) = v6_fallback {
        return Ok(bootstrapped);
    }

    // Fail-closed: report the strongest failure observed. `NoAnswer` covers the
    // degenerate "no resolvers configured" case, where nothing was observed.
    // One line per FAILED bootstrap, naming the strongest finding — emitted
    // here rather than per-reply so a resolve that recovers via AAAA or a later
    // resolver stays silent.
    let failure = worst.unwrap_or(BootstrapError::NoAnswer);
    if !dns.allow_insecure_bootstrap {
        tracing::warn!(
            ?failure,
            resolvers = dns.servers.len(),
            "secure DNS bootstrap failed; refusing to resolve the proxy address (dns.allow_insecure_bootstrap is off)"
        );
        return Err(failure);
    }

    // Opt-in insecure fallback: the OS resolver. Prefer IPv4, same as above. On
    // failure report the DoH finding, not the OS one — the DoH failure is the
    // one the user can act on.
    //
    // This WARN is the ONLY record of the finding on this path: the fallback can
    // succeed, and a successful start shows the user nothing. Spell out the
    // consequence rather than flagging it — a reader of this line is the entire
    // audience for it.
    tracing::warn!(
        ?failure,
        resolvers = dns.servers.len(),
        "secure DNS bootstrap failed; resolving the proxy address over PLAINTEXT system DNS instead \
         (dns.allow_insecure_bootstrap is on). A CertificateRejected finding here means the proxy \
         address was resolved over the same network path that presented an untrusted certificate."
    );
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, 0))
        .await
        .inspect_err(|e| tracing::warn!(kind = ?e.kind(), "plaintext DNS fallback also failed"))
        .map_err(|_| failure)?
        .collect();
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .map(|a| Bootstrapped {
            server_ip: a.ip(),
            via: reachable.map_or(PinSource::SecureBootstrapFailed, PinSource::Answered),
        })
        .ok_or(failure)
}

/// Format a resolved IP as the `server_host` handed to the plugin chain /
/// bypass. garter recombines it as `format!("{host}:{port}")` in chain.rs, so
/// an IPv6 literal MUST be bracketed or the recombined
/// string is an unparseable `addr:port`. V4 is returned plain.
pub fn handoff_host(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    }
}

/// Test-only querier mirroring [`ForwarderQuerier`] but built on the forwarder's
/// extra-root TLS seam + a fixed upstream port, so the loopback-TLS e2e drives
/// the REAL `forward_https` + `DirectConnector` + rustls path against an
/// in-test DoH listener with a self-signed cert.
#[cfg(test)]
pub(crate) fn test_loopback_querier(cert: rustls_pki_types::CertificateDer<'static>, port: u16) -> Arc<dyn DohQuerier> {
    struct LoopbackForwarderQuerier {
        cert: rustls_pki_types::CertificateDer<'static>,
        port: u16,
    }
    #[async_trait]
    impl DohQuerier for LoopbackForwarderQuerier {
        async fn query(&self, server: IpAddr, wire: &[u8]) -> Result<Vec<u8>, UpstreamCause> {
            let cfg = single_resolver_cfg(server);
            let fwd =
                DnsForwarder::new_with_extra_root(cfg, Arc::new(DirectConnector), true, self.cert.clone(), self.port);
            single_round_trip(&fwd, wire).await
        }
    }
    Arc::new(LoopbackForwarderQuerier { cert, port })
}

/// Test-only querier mirroring [`ForwarderQuerier`] exactly — including the
/// PRODUCTION `webpki_roots` trust configuration — with only the upstream port
/// overridden.
#[cfg(test)]
pub(crate) fn test_untrusted_querier(port: u16) -> Arc<dyn DohQuerier> {
    struct UntrustedForwarderQuerier {
        port: u16,
    }
    #[async_trait]
    impl DohQuerier for UntrustedForwarderQuerier {
        async fn query(&self, server: IpAddr, wire: &[u8]) -> Result<Vec<u8>, UpstreamCause> {
            let cfg = single_resolver_cfg(server);
            let fwd = DnsForwarder::new_with_ports(cfg, Arc::new(DirectConnector), true, vec![self.port]);
            single_round_trip(&fwd, wire).await
        }
    }
    Arc::new(UntrustedForwarderQuerier { port })
}

#[cfg(test)]
#[path = "bootstrap_tests.rs"]
mod bootstrap_tests;
