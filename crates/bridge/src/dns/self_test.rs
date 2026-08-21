//! The start-time DNS forwarder self-test gate: builds the in-TUN endpoint +
//! forwarder, runs a bounded probe query through it, and classifies a failure
//! into one of the three claims `start_inner`'s toast/`bridge.log` may make.
//! See `CLAUDE.md` ("DNS forwarder") for the architectural context.
//!
//! Self-contained: only `proxy_manager::start_inner` calls into this module,
//! and it only calls back into `crate::dns::forwarder` / `crate::proxy`.

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::dns::forwarder::ForwardFailure;
use crate::proxy::ProxyError;

/// Build the in-TUN DNS endpoint + forwarder, if the config enables it. The
/// forwarder's upstream runs via [`crate::dns::socks5_connector::Socks5Connector`]
/// targeting the just-started SS SOCKS5 listener, so user filter rules
/// cannot strand our own queries.
///
/// Returns the `forwarder` Arc alongside the endpoint so the blocking
/// self-test gate in `start_inner` can call `forwarder.forward(...)` without
/// re-plumbing.
///
/// Rejects the `dns.enabled && servers.is_empty()` config combination with
/// `ForwarderSelfTestFailed { reason: "no DNS servers configured" }` because
/// that combination would otherwise produce a degenerate runtime (TUN routes
/// go live but the forwarder has nothing to forward to).
pub(crate) async fn build_local_dns(
    dns_cfg: &hole_common::config::DnsConfig,
    local_ss_port: u16,
    ipv6_bypass_available: bool,
    _cancel: CancellationToken,
) -> Result<
    (
        Option<crate::endpoint::LocalDnsEndpoint>,
        Option<std::sync::Arc<crate::dns::forwarder::DnsForwarder>>,
    ),
    ProxyError,
> {
    if !dns_cfg.enabled {
        return Ok((None, None));
    }
    if dns_cfg.servers.is_empty() {
        // Hard error: the only sensible recovery is to disable the forwarder.
        // A live TUN with no upstream would strand every in-tunnel UDP/53
        // flow at the LocalDnsEndpoint with nothing to forward to.
        return Err(ProxyError::ForwarderSelfTestFailed {
            reason: "no DNS servers configured".into(),
            attempts: 0,
            elapsed_ms: 0,
        });
    }

    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    let socks_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), local_ss_port);
    let connector = Arc::new(crate::dns::socks5_connector::Socks5Connector::new(socks_addr))
        as Arc<dyn crate::dns::connector::UpstreamConnector>;
    let forwarder = Arc::new(crate::dns::forwarder::DnsForwarder::new(
        dns_cfg.clone(),
        connector,
        ipv6_bypass_available,
    ));

    // The in-TUN endpoint is the sole OS DNS path: OS DNS routes into hole-tun
    // and is intercepted here, not via a loopback :53 server.
    let endpoint = crate::endpoint::LocalDnsEndpoint::new(Arc::clone(&forwarder));

    Ok((Some(endpoint), Some(forwarder)))
}

/// Hint logged on self-test failure when the plugin tap IS enabled.
/// Tells the reader where the per-connection diagnostic lines are.
pub(crate) const TAP_ENABLED_HINT: &str =
    "DNS self-test failed with plugin tap enabled; check 'plugin tap: closed' lines above for per-connection bytes_to_plugin / bytes_from_plugin / ttfb_ms / close_kind";

/// Hint logged on self-test failure when the plugin tap is NOT enabled. Points
/// at the diagnostics this run already produced; the tap is an offer, not a
/// prerequisite. Emitted from `run_forwarder_self_test`, which does not know
/// whether a plugin is configured, so it must read true either way.
pub(crate) const TAP_DISABLED_HINT: &str =
    "DNS self-test failed; the 'upstream failed' lines above carry the layer, cause and byte counts for every attempt. For per-connection byte flow through a plugin chain, set diagnostic_plugin_tap=true in AppConfig and restart the bridge";

/// Run the forwarder self-test inline: one walk, giving every configured
/// resolver [`crate::dns::forwarder::TUNNEL_QUERY_TIMEOUT`] — the identical
/// call [`crate::dns::forwarder::DnsForwarder::forward`] makes, so the gate
/// can never be looser than what the runtime forwarder will then do. Returns
/// `SelfTestOutcome::Ok` when any well-formed non-SERVFAIL reply comes back,
/// else `Failed`.
///
/// No retry: at the shipped default of two-or-more resolvers, a single walk
/// already contains one independent dial per resolver, so a retry's only
/// unique contribution is at a single-resolver config — while its cost would
/// fall on tunnels that are slow but working, which is the cohort this gate
/// exists to stop mis-reporting. See the PR body for the full accounting.
///
/// Also writes the canonical `"forwarder self-test ok"` / `"forwarder
/// self-test failed"` log line at `info!`. On failure, additionally emits a
/// `warn!` correlation breadcrumb pointing the reader to the plugin tap
/// (depending on whether it was enabled this run — see `TAP_ENABLED_HINT` /
/// `TAP_DISABLED_HINT`).
///
/// A blocking gate: called from `start_inner` BEFORE `Dispatcher::new` /
/// `routing.install` / `Dns::apply`. A failure short-circuits the start;
/// the locally-owned `running_proxy` + `plugin_chain` RAII guards unwind
/// without ever hijacking system DNS into a dead tunnel.
pub(crate) async fn run_forwarder_self_test(
    forwarder: std::sync::Arc<crate::dns::forwarder::DnsForwarder>,
    servers: Vec<std::net::IpAddr>,
    diagnostic_tap_enabled: bool,
    cancel: CancellationToken,
) -> SelfTestOutcome {
    let Some(&first_server) = servers.first() else {
        info!("forwarder self-test skipped: no servers configured");
        return SelfTestOutcome::Ok { attempts: 0 };
    };

    let query = sample_self_test_query();
    // A `tokio::time::Instant`, not `std::time::Instant`: `try_forward`'s own
    // budget below is virtual-time, and mixing clocks made `elapsed_ms`
    // unmeasurable under `tokio::time::pause()` in tests without affecting
    // production.
    let started = tokio::time::Instant::now();
    let before = forwarder.upstream_activity();
    // The gate is the forwarder's first user: `build_local_dns` constructs it
    // for this start, and the `Dispatcher` that drives the in-TUN endpoint is
    // not created until the gate passes. The diff is what the run itself moved.
    debug_assert_eq!(
        before,
        crate::dns::forwarder::UpstreamActivity::default(),
        "the self-test gate must be the forwarder's first user"
    );
    // Both latch: the reading spans the whole run, not just the walk's result.
    let mut last_err: Option<String> = None;
    let mut answered = false;
    let mut dialled = false;
    let mut attempts: u32 = 0;
    let mut outcome = None;

    // The budget goes down into the forwarder so `forward_one`'s own deadline
    // fires first, producing a classified `UpstreamErr` that
    // `log_upstream_failure` can log. Cancel stays a `select!` arm:
    // drop-on-cancel is the documented single exception in this module, since
    // the forwarder's only in-flight resource is a socket that closes on
    // Drop. No wrapping `timeout` around the whole call either, for the same
    // reason: it would drop whichever `forward_one` was in flight, and a
    // dropped future produces no `UpstreamErr`.
    let result = tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            outcome = Some(SelfTestOutcome::Cancelled);
            None
        }
        r = forwarder.try_forward(&query, crate::dns::forwarder::TUNNEL_QUERY_TIMEOUT) => Some(r),
    };

    if let Some(result) = result {
        attempts = 1;
        match result {
            Ok(reply) => {
                dialled = true;
                if is_dns_reply_ok(&reply) {
                    outcome = Some(SelfTestOutcome::Ok { attempts });
                } else {
                    // `is_dns_reply_ok` rejects on two independent grounds;
                    // say which, so a truncated answer is not reported as a
                    // resolver that returned SERVFAIL.
                    answered = true;
                    last_err = Some(if reply.len() < 12 {
                        format!("a resolver answered with a malformed reply ({} bytes)", reply.len())
                    } else {
                        "a resolver answered with SERVFAIL".to_string()
                    });
                }
            }
            Err(failure) => {
                let msg = match failure {
                    ForwardFailure::NoUpstream => "no configured DNS resolver could be used".to_string(),
                    ForwardFailure::MalformedQuery => {
                        unreachable!("the self-test's own query is always at least a DNS header")
                    }
                    ForwardFailure::Upstream(cause) => {
                        dialled = true;
                        describe_upstream_failure(cause)
                    }
                };
                // `answered` can only be set in the `Ok` arm above, mutually
                // exclusive with this one, so the guard is unconditionally
                // true for a single walk — kept structural, not collapsed,
                // because it must reactivate the instant a retry returns.
                if !answered {
                    last_err = Some(msg);
                }
            }
        }
    }

    let moved = forwarder.upstream_activity().since(before);
    let elapsed_ms = started.elapsed().as_millis() as u64;
    // Reaching `Failed` with no `last_err` would mean the walk above neither
    // succeeded nor classified a failure — every arm sets one or the other,
    // so this is a contract check, not a real fallback.
    debug_assert!(
        outcome.is_some() || last_err.is_some(),
        "a walk that ran must have classified an answer or a failure"
    );
    let outcome = outcome.unwrap_or_else(|| SelfTestOutcome::Failed {
        attempts,
        elapsed_ms,
        reason: classify_failure(
            Observed {
                answered,
                dialled,
                moved,
            },
            last_err.unwrap_or_else(|| "no attempt completed".to_string()),
        ),
    });

    match &outcome {
        SelfTestOutcome::Ok { attempts } => {
            info!(%first_server, attempts, elapsed_ms, "forwarder self-test ok");
        }
        SelfTestOutcome::Failed { attempts, reason, .. } => {
            let reason = match reason {
                SelfTestReason::NoConnection => "no connection into the tunnel was opened",
                SelfTestReason::TunnelSilent => "nothing came back through the tunnel",
                SelfTestReason::TunnelSetupPending => "the tunnel was still being set up when the attempt ran out",
                SelfTestReason::InconclusiveTransport(s) | SelfTestReason::Other(s) => s.as_str(),
            };
            info!(
                %first_server,
                attempts,
                elapsed_ms,
                reason,
                bytes_to_upstream = moved.written,
                bytes_from_upstream = moved.read,
                "forwarder self-test failed"
            );
            if diagnostic_tap_enabled {
                warn!("{TAP_ENABLED_HINT}");
            } else {
                warn!("{TAP_DISABLED_HINT}");
            }
        }
        SelfTestOutcome::Cancelled => {
            info!(%first_server, elapsed_ms, "forwarder self-test cancelled");
        }
    }
    outcome
}

/// Why the self-test failed, in the terms its report is allowed to claim.
#[derive(Debug)]
pub(crate) enum SelfTestReason {
    /// Not one connection into the tunnel was opened, AND every attempt to
    /// open one failed definitely — see [`ProxyError::NoTunnelConnection`].
    /// The second half is load-bearing: an attempt still outstanding when its
    /// budget fired is [`Self::TunnelSetupPending`], not this.
    NoConnection,
    /// A connection carried the query and nothing came back — see
    /// [`ProxyError::TunnelSilent`].
    TunnelSilent,
    /// Nothing was established, and at least one attempt's budget fired with
    /// its connect STILL OUTSTANDING — see [`ProxyError::TunnelSetupIncomplete`].
    /// Distinct from `NoConnection`, which needs every connect failure to have
    /// been definite: a SOCKS5 CONNECT is not acknowledged until the plugin's
    /// own outer connection is up, so an outstanding one is the tunnel still
    /// being set up, not the local proxy turning us away. The plugin is not
    /// exonerated, so the report still quotes it.
    TunnelSetupPending,
    /// A UDP ASSOCIATE completed — the local SOCKS5 listener did accept
    /// something — but nothing came back. Weaker evidence than
    /// `TunnelSilent` (an ASSOCIATE never reaches the plugin, so it proves
    /// nothing about it) and so makes neither positive claim on the toast —
    /// the string carries the same `ForwarderSelfTestFailed` sentence
    /// `Other` does — but unlike `Other`, nothing here has EXONERATED the
    /// plugin transport either, so the report still quotes it.
    InconclusiveTransport(String),
    /// Something answered, or nothing was dialled; carries the sentence for
    /// the toast. The transport is proven healthy or was never exercised —
    /// quoting the plugin here would misattribute someone else's failure.
    Other(String),
}

/// What one self-test run observed. Every field spans the WHOLE run — `moved`
/// accumulates over attempts and upstreams, the flags latch — so the three are
/// one granularity and none can be read against another's scope.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Observed {
    /// A reply arrived at some point and was rejected (SERVFAIL, or too short
    /// to be a reply).
    pub(crate) answered: bool,
    /// At least one upstream was dialled. `false` only for a config whose
    /// every server is skipped (all-IPv6 with no bypass) — a cancel fires
    /// before the walk starts and short-circuits to `Cancelled` instead of
    /// reaching `classify_failure` at all.
    pub(crate) dialled: bool,
    /// What the forwarder did during the run.
    pub(crate) moved: crate::dns::forwarder::UpstreamActivity,
}

/// Render a transport-layer `UpstreamCause` as the self-test's own reading of
/// it. Three causes imply a peer answered at some layer even though no valid
/// DNS reply resulted — wording those as "no resolver answered" would
/// contradict the byte counts logged right next to this string.
pub(crate) fn describe_upstream_failure(cause: crate::dns::forwarder::UpstreamCause) -> String {
    use crate::dns::forwarder::UpstreamCause;
    match cause {
        UpstreamCause::BadResponse | UpstreamCause::CertificateRejected | UpstreamCause::TlsFailed => {
            format!("a resolver responded, but the exchange failed ({cause})")
        }
        // A connect that never completed is not silence FROM a resolver — no
        // connection to one was ever opened. Saying "no resolver answered"
        // would claim we got as far as asking.
        UpstreamCause::ConnectTimeout => {
            format!("no connection to a resolver could be opened through the tunnel ({cause})")
        }
        UpstreamCause::Unreachable | UpstreamCause::Io | UpstreamCause::ExchangeTimeout => {
            format!("no resolver answered through the tunnel ({cause})")
        }
    }
}

/// Should the plugin's ring be quoted next to this failure? Two conditions
/// both apply, checked independently rather than off one collapsed value:
///
/// - The self-test's OWN reading implicates the transport —
///   `NoConnection`/`TunnelSilent`/`TunnelSetupPending`, or
///   `InconclusiveTransport` (a UDP ASSOCIATE that reached the local listener
///   but proved nothing about the plugin either way). `TunnelSetupPending` is
///   in that set because a connect still outstanding when its budget fired is
///   precisely the plugin's own outer connection not being up yet — the case
///   where the plugin's log IS the answer. `Other` means the transport is
///   proven healthy (a reply arrived and was rejected) or was never exercised
///   (nothing dialled) — quoting the plugin there would blame it for a failure
///   that is not its own.
/// - The out-of-band probe hasn't already reattributed the failure to the
///   network path. `self_test_error_for` lets a `Blocked`/`TcpRefused`/
///   `TcpTimeout` verdict replace the self-test's own reading entirely
///   (`NetworkBlocked`, or a rewritten `ForwarderSelfTestFailed`); quoting
///   the plugin beside a failure the code has attributed elsewhere would
///   misattribute it. Checked directly against `verdict` rather than
///   against `self_test_error_for`'s output, because `InconclusiveTransport`
///   and `Other` both collapse to the same `ForwarderSelfTestFailed` shape
///   there — the FINAL `ProxyError` alone can no longer tell them apart.
pub(crate) fn implicates_plugin_transport(
    reason: &SelfTestReason,
    verdict: Option<crate::reachability::ReachabilityVerdict>,
) -> bool {
    use crate::reachability::ReachabilityVerdict::*;
    let reason_implicates = matches!(
        reason,
        SelfTestReason::NoConnection
            | SelfTestReason::TunnelSilent
            | SelfTestReason::TunnelSetupPending
            | SelfTestReason::InconclusiveTransport(_)
    );
    let verdict_overrides = matches!(verdict, Some(Blocked | TcpRefused | TcpTimeout));
    reason_implicates && !verdict_overrides
}

/// Emit the plugin chain's kept output for a failed gate, or say there is no
/// chain to quote. `bridge.log` only — these lines can name the server host.
pub(crate) fn report_plugin_output(log: Option<&crate::proxy::plugin_log::PluginLog>) {
    match log {
        Some(log) => crate::proxy::plugin_log::warn_recent(log),
        None => warn!("{}", crate::proxy::plugin_log::NO_PLUGIN_CONFIGURED),
    }
}

/// Turn a reading into the claim the report may make. Every claim rests on a
/// positive observation, never on a cause code: a local hop that HANGS never
/// reaches `UpstreamLayer::Connect`, so its cause is `ConnectTimeout`, and
/// splitting on `Unreachable` would file it under the tunnel sentence.
///
/// The local-hop claim keys on `connects`, not on `written` — see
/// [`crate::dns::forwarder::UpstreamActivity`] for why a reset before the first
/// write still counts as a connection. A UDP ASSOCIATE (`associates`) is
/// weaker evidence than a CONNECT and must not be read as either claim: it
/// disproves `NoConnection` (the local SOCKS5 listener did accept something)
/// without being strong enough to support `TunnelSilent` (it says nothing
/// about the plugin), so it falls through to `Other`.
///
/// `last_err` is trustworthy verbatim only in the `answered` case — the
/// `Ok(reply)` arm sets it in the same step it latches `answered`, and the
/// loop pins it there so a later attempt's failure can't overwrite it (see
/// `run_forwarder_self_test`). `moved.read` has no such message attached to
/// it: it can be positive from an attempt whose own completion never
/// reached `is_dns_reply_ok` (a peer that replies partially then resets),
/// so `last_err` there could still be a DIFFERENT, later "no resolver
/// answered" message — reporting it verbatim would contradict the very
/// byte counts logged beside it, so a neutral phrase is used instead.
pub(crate) fn classify_failure(observed: Observed, last_err: String) -> SelfTestReason {
    if !observed.dialled {
        return SelfTestReason::Other(last_err);
    }
    if observed.answered {
        return SelfTestReason::Other(last_err);
    }
    if observed.moved.read > 0 {
        return SelfTestReason::Other("a resolver responded, but the exchange failed".to_string());
    }
    if observed.moved.connects > 0 {
        SelfTestReason::TunnelSilent
    } else if observed.moved.associates > 0 {
        SelfTestReason::InconclusiveTransport(last_err)
    } else if observed.moved.connect_timeouts > 0 {
        // Sits BELOW the byte/connect/associate arms on purpose: those are
        // positive evidence that something was established, and an outstanding
        // connect is the absence of it. Above `NoConnection`, because that
        // variant's claim — nothing was opened and every failure was definite —
        // is false once an attempt was still in flight when its budget fired.
        SelfTestReason::TunnelSetupPending
    } else {
        SelfTestReason::NoConnection
    }
}

#[derive(Debug)]
pub(crate) enum SelfTestOutcome {
    Ok {
        attempts: u32,
    },
    Failed {
        attempts: u32,
        elapsed_ms: u64,
        reason: SelfTestReason,
    },
    /// The bridge cancel token fired before the self-test could complete
    /// or fail definitively. Maps to `ProxyError::Cancelled`; not a
    /// diagnostic failure (the user asked for it).
    Cancelled,
}

/// Map a self-test failure to the `ProxyError` the toast sees, given the
/// out-of-band reachability `verdict` (`None` when the probe was skipped). A
/// `Blocked` verdict becomes the typed [`ProxyError::NetworkBlocked`];
/// `TcpRefused`/`TcpTimeout` rewrite the reason to the probe's `user_message`.
///
/// The precedence is deliberate and total: whenever the server's own port is
/// refused or unanswered, the probe's sentence replaces
/// [`ProxyError::TunnelSilent`] / [`ProxyError::NoTunnelConnection`] entirely.
/// Those two surface only when the probe reported `Reachable` / `DnsFailed` /
/// `Inconclusive`, or was suppressed by an active fail-closed cover.
pub(crate) fn self_test_error_for(
    verdict: Option<crate::reachability::ReachabilityVerdict>,
    attempts: u32,
    elapsed_ms: u64,
    reason: SelfTestReason,
) -> ProxyError {
    use crate::reachability::ReachabilityVerdict::*;
    match verdict {
        Some(Blocked) => ProxyError::NetworkBlocked,
        Some(v @ (TcpRefused | TcpTimeout)) => ProxyError::ForwarderSelfTestFailed {
            attempts,
            elapsed_ms,
            reason: v
                .user_message()
                .expect("TcpRefused/TcpTimeout always carry a user_message")
                .to_owned(),
        },
        _ => match reason {
            SelfTestReason::NoConnection => ProxyError::NoTunnelConnection { attempts, elapsed_ms },
            SelfTestReason::TunnelSilent => ProxyError::TunnelSilent { attempts, elapsed_ms },
            SelfTestReason::TunnelSetupPending => ProxyError::TunnelSetupIncomplete { attempts, elapsed_ms },
            SelfTestReason::InconclusiveTransport(reason) | SelfTestReason::Other(reason) => {
                ProxyError::ForwarderSelfTestFailed {
                    attempts,
                    elapsed_ms,
                    reason,
                }
            }
        },
    }
}

/// Treat "any well-formed DNS reply that isn't SERVFAIL" as success.
/// The reply header is 12 bytes; RCODE lives in the low nibble of byte 3
/// (RFC 1035 §4.1.1). RCODE 2 = SERVFAIL (upstream failed explicitly);
/// all other RCODEs (NoError, NXDOMAIN, REFUSED) mean the path works.
pub(crate) fn is_dns_reply_ok(reply: &[u8]) -> bool {
    reply.len() >= 12 && (reply[3] & 0x0F) != 2
}

/// Build a minimal wire-format DNS query: `example.com A`. Used by
/// [`run_forwarder_self_test`] — hardcoded hostname is acceptable
/// because the forwarder self-test is an internal probe, never a user-
/// visible config. NXDOMAIN on this name still proves the path works.
pub(crate) fn sample_self_test_query() -> Vec<u8> {
    let mut q = Vec::with_capacity(32);
    q.extend_from_slice(&0x0001_u16.to_be_bytes()); // id
    q.extend_from_slice(&[0x01, 0x00]); // flags: RD=1
    q.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    q.push(7);
    q.extend_from_slice(b"example");
    q.push(3);
    q.extend_from_slice(b"com");
    q.push(0);
    q.extend_from_slice(&[0x00, 0x01]); // QTYPE=A
    q.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN
    q
}

#[cfg(test)]
#[path = "self_test_tests.rs"]
mod self_test_tests;
