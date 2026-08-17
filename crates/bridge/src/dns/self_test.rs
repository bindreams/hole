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

/// Per-upstream budget for one attempt, before dividing across a walk's
/// width — see [`attempt_budget`].
const PER_ATTEMPT: std::time::Duration = std::time::Duration::from_millis(1500);

/// Per-upstream budget for a walk of `width` upstreams with `remaining` time
/// left on the outer deadline, or `None` if there is not enough left for a
/// real attempt.
///
/// `width == 0` needs no check: a zero-width walk dials nothing and returns
/// immediately regardless of how much time is left, so its budget is
/// irrelevant. Otherwise, checking the DERIVED per-upstream budget rather
/// than `remaining` directly is what makes `remaining == 0` (deadline
/// already passed) return `None` rather than a same-instant, zero-budget
/// "attempt" per upstream in the walk — one that would still count toward
/// `attempts` and log a `budget_ms=0` timeout with no dial behind it.
/// `Duration`'s division is nanosecond-precise, so this only ever rounds a
/// genuinely nonzero `remaining` down to zero when it's under `width`
/// nanoseconds — in practice indistinguishable from the deadline having
/// already passed.
fn attempt_budget(remaining: std::time::Duration, width: usize) -> Option<std::time::Duration> {
    if width == 0 {
        return Some(PER_ATTEMPT);
    }
    let per_upstream = PER_ATTEMPT.min(remaining / width as u32);
    (!per_upstream.is_zero()).then_some(per_upstream)
}

/// Run the forwarder self-test inline. Returns `SelfTestOutcome::Ok` when any
/// well-formed non-SERVFAIL reply comes back within the 3×1500ms / 5s budget,
/// else `Failed`.
///
/// `PER_ATTEMPT` is handed to `try_forward` as the PER-UPSTREAM budget, shrunk
/// so that a whole attempt (one walk of N resolvers) still fits inside what is
/// left of `OUTER_BUDGET`. `ATTEMPTS` is therefore a maximum: the loop stops
/// early rather than overrun. Also writes the canonical `"forwarder self-test
/// ok"` / `"forwarder self-test failed"` log line at `info!`. On failure,
/// additionally emits a `warn!` correlation breadcrumb pointing the reader to
/// the plugin tap (depending on whether it was enabled this run — see
/// `TAP_ENABLED_HINT` / `TAP_DISABLED_HINT`).
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
    const OUTER_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);
    const ATTEMPTS: u32 = 3;

    let Some(&first_server) = servers.first() else {
        info!("forwarder self-test skipped: no servers configured");
        return SelfTestOutcome::Ok { attempts: 0 };
    };

    let query = sample_self_test_query();
    let started = std::time::Instant::now();
    let before = forwarder.upstream_activity();
    // The gate is the forwarder's first user: `build_local_dns` constructs it
    // for this start, and the `Dispatcher` that drives the in-TUN endpoint is
    // not created until the gate passes. The diff is what the run itself moved.
    debug_assert_eq!(
        before,
        crate::dns::forwarder::UpstreamActivity::default(),
        "the self-test gate must be the forwarder's first user"
    );
    // The overall bound is a DEADLINE the loop respects, not a `timeout` around
    // it. A wrapping timeout would cancel — i.e. drop — whichever `forward_one`
    // was in flight, and a dropped future produces no `UpstreamErr`, so that
    // upstream's failure would never be classified or logged. Bounding each
    // attempt by what remains instead means every attempt runs to completion
    // and nothing is discarded.
    let deadline = tokio::time::Instant::now() + OUTER_BUDGET;
    let mut last_err: Option<String> = None;
    // Both latch: the reading spans the whole run, not the last attempt.
    let mut answered = false;
    let mut dialled = false;
    let mut completed: u32 = 0;
    let mut outcome = None;

    for attempt in 1..=ATTEMPTS {
        // Cooperative cancel check between retry attempts.
        if cancel.is_cancelled() {
            outcome = Some(SelfTestOutcome::Cancelled);
            break;
        }
        // The width comes from the forwarder, not from `servers.len()`: it
        // skips IPv6 entries without an IPv6 bypass, and counting those would
        // shrink every surviving upstream's budget while leaving part of the
        // deadline unused. `attempt_budget` stops the walk once there isn't
        // enough of the deadline left for a real attempt.
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let width = forwarder.attempted_upstreams();
        let Some(per_upstream) = attempt_budget(remaining, width) else {
            break;
        };
        // The budget goes down into the forwarder so `forward_one`'s own
        // deadline fires first, producing a classified `UpstreamErr` that
        // `log_upstream_failure` can log. Cancel stays a `select!` arm:
        // drop-on-cancel is the documented single exception in this module,
        // since the forwarder's only in-flight resource is a socket that
        // closes on Drop.
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                outcome = Some(SelfTestOutcome::Cancelled);
                break;
            }
            r = forwarder.try_forward(&query, per_upstream) => r,
        };
        completed = attempt;
        match result {
            Ok(reply) => {
                dialled = true;
                if is_dns_reply_ok(&reply) {
                    outcome = Some(SelfTestOutcome::Ok { attempts: attempt });
                    break;
                }
                // `is_dns_reply_ok` rejects on two independent grounds; say
                // which, so a truncated answer is not reported as a resolver
                // that returned SERVFAIL.
                answered = true;
                last_err = Some(if reply.len() < 12 {
                    format!("a resolver answered with a malformed reply ({} bytes)", reply.len())
                } else {
                    "a resolver answered with SERVFAIL".to_string()
                });
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
                // Once a resolver has answered (even a rejected reply), that
                // is the more informative, positive fact. A later attempt's
                // unrelated failure must not clobber it — `classify_failure`
                // forwards `last_err` verbatim whenever `answered` is set, so
                // letting it drift to "no resolver answered" here would
                // contradict the very reply already observed.
                if !answered {
                    last_err = Some(msg);
                }
            }
        }
    }

    let moved = forwarder.upstream_activity().since(before);
    let elapsed_ms = started.elapsed().as_millis() as u64;
    let outcome = outcome.unwrap_or_else(|| SelfTestOutcome::Failed {
        attempts: completed,
        elapsed_ms,
        reason: classify_failure(
            Observed {
                answered,
                dialled,
                moved,
            },
            last_err.unwrap_or_else(|| format!("no attempt completed within {OUTER_BUDGET:?}")),
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
    /// Not one connection into the tunnel was opened — see
    /// [`ProxyError::NoTunnelConnection`].
    NoConnection,
    /// A connection carried the query and nothing came back — see
    /// [`ProxyError::TunnelSilent`].
    TunnelSilent,
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
    /// At least one upstream was dialled. `false` for a config whose every
    /// server is skipped, or a run with no budget left to start an attempt.
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
///   `NoConnection`/`TunnelSilent`, or `InconclusiveTransport` (a UDP
///   ASSOCIATE that reached the local listener but proved nothing about the
///   plugin either way). `Other` means the transport is proven healthy (a
///   reply arrived and was rejected) or was never exercised (nothing
///   dialled) — quoting the plugin there would blame it for a failure that
///   is not its own.
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
        SelfTestReason::NoConnection | SelfTestReason::TunnelSilent | SelfTestReason::InconclusiveTransport(_)
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
