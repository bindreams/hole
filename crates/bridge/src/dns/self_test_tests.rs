// `CancellationToken::new` is pervasive across these tests as the test
// harness's root signal; module-level allow per clippy.toml's
// "Bridge cancellation contract" sanctioned-test-file exception.
#![allow(clippy::disallowed_methods)]

use super::*;
use crate::dns::forwarder::{DnsForwarder, UpstreamActivity, UpstreamCause};
use crate::reachability::ReachabilityVerdict;
use crate::test_support::log_capture::VecWriter;
use crate::test_support::refusing_connector::{
    GatedConnector, HangThenAnswer, HangingConnector, RefusingConnector, SilentConnector,
};
use hole_common::config::{DnsConfig, DnsProtocol};
use std::sync::Arc as SArc;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::{Layer, SubscriberExt};

fn test_dns_cfg() -> DnsConfig {
    DnsConfig {
        enabled: true,
        servers: vec!["127.0.0.1".parse().unwrap()],
        protocol: DnsProtocol::PlainTcp,
        allow_insecure_bootstrap: false,
    }
}

/// Bind a UDP socket that answers every datagram with a SERVFAIL built from
/// it. A resolver that answered — the case that must never be reported as a
/// silent tunnel.
async fn servfail_udp_stub() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 512];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            let reply = crate::dns::forwarder::synthesize_servfail(&buf[..n]);
            let _ = sock.send_to(&reply, peer).await;
        }
    });
    (addr, handle)
}

/// Every branch of the classifier, including the ones that must NOT claim a
/// silent tunnel. The condition decides which of three sentences a user
/// reads, so each arm is pinned rather than inferred from one case.
#[skuld::test]
fn classify_failure_covers_every_branch() {
    let no_connection = UpstreamActivity::default();
    let wrote_only = UpstreamActivity {
        read: 0,
        written: 44,
        connects: 1,
        associates: 0,
        connect_timeouts: 0,
    };
    // Connected, then reset before the first write.
    let connected_only = UpstreamActivity {
        read: 0,
        written: 0,
        connects: 1,
        associates: 0,
        connect_timeouts: 0,
    };
    let both = UpstreamActivity {
        read: 91,
        written: 44,
        connects: 1,
        associates: 0,
        connect_timeouts: 0,
    };
    // A completed UDP ASSOCIATE, but no reply — weaker than a CONNECT.
    let associated_only = UpstreamActivity {
        read: 0,
        written: 44,
        connects: 0,
        associates: 1,
        connect_timeouts: 0,
    };
    // Nothing established, and an attempt was still outstanding when its
    // budget fired.
    let pending_connect = UpstreamActivity {
        read: 0,
        written: 0,
        connects: 0,
        associates: 0,
        connect_timeouts: 1,
    };
    let case = |answered, dialled, moved| {
        classify_failure(
            Observed {
                answered,
                dialled,
                moved,
            },
            "reason".to_string(),
        )
    };

    // The query reached the tunnel and nothing returned.
    assert!(matches!(case(false, true, wrote_only), SelfTestReason::TunnelSilent));
    // The tunnel took the connection and died before the first write. Zero
    // bytes, but the connect disproves a local-hop claim.
    assert!(matches!(
        case(false, true, connected_only),
        SelfTestReason::TunnelSilent
    ));
    // No connection was established and every connect failure was DEFINITE.
    // The readings for "refused" and "still outstanding when the budget fired"
    // deliberately differ — so this fixture carries no `connect_timeouts` and
    // the next case carries one.
    assert!(matches!(case(false, true, no_connection), SelfTestReason::NoConnection));
    // Nothing established, but an attempt was still in flight when its budget
    // fired: the tunnel was coming up, not refusing us.
    assert!(matches!(
        case(false, true, pending_connect),
        SelfTestReason::TunnelSetupPending
    ));
    // A UDP ASSOCIATE completed but nothing came back: disproves
    // NoConnection (the local listener DID accept something) without
    // being TunnelSilent-grade evidence about the plugin, so neither
    // positive claim is made — but the plugin is not exonerated either.
    assert!(matches!(
        case(false, true, associated_only),
        SelfTestReason::InconclusiveTransport(_)
    ));
    // A reply arrived and was rejected — the tunnel is not silent.
    assert!(matches!(case(true, true, both), SelfTestReason::Other(_)));
    // Bytes came back even though the walk failed.
    assert!(matches!(case(false, true, both), SelfTestReason::Other(_)));
    // Nothing was dialled: a config fault, not a reading of the tunnel.
    assert!(matches!(case(false, false, no_connection), SelfTestReason::Other(_)));
}

/// A transport that never completed its connect must not be reported as a
/// local proxy refusing connections: the SOCKS5 CONNECT is not acknowledged
/// until the plugin's own outer connection is up, so an outstanding one means
/// the tunnel was still coming up.
#[skuld::test]
fn a_pending_connect_is_not_reported_as_no_connection() {
    let reason = classify_failure(
        Observed {
            answered: false,
            dialled: true,
            moved: UpstreamActivity {
                read: 0,
                written: 0,
                connects: 0,
                associates: 0,
                connect_timeouts: 1,
            },
        },
        "reason".to_string(),
    );
    assert!(matches!(reason, SelfTestReason::TunnelSetupPending), "got {reason:?}");
}

/// The other half of the split, which must stay true: with every connect
/// failure DEFINITE, the reading is still `NoConnection`.
#[skuld::test]
fn a_definite_connect_failure_is_still_reported_as_no_connection() {
    let reason = classify_failure(
        Observed {
            answered: false,
            dialled: true,
            moved: UpstreamActivity::default(),
        },
        "reason".to_string(),
    );
    assert!(matches!(reason, SelfTestReason::NoConnection), "got {reason:?}");
}

/// Positive evidence still wins. A completed CONNECT proves something was
/// established, so a pending connect elsewhere in the same run must not
/// downgrade the reading away from `TunnelSilent`.
#[skuld::test]
fn positive_byte_evidence_still_outranks_a_pending_connect() {
    let reason = classify_failure(
        Observed {
            answered: false,
            dialled: true,
            moved: UpstreamActivity {
                read: 0,
                written: 44,
                connects: 1,
                associates: 0,
                connect_timeouts: 1,
            },
        },
        "reason".to_string(),
    );
    assert!(matches!(reason, SelfTestReason::TunnelSilent), "got {reason:?}");
}

/// A pending connect does NOT exonerate the plugin, so the report still quotes
/// its output — unless the out-of-band probe has already attributed the failure
/// to the network, which outranks anything the gate could conclude.
#[skuld::test]
fn a_pending_connect_still_implicates_the_plugin_transport() {
    assert!(implicates_plugin_transport(&SelfTestReason::TunnelSetupPending, None));
    for verdict in [
        ReachabilityVerdict::Blocked,
        ReachabilityVerdict::TcpRefused,
        ReachabilityVerdict::TcpTimeout,
    ] {
        assert!(
            !implicates_plugin_transport(&SelfTestReason::TunnelSetupPending, Some(verdict)),
            "{verdict:?} attributes the failure elsewhere, so the plugin must not be quoted"
        );
    }
}

/// The reading maps to its own error, and a damning probe verdict still
/// outranks it.
#[skuld::test]
fn tunnel_setup_incomplete_maps_to_its_own_error() {
    let err = self_test_error_for(None, 3, 20_000, SelfTestReason::TunnelSetupPending);
    assert!(
        matches!(
            err,
            ProxyError::TunnelSetupIncomplete {
                attempts: 3,
                elapsed_ms: 20_000
            }
        ),
        "got {err:?}"
    );
    let blocked = self_test_error_for(
        Some(ReachabilityVerdict::Blocked),
        3,
        20_000,
        SelfTestReason::TunnelSetupPending,
    );
    assert!(matches!(blocked, ProxyError::NetworkBlocked), "got {blocked:?}");
}

/// The sentence names a slow server AND an unreachable one and picks neither —
/// a pending connect is equally consistent with both, and telling a censored
/// user to wait would be the same class of misattribution this variant removes.
/// Only integers are interpolated, so nothing host-shaped can reach a toast.
#[skuld::test]
fn tunnel_setup_incomplete_message_is_pii_free_and_names_both_causes() {
    let err = ProxyError::TunnelSetupIncomplete {
        attempts: 3,
        elapsed_ms: 20_000,
    };
    let text = err.to_string();
    assert!(text.contains("slow"), "got: {text}");
    assert!(text.contains("unreachable"), "got: {text}");
    assert!(
        !text.contains('/') && !text.contains('\\'),
        "no path may appear: {text}"
    );
    assert!(
        !text.contains("127.0.0.1") && !text.contains("1.1.1.1"),
        "no address may appear: {text}"
    );
}

/// Regression: a peer that replies partially then resets (e.g. `Io`) counts
/// `read > 0` without ever setting `answered` (its own attempt never reached
/// `is_dns_reply_ok`). `last_err` in that case may describe a DIFFERENT,
/// later failure ("no resolver answered") — reporting it verbatim would
/// contradict the very byte counts logged beside it, so the message must be
/// the neutral, always-true phrase instead of the passed-in `last_err`.
#[skuld::test]
fn read_without_answered_overrides_a_stale_no_resolver_answered_message() {
    let moved = UpstreamActivity {
        read: 47,
        written: 12,
        connects: 1,
        associates: 0,
        connect_timeouts: 0,
    };
    let reason = classify_failure(
        Observed {
            answered: false,
            dialled: true,
            moved,
        },
        "no resolver answered through the tunnel (io)".to_string(),
    );
    match reason {
        SelfTestReason::Other(s) => assert!(
            !s.contains("no resolver answered"),
            "47 bytes came back; the message must not claim silence, got: {s}"
        ),
        other => panic!("expected Other, got {other:?}"),
    }
}

/// An earlier upstream in the walk carried the query; a later one could not
/// connect. The reading is cumulative, so the bytes that reached the tunnel
/// still decide — reporting the local hop here would contradict the counters.
#[skuld::test]
fn bytes_from_an_earlier_attempt_still_decide() {
    let reason = classify_failure(
        Observed {
            answered: false,
            dialled: true,
            moved: UpstreamActivity {
                read: 0,
                written: 44,
                connects: 1,
                associates: 0,
                connect_timeouts: 0,
            },
        },
        "no resolver answered through the tunnel (unreachable)".into(),
    );
    assert!(matches!(reason, SelfTestReason::TunnelSilent), "got {reason:?}");
}

/// The load-bearing report. A tunnel that swallows the query and answers
/// nothing is what a dead plugin transport looks like from here, and the
/// message must say that instead of blaming the DNS self-test.
#[skuld::test]
fn a_silent_tunnel_is_reported_as_a_silent_tunnel() {
    let outcome = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let (connector, connected_rx) = SilentConnector::new();
            let forwarder = SArc::new(DnsForwarder::new(test_dns_cfg(), connector, false));
            let run = tokio::spawn(run_forwarder_self_test(
                forwarder,
                vec!["127.0.0.1".parse().unwrap()],
                false,
                CancellationToken::new(),
            ));
            connected_rx.await.expect("the stub connector completed a connect");
            tokio::time::pause();
            run.await.unwrap()
        });

    let SelfTestOutcome::Failed { attempts, reason, .. } = outcome else {
        panic!("expected Failed, got {outcome:?}");
    };
    assert!(matches!(reason, SelfTestReason::TunnelSilent), "got {reason:?}");

    let err = self_test_error_for(Some(ReachabilityVerdict::Reachable), attempts, 4517, reason);
    assert_eq!(
        err.to_string(),
        "Nothing came back through the tunnel (4517ms). \
         Either the proxy connection could not be established, \
         or the server cannot reach your DNS resolver."
    );
    // Only integers are interpolated, so nothing host-shaped can reach a toast.
    assert!(!err.to_string().contains("127.0.0.1"), "got: {err}");
}

/// A connect that never completes: the local hop, not `TunnelSilent` — see
/// [`ProxyError::NoTunnelConnection`].
#[skuld::test]
fn a_refused_local_hop_is_reported_as_no_connection() {
    let outcome = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let forwarder = SArc::new(DnsForwarder::new(test_dns_cfg(), RefusingConnector::all(), false));
            run_forwarder_self_test(
                forwarder,
                vec!["127.0.0.1".parse().unwrap()],
                false,
                CancellationToken::new(),
            )
            .await
        });
    let SelfTestOutcome::Failed { attempts, reason, .. } = outcome else {
        panic!("expected Failed, got {outcome:?}");
    };
    assert!(matches!(reason, SelfTestReason::NoConnection), "got {reason:?}");
    let err = self_test_error_for(None, attempts, 4517, reason);
    assert_eq!(
        err.to_string(),
        "Could not open a connection into the tunnel (4517ms). \
         Every attempt to open one failed outright."
    );
    assert!(
        !err.to_string().contains("local proxy"),
        "the Connect layer flattens a local refusal and a SOCKS5 error reply about the \
         REMOTE hop into one io::Error, so this sentence must attribute no side; got: {err}"
    );
}

/// Regression: `shadowsocks-service` answers a UDP ASSOCIATE purely
/// locally, without touching the plugin — unlike a SOCKS5 CONNECT, which
/// it only answers once the attempt reaches the plugin's local port. A
/// completed ASSOCIATE with no reply DISPROVES `NoConnection` (the local
/// listener demonstrably accepted something) but is not strong enough
/// evidence for `TunnelSilent` either (it says nothing about the plugin),
/// so it must read as neither positive claim — `InconclusiveTransport`,
/// not `NoConnection`/`TunnelSilent`/`Other`.
#[skuld::test]
fn a_silent_udp_associate_is_reported_as_inconclusive_not_a_local_hop_claim() {
    let outcome = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let (connector, connected_rx) = SilentConnector::new();
            let cfg = DnsConfig {
                protocol: DnsProtocol::PlainUdp,
                ..test_dns_cfg()
            };
            let forwarder = SArc::new(DnsForwarder::new(cfg, connector, false));
            let run = tokio::spawn(run_forwarder_self_test(
                forwarder,
                vec!["127.0.0.1".parse().unwrap()],
                false,
                CancellationToken::new(),
            ));
            connected_rx.await.expect("the stub connector completed a connect");
            tokio::time::pause();
            run.await.unwrap()
        });

    let SelfTestOutcome::Failed { reason, .. } = outcome else {
        panic!("expected Failed, got {outcome:?}");
    };
    assert!(
        matches!(reason, SelfTestReason::InconclusiveTransport(_)),
        "a completed UDP ASSOCIATE with no reply disproves NoConnection but is not \
         TunnelSilent-grade evidence either; got {reason:?}"
    );
}

/// A resolver that answered SERVFAIL over UDP must not be reported as a
/// silent tunnel.
#[skuld::test]
fn a_udp_resolver_that_answers_servfail_is_not_a_silent_tunnel() {
    let outcome = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let (addr, _stub) = servfail_udp_stub().await;
            let cfg = DnsConfig {
                servers: vec![addr.ip()],
                protocol: DnsProtocol::PlainUdp,
                ..test_dns_cfg()
            };
            let forwarder = SArc::new(DnsForwarder::new_with_ports(
                cfg,
                SArc::new(crate::dns::connector::DirectConnector),
                true,
                vec![addr.port()],
            ));
            run_forwarder_self_test(forwarder, vec![addr.ip()], false, CancellationToken::new()).await
        });
    let SelfTestOutcome::Failed { reason, .. } = outcome else {
        panic!("expected Failed, got {outcome:?}");
    };
    match reason {
        SelfTestReason::Other(s) => assert!(s.contains("SERVFAIL"), "got: {s}"),
        other => panic!("a resolver answered; expected Other, got {other:?}"),
    }
}

/// A probe verdict is direct out-of-band evidence about the server and
/// outranks every self-test reading.
#[skuld::test]
fn a_blocked_probe_outranks_every_self_test_reading() {
    for reason in [
        SelfTestReason::TunnelSilent,
        SelfTestReason::NoConnection,
        SelfTestReason::Other("anything".into()),
    ] {
        let err = self_test_error_for(Some(ReachabilityVerdict::Blocked), 3, 4517, reason);
        assert!(matches!(err, ProxyError::NetworkBlocked), "got {err:?}");
    }
}

/// Every `UpstreamCause` gets wording matching what was actually observed.
/// Three causes imply a peer answered at some layer even though no valid
/// DNS reply resulted; claiming "no resolver answered" for those would
/// contradict the byte counts logged right next to this string.
#[skuld::test]
fn describe_upstream_failure_does_not_claim_silence_for_a_cause_that_answered() {
    for cause in [
        UpstreamCause::BadResponse,
        UpstreamCause::CertificateRejected,
        UpstreamCause::TlsFailed,
    ] {
        let msg = super::describe_upstream_failure(cause);
        assert!(
            !msg.contains("no resolver answered"),
            "{cause} implies a peer responded; got: {msg}"
        );
    }
    for cause in [
        UpstreamCause::Unreachable,
        UpstreamCause::Io,
        UpstreamCause::ExchangeTimeout,
    ] {
        let msg = super::describe_upstream_failure(cause);
        assert!(
            msg.contains("no resolver answered"),
            "{cause} is a genuine silence; got: {msg}"
        );
    }
    // A connect that never completed is NOT silence from a resolver: no
    // connection to one was ever opened, so claiming we asked and got nothing
    // back would overstate how far the attempt got.
    let msg = super::describe_upstream_failure(UpstreamCause::ConnectTimeout);
    assert!(
        !msg.contains("no resolver answered"),
        "a pending connect never reached a resolver; got: {msg}"
    );
    assert!(
        msg.contains("no connection"),
        "the wording must name the connection, not the resolver; got: {msg}"
    );
}

/// The reason must never be a `Debug`-formatted internal enum: the toast is
/// the only thing most users read. Drives the REAL production formatter
/// (`describe_upstream_failure`) rather than a hand-authored clean
/// string, so a regression that reintroduces `{cause:?}`-style Debug
/// formatting is caught here.
#[skuld::test]
fn the_reason_never_carries_a_debug_formatted_enum() {
    let msg = super::describe_upstream_failure(UpstreamCause::ExchangeTimeout);
    let err = self_test_error_for(None, 3, 4517, SelfTestReason::Other(msg));
    assert!(!err.to_string().contains("Upstream("), "got: {err}");
    assert!(err.to_string().contains("timeout"), "got: {err}");
}

/// Pins `implicates_plugin_transport`'s two independent conditions: the
/// pre-verdict reason must implicate the transport (three variants: the two
/// tunnel readings plus the UDP-associate inconclusive case), AND no
/// `Blocked`/`TcpRefused`/`TcpTimeout` verdict may have already reattributed
/// the failure to the network path.
#[skuld::test]
fn implicates_plugin_transport_covers_every_combination() {
    let implicates = super::implicates_plugin_transport;

    // Reason implicates, no overriding verdict: quote the plugin.
    assert!(implicates(&SelfTestReason::NoConnection, None));
    assert!(implicates(&SelfTestReason::TunnelSilent, None));
    assert!(implicates(
        &SelfTestReason::InconclusiveTransport("no resolver answered through the tunnel (unreachable)".into()),
        None
    ));
    assert!(implicates(
        &SelfTestReason::TunnelSilent,
        Some(ReachabilityVerdict::Reachable)
    ));

    // Other never implicates, even with no overriding verdict: the
    // transport is proven healthy or was never exercised.
    assert!(!implicates(
        &SelfTestReason::Other("a resolver answered with SERVFAIL".into()),
        None
    ));

    // A Blocked/TcpRefused/TcpTimeout verdict overrides every reason,
    // including the ones that would otherwise implicate the transport.
    for reason in [
        SelfTestReason::NoConnection,
        SelfTestReason::TunnelSilent,
        SelfTestReason::InconclusiveTransport("reason".into()),
    ] {
        for verdict in [
            ReachabilityVerdict::Blocked,
            ReachabilityVerdict::TcpRefused,
            ReachabilityVerdict::TcpTimeout,
        ] {
            assert!(
                !implicates(&reason, Some(verdict)),
                "verdict {verdict:?} must override reason {reason:?}"
            );
        }
    }
}

/// `report_plugin_output` quotes a chain's lines, and says so when there is
/// no chain — the branch that makes the gate's call site observable.
#[skuld::test]
fn report_plugin_output_quotes_a_chain_or_says_there_is_none() {
    let capture = |f: &dyn Fn()| {
        let writer = VecWriter::new();
        let subscriber = tracing_subscriber::registry().with(
            fmt::layer()
                .with_writer(writer.clone())
                .with_ansi(false)
                .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
        );
        {
            let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);
            f();
        }
        writer.snapshot_string()
    };

    let log = crate::proxy::plugin_log::PluginLog::new();
    log.push_line("transport/internet/tls: ECH required but no ECH config could be obtained");
    let with_chain = capture(&|| super::report_plugin_output(Some(&log)));
    assert!(with_chain.contains("ECH required"), "got:\n{with_chain}");

    let without = capture(&|| super::report_plugin_output(None));
    assert!(
        without.contains(crate::proxy::plugin_log::NO_PLUGIN_CONFIGURED),
        "got:\n{without}"
    );
}

/// The self-test hands its budget DOWN to the forwarder instead of
/// wrapping the call in a `timeout`, so a failing attempt is classified and
/// logged before the self-test's own budget can drop it. This asserts the
/// reason carries the typed cause, i.e. the gate reports WHAT failed.
#[skuld::test]
fn self_test_failure_logs_the_typed_upstream_cause() {
    let writer = VecWriter::new();

    let outcome = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let subscriber = tracing_subscriber::registry().with(
                fmt::layer()
                    .with_writer(writer.clone())
                    .with_ansi(false)
                    .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
            );
            let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);

            let forwarder = SArc::new(DnsForwarder::new(test_dns_cfg(), RefusingConnector::all(), false));
            run_forwarder_self_test(
                forwarder,
                vec!["127.0.0.1".parse().unwrap()],
                false,
                CancellationToken::new(),
            )
            .await
        });

    let reason = match outcome {
        SelfTestOutcome::Failed { reason, .. } => reason,
        other => panic!("expected Failed, got {other:?}"),
    };
    // Refused at connect: not one byte reached the tunnel.
    assert!(matches!(reason, SelfTestReason::NoConnection), "got {reason:?}");

    let output = writer.snapshot_string();
    assert!(
        output.contains("upstream failed"),
        "the per-upstream WARN must survive the self-test's budget; got:\n{output}"
    );
    assert!(
        output.contains("layer=connect"),
        "expected 'layer=connect'; got:\n{output}"
    );
    assert!(
        output.contains("cause=unreachable"),
        "expected 'cause=unreachable'; got:\n{output}"
    );
    assert!(
        output.contains(&format!(
            "budget_ms={}",
            crate::dns::forwarder::TUNNEL_QUERY_TIMEOUT.as_millis()
        )),
        "the WARN must report the SELF-TEST's budget, proving it reached forward_one; got:\n{output}"
    );
}

/// A walk gives EVERY resolver the full per-resolver bound and nothing
/// shared: two hanging upstreams cost exactly `2 × TUNNEL_QUERY_TIMEOUT`, not
/// a deadline divided between them (there is no deadline any more — no
/// retry, so nothing to divide it across). Virtual time: the connector never
/// completes, so every `forward_one` budget expires via auto-advance and no
/// wall-clock is consumed.
#[skuld::test]
fn self_test_gives_every_hanging_resolver_the_full_bound() {
    let (outcome, elapsed) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::pause();
            let servers: Vec<std::net::IpAddr> = vec!["127.0.0.1".parse().unwrap(), "127.0.0.2".parse().unwrap()];
            let cfg = DnsConfig {
                servers: servers.clone(),
                ..test_dns_cfg()
            };
            let forwarder = SArc::new(DnsForwarder::new(cfg, SArc::new(HangingConnector), false));
            let t0 = tokio::time::Instant::now();
            let outcome = run_forwarder_self_test(forwarder, servers, false, CancellationToken::new()).await;
            (outcome, t0.elapsed())
        });

    // tokio rounds every timer deadline UP to a whole millisecond and the
    // walk arms one timeout per upstream, so allow that many milliseconds of
    // overshoot across the two.
    let quantization = std::time::Duration::from_millis(2);
    let expected = 2 * crate::dns::forwarder::TUNNEL_QUERY_TIMEOUT;
    assert!(
        elapsed >= expected && elapsed <= expected + quantization,
        "a walk of two hanging resolvers must cost exactly 2 x TUNNEL_QUERY_TIMEOUT; took {elapsed:?}, expected ~{expected:?}"
    );
    match outcome {
        SelfTestOutcome::Failed { reason, attempts, .. } => {
            // Every connect stays outstanding until its budget fires, so the
            // run is `TunnelSetupPending` — NOT `NoConnection`. This shape
            // used to be reported as "the local proxy or its plugin is not
            // accepting connections", a claim about a refusal that never
            // happened. `NoConnection` is now reserved for connects that
            // failed outright, pinned by
            // `a_definite_connect_failure_is_still_reported_as_no_connection`.
            assert!(matches!(reason, SelfTestReason::TunnelSetupPending), "got {reason:?}");
            assert_eq!(attempts, 1, "one walk, so exactly one attempt is counted");
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}

fn noerror_reply() -> Vec<u8> {
    let mut reply = vec![0u8; 12];
    reply[3] = 0x00; // RCODE = 0 (NoError)
    reply
}

/// **Load-bearing regression.** A transport that is alive but slow —
/// 5s into establishing, well past the deleted 1500ms `PER_ATTEMPT` budget
/// (the deleted 5s `OUTER_BUDGET` gave no extra margin at this point — it
/// would have expired at the same 5s), but under the 10s
/// `TUNNEL_QUERY_TIMEOUT` — must pass the gate rather than being refused as
/// dead.
#[skuld::test]
fn a_slow_but_alive_transport_passes_the_gate() {
    // Current-thread runtime with `tokio::time::pause()`: the whole test runs
    // on virtual time, so a 5s establishment costs no real wall-clock time.
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::pause();
            let t0 = tokio::time::Instant::now();
            let (connector, connect_requested, release) = GatedConnector::new(noerror_reply());
            let cfg = DnsConfig {
                protocol: DnsProtocol::PlainTcp,
                ..test_dns_cfg()
            };
            let forwarder = SArc::new(DnsForwarder::new(cfg, connector, false));
            let run = tokio::spawn(run_forwarder_self_test(
                forwarder,
                vec!["127.0.0.1".parse().unwrap()],
                false,
                CancellationToken::new(),
            ));

            // Rendezvous on the connect having genuinely started, not a timer.
            connect_requested.await.expect("connect_tcp was entered");
            assert_eq!(
                t0.elapsed(),
                std::time::Duration::ZERO,
                "no virtual time may pass before the connect is even in flight"
            );
            // The rendezvous-then-advance ordering with no `.await` between
            // them is what makes this deterministic: inserting one would let
            // `tokio::time::pause()`'s auto-advance race ahead to the 10s
            // deadline before this deliberate 5s step runs.
            tokio::time::advance(std::time::Duration::from_secs(5)).await;
            let _ = release.send(());

            let outcome = run.await.unwrap();
            assert!(
                matches!(outcome, SelfTestOutcome::Ok { attempts: 1 }),
                "got {outcome:?}"
            );
        });
}

/// finding-11 guard at the gate: a hung primary must not strand the
/// secondary. `HangThenAnswer` hangs `connect_tcp` for the primary and
/// answers the secondary in-process, so the walk's own failover (not a
/// retry) is what passes the gate.
#[skuld::test]
fn a_slow_first_resolver_falls_through_to_a_healthy_second() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::pause();
            let servers: Vec<std::net::IpAddr> = vec!["127.0.0.1".parse().unwrap(), "127.0.0.2".parse().unwrap()];
            let ports = vec![11000u16, 11001u16];
            let cfg = DnsConfig {
                servers: servers.clone(),
                protocol: DnsProtocol::PlainTcp,
                ..test_dns_cfg()
            };
            let hang = vec![std::net::SocketAddr::new(servers[0], ports[0])];
            let connector = HangThenAnswer::new(hang, &noerror_reply());
            let forwarder = SArc::new(DnsForwarder::new_with_ports(cfg, connector, false, ports));
            let outcome = run_forwarder_self_test(forwarder, servers, false, CancellationToken::new()).await;
            assert!(
                matches!(outcome, SelfTestOutcome::Ok { attempts: 1 }),
                "got {outcome:?}"
            );
        });
}

/// Pins the classification AND the reported duration for a single hanging
/// resolver — distinct from `self_test_gives_every_hanging_resolver_the_full_bound`,
/// which pins the WALL elapsed of the whole call across two resolvers.
#[skuld::test]
fn a_transport_that_never_establishes_is_reported_as_pending_setup() {
    let outcome = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::pause();
            let forwarder = SArc::new(DnsForwarder::new(test_dns_cfg(), SArc::new(HangingConnector), false));
            run_forwarder_self_test(
                forwarder,
                vec!["127.0.0.1".parse().unwrap()],
                false,
                CancellationToken::new(),
            )
            .await
        });
    match outcome {
        SelfTestOutcome::Failed {
            reason,
            attempts,
            elapsed_ms,
        } => {
            assert!(matches!(reason, SelfTestReason::TunnelSetupPending), "got {reason:?}");
            assert_eq!(attempts, 1);
            // tokio rounds every timer deadline UP to a whole millisecond.
            let bound_ms = crate::dns::forwarder::TUNNEL_QUERY_TIMEOUT.as_millis() as u64;
            assert!(
                (bound_ms..=bound_ms + 1).contains(&elapsed_ms),
                "expected elapsed_ms in [{bound_ms}, {}], got {elapsed_ms}",
                bound_ms + 1
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}

/// A cancel that fires while the connect is still establishing must report
/// `Cancelled` immediately — not after waiting out `TUNNEL_QUERY_TIMEOUT`.
#[skuld::test]
fn a_cancel_during_establishment_reports_cancelled_without_waiting_out_the_bound() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::pause();
            let t0 = tokio::time::Instant::now();
            let (connector, connect_requested, _release) = GatedConnector::new(noerror_reply());
            let cfg = DnsConfig {
                protocol: DnsProtocol::PlainTcp,
                ..test_dns_cfg()
            };
            let forwarder = SArc::new(DnsForwarder::new(cfg, connector, false));
            let cancel = CancellationToken::new();
            let run = tokio::spawn(run_forwarder_self_test(
                forwarder,
                vec!["127.0.0.1".parse().unwrap()],
                false,
                cancel.clone(),
            ));

            connect_requested.await.expect("connect_tcp was entered");
            cancel.cancel();
            let outcome = run.await.unwrap();

            assert!(matches!(outcome, SelfTestOutcome::Cancelled), "got {outcome:?}");
            assert_eq!(
                t0.elapsed(),
                std::time::Duration::ZERO,
                "cancelling mid-establishment must not wait out any bound"
            );
        });
}

/// Empty servers → `run_forwarder_self_test` logs `skipped` and
/// returns `Ok(0)`. Empty-servers in production is rejected at
/// `build_local_dns` *before* `run_forwarder_self_test` is even
/// called (test below: `build_local_dns_returns_err_for_empty_servers`);
/// this test pins the helper's contract in isolation.
#[skuld::test]
fn self_test_empty_servers_returns_ok_zero() {
    let writer = VecWriter::new();

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let subscriber = tracing_subscriber::registry().with(
                fmt::layer()
                    .with_writer(writer.clone())
                    .with_ansi(false)
                    .with_filter(tracing_subscriber::filter::LevelFilter::INFO),
            );
            let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);

            let forwarder = SArc::new(DnsForwarder::new(test_dns_cfg(), RefusingConnector::all(), false));
            let outcome = run_forwarder_self_test(forwarder, vec![], false, CancellationToken::new()).await;
            assert!(matches!(outcome, SelfTestOutcome::Ok { attempts: 0 }));
        });

    let output = writer.snapshot_string();
    assert!(
        output.contains("forwarder self-test skipped: no servers configured"),
        "expected skipped log; got:\n{output}"
    );
}

/// Dead upstream → `run_forwarder_self_test` returns
/// `SelfTestOutcome::Failed { attempts: 1, .. }` and logs `forwarder
/// self-test failed` at INFO. `into_result` then maps that to
/// `ProxyError::ForwarderSelfTestFailed`.
#[skuld::test]
fn self_test_dead_upstream_returns_failed() {
    let writer = VecWriter::new();

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let subscriber = tracing_subscriber::registry().with(
                fmt::layer()
                    .with_writer(writer.clone())
                    .with_ansi(false)
                    .with_filter(tracing_subscriber::filter::LevelFilter::INFO),
            );
            let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);

            let forwarder = SArc::new(DnsForwarder::new(test_dns_cfg(), RefusingConnector::all(), false));
            let outcome = run_forwarder_self_test(
                forwarder,
                vec!["127.0.0.1".parse().unwrap()],
                false,
                CancellationToken::new(),
            )
            .await;
            let SelfTestOutcome::Failed { attempts, reason, .. } = outcome else {
                panic!("expected Failed");
            };
            assert_eq!(attempts, 1);
            assert!(matches!(reason, SelfTestReason::NoConnection), "got {reason:?}");
            let err = self_test_error_for(None, attempts, 4500, reason);
            assert!(matches!(
                err,
                ProxyError::NoTunnelConnection {
                    attempts: 1,
                    elapsed_ms: 4500
                }
            ));
        });

    let output = writer.snapshot_string();
    assert!(
        output.contains("forwarder self-test failed"),
        "expected 'forwarder self-test failed' in log; got:\n{output}"
    );
    assert!(output.contains("INFO"), "expected INFO level; got:\n{output}");
}

/// When self-test fails AND `diagnostic_plugin_tap=true`,
/// emit a `warn!` breadcrumb pointing the reader to the tap output
/// above. Const-anchored so a text change breaks only the const.
#[skuld::test]
fn self_test_failure_with_tap_enabled_emits_correlation_hint() {
    let writer = VecWriter::new();

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let subscriber = tracing_subscriber::registry().with(
                fmt::layer()
                    .with_writer(writer.clone())
                    .with_ansi(false)
                    .with_filter(tracing_subscriber::filter::LevelFilter::INFO),
            );
            let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);

            let forwarder = SArc::new(DnsForwarder::new(test_dns_cfg(), RefusingConnector::all(), false));
            let _ = run_forwarder_self_test(
                forwarder,
                vec!["127.0.0.1".parse().unwrap()],
                true,
                CancellationToken::new(),
            )
            .await;
        });

    let output = writer.snapshot_string();
    assert!(
        output.contains(super::TAP_ENABLED_HINT),
        "expected TAP_ENABLED_HINT in log; got:\n{output}"
    );
    assert!(
        !output.contains(super::TAP_DISABLED_HINT),
        "tap=true must NOT emit the disabled hint; got:\n{output}"
    );
}

/// The reworded hint must not demand a fresh reproduction — it should point
/// at what this run already logged.
#[skuld::test]
fn the_tap_disabled_hint_does_not_demand_a_reproduction() {
    let hint = super::TAP_DISABLED_HINT;
    assert!(!hint.contains("next reproduction"), "got: {hint}");
    assert!(
        hint.contains("above"),
        "the hint must point at what this run logged: {hint}"
    );
}

/// When self-test fails AND tap is OFF, emit a `warn!`
/// remediation hint pointing the reader to the config flag.
#[skuld::test]
fn self_test_failure_without_tap_emits_remediation_hint() {
    let writer = VecWriter::new();

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let subscriber = tracing_subscriber::registry().with(
                fmt::layer()
                    .with_writer(writer.clone())
                    .with_ansi(false)
                    .with_filter(tracing_subscriber::filter::LevelFilter::INFO),
            );
            let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);

            let forwarder = SArc::new(DnsForwarder::new(test_dns_cfg(), RefusingConnector::all(), false));
            let _ = run_forwarder_self_test(
                forwarder,
                vec!["127.0.0.1".parse().unwrap()],
                false,
                CancellationToken::new(),
            )
            .await;
        });

    let output = writer.snapshot_string();
    assert!(
        output.contains(super::TAP_DISABLED_HINT),
        "expected TAP_DISABLED_HINT in log; got:\n{output}"
    );
    assert!(
        !output.contains(super::TAP_ENABLED_HINT),
        "tap=false must NOT emit the enabled hint; got:\n{output}"
    );
}

/// `build_local_dns` rejects the degenerate `enabled=true, servers=[]`
/// config: a live TUN would strand every in-tunnel UDP/53 flow at the
/// LocalDnsEndpoint with no upstream to forward to.
#[skuld::test]
fn build_local_dns_returns_err_for_empty_servers() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let cfg = DnsConfig {
                enabled: true,
                servers: vec![], // degenerate
                protocol: DnsProtocol::PlainTcp,
                allow_insecure_bootstrap: false,
            };
            match build_local_dns(&cfg, 1080, false, CancellationToken::new()).await {
                Err(ProxyError::ForwarderSelfTestFailed {
                    attempts: 0,
                    elapsed_ms: 0,
                    ..
                }) => {}
                Err(other) => panic!("unexpected error variant: {other:?}"),
                Ok(_) => panic!("expected ForwarderSelfTestFailed for empty servers"),
            }
        });
}

/// `is_dns_reply_ok` reply-decode contract — direct unit
/// tests of the RCODE check. Without these, a regression in the
/// mask (`0x0F` → `0xF0`) or the length check would only surface
/// once the gate runs against real upstream DNS in production.
#[skuld::test]
fn is_dns_reply_ok_treats_noerror_as_success() {
    let mut reply = vec![0u8; 12];
    reply[3] = 0x00; // RCODE = 0 (NoError)
    assert!(super::is_dns_reply_ok(&reply));
}

#[skuld::test]
fn is_dns_reply_ok_treats_nxdomain_as_success() {
    let mut reply = vec![0u8; 12];
    reply[3] = 0x03; // RCODE = 3 (NXDOMAIN). Path probe semantic.
    assert!(super::is_dns_reply_ok(&reply));
}

#[skuld::test]
fn is_dns_reply_ok_treats_refused_as_success() {
    let mut reply = vec![0u8; 12];
    reply[3] = 0x05; // RCODE = 5 (REFUSED). Resolver declined, path works.
    assert!(super::is_dns_reply_ok(&reply));
}

#[skuld::test]
fn is_dns_reply_ok_rejects_servfail() {
    let mut reply = vec![0u8; 12];
    reply[3] = 0x02; // RCODE = 2 (SERVFAIL). Upstream explicitly failed.
    assert!(!super::is_dns_reply_ok(&reply));
}

#[skuld::test]
fn is_dns_reply_ok_ignores_high_nibble_of_byte_3() {
    // RFC 1035: low nibble = RCODE; high nibble = Z (reserved) + RA
    // (recursion available). High-nibble bits set MUST NOT mask the
    // RCODE check.
    let mut reply = vec![0u8; 12];
    reply[3] = 0xF2; // high nibble set + RCODE=2
    assert!(!super::is_dns_reply_ok(&reply));
    reply[3] = 0xF0; // high nibble set + RCODE=0
    assert!(super::is_dns_reply_ok(&reply));
}

#[skuld::test]
fn is_dns_reply_ok_rejects_truncated_reply() {
    // Fewer than 12 bytes is not a well-formed DNS header.
    assert!(!super::is_dns_reply_ok(&[]));
    assert!(!super::is_dns_reply_ok(&[0u8; 11]));
}

/// `dns.enabled = false` → `build_local_dns` returns
/// `(None, None)` → gate is skipped entirely in `start_inner`.
#[skuld::test]
fn build_local_dns_returns_none_when_disabled() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let cfg = DnsConfig {
                enabled: false,
                servers: vec![],
                protocol: DnsProtocol::PlainTcp,
                allow_insecure_bootstrap: false,
            };
            let res = build_local_dns(&cfg, 1080, false, CancellationToken::new()).await;
            let (ep, fwd) = match res {
                Ok(t) => t,
                Err(e) => panic!("expected Ok((None, None)) for disabled DNS, got {e:?}"),
            };
            assert!(ep.is_none());
            assert!(fwd.is_none());
        });
}

/// The in-TUN LocalDnsEndpoint is the sole OS DNS path, so it must be
/// constructed whenever DNS is enabled with servers. `build_local_dns`
/// returns a 2-tuple `(Option<LocalDnsEndpoint>, Option<Arc<DnsForwarder>>)`.
#[skuld::test]
fn build_local_dns_builds_endpoint_when_enabled() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let cfg = DnsConfig {
                enabled: true,
                servers: vec!["1.1.1.1".parse().unwrap()],
                protocol: DnsProtocol::PlainTcp,
                allow_insecure_bootstrap: false,
            };
            let (ep, fwd) = build_local_dns(&cfg, 1080, false, CancellationToken::new())
                .await
                .expect("build_local_dns ok when enabled");
            assert!(ep.is_some(), "endpoint must exist (sole DNS path)");
            assert!(fwd.is_some(), "forwarder must exist for the self-test gate");
        });
}

fn original_reason() -> String {
    "attempt 3 timed out".to_string()
}

#[skuld::test]
fn self_test_error_blocked_is_network_blocked() {
    let e = self_test_error_for(
        Some(ReachabilityVerdict::Blocked),
        3,
        200,
        SelfTestReason::Other(original_reason()),
    );
    assert!(
        matches!(e, ProxyError::NetworkBlocked),
        "Blocked must map to the typed NetworkBlocked, got {e:?}"
    );
}

#[skuld::test]
fn self_test_error_tcp_refused_rewrites_reason() {
    let e = self_test_error_for(
        Some(ReachabilityVerdict::TcpRefused),
        3,
        200,
        SelfTestReason::Other(original_reason()),
    );
    match e {
        ProxyError::ForwarderSelfTestFailed { reason, .. } => {
            assert!(reason.contains("refused"), "got {reason:?}");
        }
        other => panic!("expected ForwarderSelfTestFailed, got {other:?}"),
    }
}

#[skuld::test]
fn self_test_error_tcp_timeout_rewrites_reason() {
    let e = self_test_error_for(
        Some(ReachabilityVerdict::TcpTimeout),
        3,
        200,
        SelfTestReason::Other(original_reason()),
    );
    match e {
        ProxyError::ForwarderSelfTestFailed { reason, .. } => {
            assert!(reason.contains("did not respond"), "got {reason:?}");
        }
        other => panic!("expected ForwarderSelfTestFailed, got {other:?}"),
    }
}

#[skuld::test]
fn self_test_error_reachable_keeps_original() {
    let e = self_test_error_for(
        Some(ReachabilityVerdict::Reachable),
        3,
        200,
        SelfTestReason::Other(original_reason()),
    );
    match e {
        ProxyError::ForwarderSelfTestFailed {
            reason,
            attempts,
            elapsed_ms,
        } => {
            assert_eq!(reason, original_reason());
            assert_eq!(attempts, 3);
            assert_eq!(elapsed_ms, 200);
        }
        other => panic!("expected ForwarderSelfTestFailed, got {other:?}"),
    }
}

#[skuld::test]
fn self_test_error_inconclusive_keeps_original() {
    let e = self_test_error_for(
        Some(ReachabilityVerdict::Inconclusive),
        3,
        200,
        SelfTestReason::Other(original_reason()),
    );
    match e {
        ProxyError::ForwarderSelfTestFailed { reason, .. } => assert_eq!(reason, original_reason()),
        other => panic!("expected ForwarderSelfTestFailed, got {other:?}"),
    }
}

#[skuld::test]
fn self_test_error_none_keeps_original() {
    let e = self_test_error_for(None, 3, 200, SelfTestReason::Other(original_reason()));
    match e {
        ProxyError::ForwarderSelfTestFailed { reason, .. } => assert_eq!(reason, original_reason()),
        other => panic!("expected ForwarderSelfTestFailed, got {other:?}"),
    }
}

/// End-to-end-ish: a TLS-transport endpoint that accepts TCP then resets the
/// handshake → the live probe verdict is `Blocked` → `self_test_error_for`
/// yields the typed `NetworkBlocked`.
#[skuld::test(name = "self_test_tests::reset_endpoint_maps_to_network_blocked")]
async fn reset_endpoint_maps_to_network_blocked() {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            drop(s);
        }
    });
    let verdict = crate::reachability::probe_server_reachability(
        &a.ip().to_string(),
        a.port(),
        Some("galoshes"),
        Some("tls;host=h"),
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(verdict, ReachabilityVerdict::Blocked);
    assert!(matches!(
        self_test_error_for(Some(verdict), 3, 200, SelfTestReason::Other(original_reason())),
        ProxyError::NetworkBlocked
    ));
}

/// Regression: a gate cancelled before its first attempt must still hit the
/// single reporting match (both cancel return-sites set `outcome` and
/// `break` rather than returning directly) — otherwise a cancelled gate is
/// indistinguishable in `bridge.log` from one that never ran at all.
#[skuld::test]
fn a_cancelled_gate_logs_and_reports_cancelled() {
    let writer = VecWriter::new();
    let subscriber = tracing_subscriber::registry().with(
        fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::INFO),
    );
    let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);

    let outcome = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let cancel = CancellationToken::new();
            cancel.cancel();
            let forwarder = SArc::new(DnsForwarder::new(test_dns_cfg(), SArc::new(HangingConnector), false));
            run_forwarder_self_test(forwarder, vec!["127.0.0.1".parse().unwrap()], false, cancel).await
        });

    assert!(matches!(outcome, SelfTestOutcome::Cancelled), "got {outcome:?}");
    let output = writer.snapshot_string();
    assert!(
        output.contains("forwarder self-test cancelled"),
        "a cancelled gate must log, not silently return; got:\n{output}"
    );
}
