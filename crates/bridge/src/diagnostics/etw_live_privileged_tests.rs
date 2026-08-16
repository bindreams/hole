//! Privileged-lane proof that `ControlTraceW(EVENT_TRACE_CONTROL_QUERY)`
//! works against a LIVE, unstopped ETW session. Runs on the elevated `tun`
//! lane only: the `TUN` label (reused
//! from `crate::test_support::skuld_fixtures`, this crate's existing
//! "elevated Windows lane" bucket — not just literal TUN-adapter tests, see
//! `proxy_manager_e2e_tests.rs`) gates it so the unprivileged
//! `SKULD_LABELS="!tun"` pass excludes it and the default pass (and CI's
//! `SKULD_LABELS="tun"` pass) runs it. NOT `#[ignore]`d and does not skip on
//! missing privilege: a default `cargo nextest` run on an unelevated box
//! runs this test and fails loud; opting out is the explicit `!tun` filter,
//! matching every other `*_privileged*` test in this crate (see
//! `crates/bridge/tests/cutover_privileged.rs`'s module doc for the same
//! contract).
//!
//! Builds its own minimal ETW session directly, rather than going through
//! `start_consumer()`, for two reasons: (1) `start_consumer()`
//! unconditionally sweeps any `hole-bridge-etw-*` session by name prefix
//! (`sweep_stale_sessions`), which would risk stopping a concurrently
//! running `DistHarness`-spawned e2e bridge's own real ETW session — nothing
//! in this codebase currently opts those subprocesses out of the always-on
//! consumer; (2) the claim under test only needs *a* live, named ETW
//! session, not the full 3-provider/PID-filter production pipeline. This
//! test's session name uses a distinct `hole-etw-live-stats-test-` prefix
//! so it is invisible to `start_consumer`'s sweep in both directions, and
//! sweeps its own prefix at the top (symmetric with production) so a
//! session orphaned by a prior hard-killed test run doesn't permanently
//! wedge `StartTraceW` with `ERROR_ALREADY_EXISTS` on that box.

use super::*;
use crate::test_support::log_capture::VecWriter;
use crate::test_support::skuld_fixtures::TUN;
use garter::tracing_test::set_default_in_current_thread;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::{Layer, SubscriberExt};

const TEST_SESSION_PREFIX: &str = "hole-etw-live-stats-test-";

/// `ControlTraceW(QUERY)` against a session that is alive and never
/// stopped must succeed twice in a row (the second call is the "still
/// alive" proof: a session `query_session_stats` had stopped as a side
/// effect could not answer a second query the same way), and each success
/// must log the message `"etw: session stats"` with `phase="live"`
/// (quoted — `tracing-subscriber`'s default field formatter quotes bare
/// string fields, matching `wfp::log_snapshot`'s existing convention) and
/// both loss counters present.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn events_lost_reported_from_a_live_session_without_stopping_it() {
    crate::diagnostics::etw_sweep::sweep_sessions_with_prefix(TEST_SESSION_PREFIX, "etw-test");

    let writer = VecWriter::new();
    let subscriber = tracing_subscriber::registry().with(
        fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::INFO),
    );
    let _guard = set_default_in_current_thread(subscriber);

    let session_name = format!("{TEST_SESSION_PREFIX}{}", std::process::id());
    let provider = Provider::by_guid(TCPIP_PROVIDER)
        .any(TCPIP_KEYWORDS)
        .add_callback(|_record: &EventRecord, _schema_locator: &SchemaLocator| {})
        .build();
    let trace_properties = TraceProperties {
        buffer_size: 256,
        ..Default::default()
    };
    // Split-lifecycle `start()` (no `process_from_handle` call) is enough:
    // `ControlTraceW(QUERY)` reads kernel-side session state independent of
    // user-mode buffer draining, so no processing thread is needed to make
    // the session queryable.
    let (trace, _handle) = UserTrace::new()
        .named(session_name.clone())
        .set_trace_properties(trace_properties)
        .enable(provider)
        .start()
        .expect("start a real ETW session (requires admin or Performance Log Users)");

    let first = query_session_stats(&session_name, "live");
    assert!(
        first.is_ok(),
        "first query against a live session must succeed: {first:?}"
    );
    let second = query_session_stats(&session_name, "live");
    assert!(
        second.is_ok(),
        "second query against the SAME still-live session must also succeed \
         (proves the first query did not stop it): {second:?}"
    );

    let output = writer.snapshot_string();
    assert_eq!(
        output.matches("etw: session stats").count(),
        2,
        "expected exactly 2 'etw: session stats' lines (not 'at stop' -- \
         that would read self-contradictory next to phase=\"live\"); got:\n{output}"
    );
    for line in output.lines().filter(|l| l.contains("etw: session stats")) {
        assert!(line.contains("phase=\"live\""), "expected phase=\"live\"; got:\n{line}");
        assert!(
            line.contains("events_lost="),
            "expected events_lost field; got:\n{line}"
        );
        assert!(
            line.contains("buffers_written="),
            "expected buffers_written field; got:\n{line}"
        );
    }

    trace.stop().expect("cleanup: stop the test's own ETW session");
}

/// `EtwGuard::drop` must stop and join the periodic stats-timer thread
/// *before* running its own stop-phase query, so no "live" phase query can
/// still be mid-flight — or start afresh — once the "stop" phase query
/// begins. Proven by driving a real [`EtwGuard`] (built via
/// `start_consumer_for_test` under a private session-name prefix, with a
/// short interval so a live tick is observed quickly) to at least one real
/// live-phase tick — a genuine rendezvous on a channel the production timer
/// thread itself writes into, not a sleep — then dropping it and asserting
/// every captured `"phase=\"live\""` log line's position precedes the
/// single `"phase=\"stop\""` line's position. If a regression reordered
/// `EtwGuard::drop` to query stop-phase before joining the timer thread,
/// the still-running timer thread could log a live-phase tick after the
/// stop-phase line.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn etw_guard_drop_stops_the_stats_timer_before_the_stop_phase_query() {
    const PREFIX: &str = "hole-etw-live-stats-test-drop-order-";
    crate::diagnostics::etw_sweep::sweep_sessions_with_prefix(PREFIX, "etw-test");

    let writer = VecWriter::new();
    let subscriber = tracing_subscriber::registry().with(
        fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::INFO),
    );
    let _guard = set_default_in_current_thread(subscriber);

    let session_name = format!("{PREFIX}{}", std::process::id());
    let (tick_tx, tick_rx) = std::sync::mpsc::channel::<u32>();
    // `start_consumer_for_test` propagates this test's thread-local
    // dispatcher into its internal threads, so no manual propagation is
    // needed around the tick callback itself.
    let etw_guard = start_consumer_for_test(session_name, std::time::Duration::from_millis(5), move |n| {
        let _ = tick_tx.send(n);
    })
    .expect("start a real ETW session (requires admin or Performance Log Users)");

    // Block on a real live-phase tick before dropping the guard, so the
    // ordering assertion below is checking against at least one genuine
    // "live" log line, not vacuously passing on an empty set.
    tick_rx.recv().expect("first live-phase tick");

    drop(etw_guard);

    let output = writer.snapshot_string();
    let lines: Vec<&str> = output.lines().collect();
    let stop_index = lines
        .iter()
        .position(|l| l.contains("phase=\"stop\""))
        .expect("EtwGuard::drop must log exactly one stop-phase query");
    assert!(
        lines[..stop_index].iter().any(|l| l.contains("phase=\"live\"")),
        "expected at least one live-phase log line before the stop-phase query; got:\n{output}"
    );
    let live_after_stop: Vec<&str> = lines[stop_index + 1..]
        .iter()
        .filter(|l| l.contains("phase=\"live\""))
        .copied()
        .collect();
    assert!(
        live_after_stop.is_empty(),
        "found live-phase log line(s) after the stop-phase query -- the stats timer thread was not \
         fully stopped before EtwGuard::drop ran its stop-phase query: {live_after_stop:?}\nfull output:\n{output}"
    );
}

/// `live_stats_tick`'s failure throttle must reset when a query succeeds,
/// so a session that fails, then recovers, then fails again re-warns on
/// the second failure instead of staying silently throttled to `info!`
/// forever. Proven against a real session name that transitions from
/// nonexistent (fail) → started (succeed) → stopped (fail again), driven
/// through the real `run_periodic_stats_inner` loop with genuine
/// tick-channel rendezvous at every transition (no sleeps).
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn periodic_tick_rewarns_after_a_transient_failure_recovers() {
    const PREFIX: &str = "hole-etw-live-stats-test-reset-";
    crate::diagnostics::etw_sweep::sweep_sessions_with_prefix(PREFIX, "etw-test");

    let writer = VecWriter::new();
    let subscriber = tracing_subscriber::registry().with(
        fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::INFO),
    );
    let _guard = set_default_in_current_thread(subscriber);

    let session_name = format!("{PREFIX}{}", std::process::id());
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
    let (tick_tx, tick_rx) = std::sync::mpsc::channel::<u32>();
    let dispatch = tracing::dispatcher::get_default(tracing::Dispatch::clone);
    let loop_session_name = session_name.clone();
    let handle = std::thread::spawn(move || {
        tracing::dispatcher::with_default(&dispatch, || {
            run_periodic_stats_inner(
                loop_session_name,
                std::time::Duration::from_millis(5),
                stop_rx,
                move |n| {
                    let _ = tick_tx.send(n);
                },
            );
        });
    });

    // Tick 1: session does not exist yet -- fails, warns (first failure).
    tick_rx.recv().expect("tick 1 (fail, no session yet)");

    // Start the real session under the exact name the timer is querying.
    let provider = Provider::by_guid(TCPIP_PROVIDER)
        .any(TCPIP_KEYWORDS)
        .add_callback(|_record: &EventRecord, _schema_locator: &SchemaLocator| {})
        .build();
    let trace_properties = TraceProperties {
        buffer_size: 256,
        ..Default::default()
    };
    let (trace, _handle) = UserTrace::new()
        .named(session_name.clone())
        .set_trace_properties(trace_properties)
        .enable(provider)
        .start()
        .expect("start a real ETW session (requires admin or Performance Log Users)");

    // Tick 2: session now exists -- succeeds, resetting the throttle.
    tick_rx.recv().expect("tick 2 (succeed, session started)");

    trace.stop().expect("stop the test's own ETW session mid-test");

    // Tick 3: session gone again -- fails. If the throttle had not reset
    // on tick 2's success, this would log "still failing" at info!, not a
    // fresh "failed" at warn!.
    tick_rx.recv().expect("tick 3 (fail again, session stopped)");

    drop(stop_tx);
    handle.join().expect("periodic stats thread panicked");

    let output = writer.snapshot_string();
    assert_eq!(
        output.matches("etw: ControlTraceW(QUERY) failed").count(),
        2,
        "expected exactly 2 fresh (warn-level) failures -- tick 1's initial failure and tick 3's \
         failure after tick 2's success reset the throttle; a stuck throttle would leave tick 3 \
         logged as \"still failing\" instead; got:\n{output}"
    );
}
