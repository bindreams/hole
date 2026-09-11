//! Claims about ETW sessions that only a real one can settle: what
//! `ControlTraceW` answers for a live, a stopped, and a never-started session,
//! and what [`EtwGuard::drop`] does with each answer. Runs on the elevated
//! `tun` lane only: the `TUN` label (reused
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

/// The by-name backstop must actually take a live session down, or the
/// session stays live and never gets stopped.
///
/// Calls [`stop_session_by_name`] directly against a real, still-live
/// session rather than through [`EtwGuard::drop`]: driving it via a
/// hand-built `EtwGuard { trace: None, .. }` would certify a state
/// production never builds (`start_consumer_named` always fills `trace`),
/// and the claim under test — that the by-name STOP can take a live session
/// down — belongs to `stop_session_by_name` itself, not to `EtwGuard`'s
/// field shape.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn stop_session_by_name_stops_a_live_session() {
    const PREFIX: &str = "hole-etw-live-stats-test-stop-by-name-";
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
    let provider = Provider::by_guid(TCPIP_PROVIDER)
        .any(TCPIP_KEYWORDS)
        .add_callback(|_record: &EventRecord, _schema_locator: &SchemaLocator| {})
        .build();
    let trace_properties = TraceProperties {
        buffer_size: 256,
        ..Default::default()
    };
    // Bound, not discarded with `_`: the latter would drop the session at the
    // end of this statement (ferrisetw's own `Drop` stops it), leaving the
    // backstop nothing to prove itself against. No processing thread is needed
    // — the claim under test is kernel-side session state, which `ControlTraceW`
    // reads and writes independently of user-mode buffer draining. The
    // end-of-scope `Drop` lands after the assertions and ignores its own error.
    let (_trace, _handle) = UserTrace::new()
        .named(session_name.clone())
        .set_trace_properties(trace_properties)
        .enable(provider)
        .start()
        .expect("start a real ETW session (requires admin or Performance Log Users)");

    let before = query_session_stats(&session_name, "live");
    assert!(
        before.is_ok(),
        "the session must be live before the by-name stop: {before:?}"
    );

    let reclaimed = stop_session_by_name(&session_name);
    assert!(reclaimed, "stop_session_by_name must report the session as reclaimed");

    let after = query_session_stats(&session_name, "live");
    assert!(
        after.is_err(),
        "the session must be gone once stop_session_by_name has run against it -- a call that \
         only reports success without stopping the session leaves it registered in the kernel: \
         {after:?}"
    );

    let output = writer.snapshot_string();
    assert!(
        output.contains("etw: stopped session by name"),
        "expected the by-name stop to be logged as the path that took the session down; got:\n{output}"
    );
}

/// The healthy path must leave nothing behind either, and must not need the
/// backstop to do it: reaching it would add an unbounded synchronous
/// `ControlTraceW` to every shutdown, the cost class of bindreams/hole#1016.
/// Driven through a real [`EtwGuard`] — session, processing thread and stats
/// timer — from `start_consumer_for_test`.
///
/// Captures at DEBUG: a backstop that ran here would find the session already
/// stopped by handle and take `stop_session_by_name`'s `debug!` arm, invisible
/// to the INFO capture the tests above use. All three of that function's arms
/// are asserted absent, so "the backstop did not run" rests on no guess about
/// which one a stray call would take — the `info!` arm needs a *live* session,
/// which a successful `UserTrace::stop` has just ruled out, and its assertion
/// is the canary for that assumption.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn etw_guard_drop_stops_the_session_it_started() {
    const PREFIX: &str = "hole-etw-live-stats-test-drop-stops-";
    crate::diagnostics::etw_sweep::sweep_sessions_with_prefix(PREFIX, "etw-test");

    let writer = VecWriter::new();
    let subscriber = tracing_subscriber::registry().with(
        fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::DEBUG),
    );
    let _guard = set_default_in_current_thread(subscriber);

    let session_name = format!("{PREFIX}{}", std::process::id());
    let etw_guard = start_consumer_for_test(session_name.clone(), LIVE_STATS_INTERVAL, |_| {})
        .expect("start a real ETW session (requires admin or Performance Log Users)");

    let before = query_session_stats(&session_name, "live");
    assert!(before.is_ok(), "the session must be live before the drop: {before:?}");

    drop(etw_guard);

    let after = query_session_stats(&session_name, "live");
    assert!(
        after.is_err(),
        "the session must be gone once EtwGuard::drop has run: {after:?}"
    );

    let output = writer.snapshot_string();
    // Root cause first: a genuine `trace.stop()` failure also trips the
    // backstop assertions below, and diagnosing it as "reached the backstop"
    // would name the symptom.
    assert!(
        !output.contains("etw: UserTrace::stop failed during drop"),
        "UserTrace::stop must succeed on the healthy path; got:\n{output}"
    );
    assert!(
        !output.contains("etw: session already stopped"),
        "the healthy path must not reach the by-name backstop -- this is the arm it would \
         actually take, the session having just been stopped by handle; got:\n{output}"
    );
    assert!(
        !output.contains("etw: stopped session by name"),
        "the healthy path must not reach the by-name backstop -- reaching it and finding the \
         session still live would mean UserTrace::stop's STOP never landed; got:\n{output}"
    );
    assert!(
        !output.contains("etw: failed to stop session by name"),
        "the healthy path must not reach the by-name backstop -- without this arm a reached \
         backstop that got an unexpected error would pass both checks above; got:\n{output}"
    );
    assert!(
        !output.contains("etw: kernel did not confirm the session was stopped"),
        "the healthy path must not abandon the processing thread -- the session WAS reclaimed \
         here, so `Drop` must join it rather than log the abandon warning and detach; got:\n{output}"
    );
}

/// The `Err` arm of `trace.stop()` — the branch the backstop exists for — must
/// fall through to the by-name STOP. Driven by a real failure rather than a
/// synthesised guard state: stopping the session out of band leaves the guard
/// holding a valid trace handle over a session that is gone, so `close_trace`
/// succeeds and the `control_trace(STOP)` behind it returns not-found. That is
/// the same `Err` a short-circuiting `CloseTrace` produces, which cannot be
/// manufactured from outside ferrisetw (`UserTrace` has no constructor taking a
/// handle).
///
/// Make `stop_session`'s `Err` arm report `stop_issued = true` — a complete
/// revert of the backstop for its only real scenario — and this is the one test
/// that fails.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn etw_guard_drop_falls_back_to_the_by_name_stop_when_usertrace_stop_errs() {
    const PREFIX: &str = "hole-etw-live-stats-test-stop-errs-";
    crate::diagnostics::etw_sweep::sweep_sessions_with_prefix(PREFIX, "etw-test");

    // DEBUG, not INFO: the backstop's expected outcome against an
    // already-stopped session is a `debug!`.
    let writer = VecWriter::new();
    let subscriber = tracing_subscriber::registry().with(
        fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::DEBUG),
    );
    let _guard = set_default_in_current_thread(subscriber);

    let session_name = format!("{PREFIX}{}", std::process::id());
    let etw_guard = start_consumer_for_test(session_name.clone(), LIVE_STATS_INTERVAL, |_| {})
        .expect("start a real ETW session (requires admin or Performance Log Users)");

    stop_trace_by_name(&session_name).expect("stop the session out of band, behind the guard's back");

    drop(etw_guard);

    let output = writer.snapshot_string();
    assert!(
        output.contains("etw: UserTrace::stop failed during drop"),
        "expected UserTrace::stop to fail, which is what puts Drop on the backstop path; got:\n{output}"
    );
    assert!(
        output.contains("etw: session already stopped"),
        "expected the by-name backstop to run and report the session already gone; got:\n{output}"
    );
}

/// `stop_session_by_name`'s expected outcome — nothing to stop — must not log
/// at `warn!`. Pins what `ControlTraceW(name, STOP)` really answers for a
/// session that does not exist, which no unit test can observe: unit tests can
/// only assert that [`is_session_not_found`] recognises a code they themselves
/// chose. If Windows answers with anything else, every trip through the backstop
/// against an already-gone session — the case the test above exercises — warns
/// about a session it in fact reclaimed.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn stopping_a_session_that_does_not_exist_is_not_a_warning() {
    let writer = VecWriter::new();
    let subscriber = tracing_subscriber::registry().with(
        fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::DEBUG),
    );
    let _guard = set_default_in_current_thread(subscriber);

    let reclaimed = stop_session_by_name(&format!("hole-etw-live-stats-test-absent-{}", std::process::id()));
    assert!(reclaimed, "a session that never existed must read as known-reclaimed");

    let output = writer.snapshot_string();
    assert!(
        output.contains("etw: session already stopped"),
        "a session that was never started must read as already stopped; got:\n{output}"
    );
    assert!(
        !output.contains("etw: failed to stop session by name"),
        "the expected outcome must not warn; got:\n{output}"
    );
}

/// Exercises [`abandon_session_on_thread_spawn_failure`], the exact cleanup
/// `start_consumer_named` runs on a processing-thread spawn failure — the
/// only other `UserTrace` lifetime site in this file, with no `EtwGuard` to
/// own the by-name backstop (module doc "Drain on Drop", and see the
/// function's own doc comment).
///
/// A real `std::thread::Builder::spawn` failure needs OS-level resource
/// exhaustion (hitting a process- or system-wide thread-count limit), which
/// is not something this test can trigger deterministically without mutating
/// shared OS/process state for the whole test binary (`ulimit`, or actually
/// spawning threads until the OS refuses one, which is itself
/// platform-dependent and not bounded by anything this test controls). That
/// trigger is therefore unverified here. What's verified instead is the
/// cleanup itself: `abandon_session_on_thread_spawn_failure` is the single
/// function both a real spawn failure and this test call, so driving it
/// directly with a synthetic `io::Error` exercises the identical code a real
/// failure would run. This test therefore does NOT pin that
/// `start_consumer_named`'s thread-spawn `.map_err` arm actually calls
/// `abandon_session_on_thread_spawn_failure` -- e.g. reverting that call site
/// to a bare `.map_err(EtwError::ThreadSpawn)` would leave every test in this
/// file, including this one, green. That call site's own ordering (dropping
/// the orphaned `trace` before invoking this helper, not after) is untested
/// by anything here.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn thread_spawn_failure_stops_the_orphaned_session() {
    const PREFIX: &str = "hole-etw-live-stats-test-spawn-fail-";
    crate::diagnostics::etw_sweep::sweep_sessions_with_prefix(PREFIX, "etw-test");

    let session_name = format!("{PREFIX}{}", std::process::id());
    let provider = Provider::by_guid(TCPIP_PROVIDER)
        .any(TCPIP_KEYWORDS)
        .add_callback(|_record: &EventRecord, _schema_locator: &SchemaLocator| {})
        .build();
    let trace_properties = TraceProperties {
        buffer_size: 256,
        ..Default::default()
    };
    // Bound, not discarded with `_`: see the identical rationale on
    // `stop_session_by_name_stops_a_live_session` above.
    let (_trace, _handle) = UserTrace::new()
        .named(session_name.clone())
        .set_trace_properties(trace_properties)
        .enable(provider)
        .start()
        .expect("start a real ETW session (requires admin or Performance Log Users)");

    let before = query_session_stats(&session_name, "live");
    assert!(
        before.is_ok(),
        "the session must be live before the simulated spawn failure: {before:?}"
    );

    let err = abandon_session_on_thread_spawn_failure(&session_name, std::io::Error::other("synthetic spawn failure"));
    assert!(
        matches!(err, EtwError::ThreadSpawn(_)),
        "the cleanup must still surface the original error as ThreadSpawn: {err:?}"
    );

    let after = query_session_stats(&session_name, "live");
    assert!(
        after.is_err(),
        "the session must be gone once the spawn-failure cleanup has run -- a cleanup that \
         doesn't reach the by-name backstop leaks the session with no thread and no guard left \
         to reclaim it: {after:?}"
    );
}

/// Drives `start_consumer_named`'s real thread-spawn-failure arm through the
/// [`start_consumer_named_with_spawn`] test seam, rather than calling
/// [`abandon_session_on_thread_spawn_failure`] directly the way
/// [`thread_spawn_failure_stops_the_orphaned_session`] above does. That test
/// pins the cleanup helper's own behaviour but, by its own doc, does not pin
/// that the call site actually invokes the helper, nor that `drop(trace)`
/// runs before the helper rather than after.
///
/// This test drives the real session-start + spawn-attempt path with an
/// injected `spawn_processor` that always fails, and distinguishes the two
/// orderings by which log line the by-name STOP backstop produces:
/// - `drop(trace)` before the helper (correct): ferrisetw's own `Drop`
///   already stopped the session, so the by-name STOP finds it already gone
///   and logs `"etw: session already stopped"` (debug), never
///   `"etw: stopped session by name"` (info).
/// - the helper before `drop(trace)` (inverted): the by-name STOP runs
///   against a still-live session and is the one that actually stops it,
///   logging `"etw: stopped session by name"` instead.
///
/// A regression that deletes the call to `abandon_session_on_thread_spawn_failure`
/// entirely (reverting to a bare `.map_err(EtwError::ThreadSpawn)?`) leaves the
/// session live, which the `after.is_err()` assertion below catches on its own.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn thread_spawn_failure_at_the_real_call_site_stops_the_session_after_dropping_the_trace() {
    const PREFIX: &str = "hole-etw-live-stats-test-spawn-fail-seam-";
    crate::diagnostics::etw_sweep::sweep_sessions_with_prefix(PREFIX, "etw-test");

    let session_name = format!("{PREFIX}{}", std::process::id());

    let writer = VecWriter::new();
    let subscriber = tracing_subscriber::registry().with(
        fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::DEBUG),
    );
    let _guard = set_default_in_current_thread(subscriber);

    let result = start_consumer_named_with_spawn(
        session_name.clone(),
        std::time::Duration::from_secs(60),
        |_tick| {},
        |_builder, _body| Err(std::io::Error::other("synthetic spawn failure")),
    );
    assert!(
        matches!(result, Err(EtwError::ThreadSpawn(_))),
        "a spawn failure must still surface as ThreadSpawn: {result:?}"
    );

    let after = query_session_stats(&session_name, "live");
    assert!(
        after.is_err(),
        "the session must be gone once the spawn-failure cleanup has run: {after:?}"
    );

    let output = writer.snapshot_string();
    assert!(
        output.contains("etw: session already stopped"),
        "drop(trace) must run before the by-name STOP backstop, so the backstop finds the \
         session already stopped by ferrisetw's own `Drop` -- got:\n{output}"
    );
    assert!(
        !output.contains("etw: stopped session by name"),
        "the by-name STOP must be a no-op backstop here, not the call that actually stopped a \
         still-live session -- that would mean the ordering was inverted -- got:\n{output}"
    );
}
