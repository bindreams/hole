//! Privileged-lane proof that `ControlTraceW(EVENT_TRACE_CONTROL_QUERY)`
//! works against a LIVE, unstopped ETW session (bindreams/hole#801's root
//! cause). Runs on the elevated `tun` lane only: the `TUN` label (reused
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
/// must log the exact `"etw: session stats"` message (not the old
/// phase-baked-into-the-message `"etw: session stats at stop"`, which would
/// read self-contradictory next to `phase="live"`) with `phase="live"`
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
