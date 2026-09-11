//! Unit tests for `wait_bounded` (bindreams/hole#842, #719). Uses
//! `crash_child`'s `TOMBSTONE_TEST_HANG_FOREVER`/`TOMBSTONE_TEST_EXIT_FAST`
//! test doubles instead of a real native fault, so these tests are
//! deterministic and fast (bounds here are small — a few hundred ms —
//! unlike `CHILD_WAIT_BOUND`'s production 60s).

use crate::{crash_child_bin, wait_bounded};
use std::time::Duration;

fn spawn_double(env_var: &str) -> std::process::Child {
    std::process::Command::new(crash_child_bin())
        .env(env_var, "1")
        .env_remove("HOLE_LOGGING_TEST_KIND")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn crash_child test double")
}

#[skuld::test]
fn wait_bounded_returns_promptly_when_child_exits() {
    let child = spawn_double("TOMBSTONE_TEST_EXIT_FAST");
    // Generous bound relative to an immediate `return` — this asserts the
    // HAPPY path returns well before it, not that it needs the full bound.
    let bound = Duration::from_secs(10);
    let started = std::time::Instant::now();
    let output = wait_bounded(child, bound);
    let elapsed = started.elapsed();
    assert!(output.status.success(), "status: {:?}", output.status);
    // "Promptly" here means the happy path is bounded by process-exit
    // latency, not by `bound` — a `wait_bounded` that (bug) always slept the
    // full duration before checking would still pass the assertion above.
    // A ten-second margin under a ten-second bound is not this codebase's
    // sanctioned "await a child exit" case (that's `bound` itself); it is a
    // real-time measurement of already-observed behavior, asserting the
    // fast path did not silently become the slow path.
    assert!(
        elapsed < bound / 2,
        "wait_bounded took {elapsed:?} to observe an immediate child exit — expected well under \
         half of the {bound:?} bound; did the happy path start blocking on something?"
    );
}

#[skuld::test]
fn wait_bounded_panics_with_clear_message_on_timeout() {
    let child = spawn_double("TOMBSTONE_TEST_HANG_FOREVER");
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        wait_bounded(child, Duration::from_millis(200))
    }));
    let err = result.expect_err("wait_bounded must panic when the child never exits");
    let msg = err
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| err.downcast_ref::<&str>().map(|s| s.to_string()))
        .expect("panic payload is a string");
    assert!(msg.contains("did not exit within"), "got: {msg}");
    assert!(msg.contains("200ms"), "bound should be named in the message: {msg}");
    // wait_bounded's timeout arm must not merely SEND a kill signal — it
    // must confirm the child actually reaped before reporting failure (see
    // bindreams/hole#842/#719 review B3: the earlier background-thread
    // design could report "timeout" after the child was already gone,
    // making a raw-pid kill race a pid-reuse victim). Proving that here is
    // NOT a second, later check of `pid`'s liveness — this suite runs many
    // crash_child's concurrently, so by the time a check ran here (after
    // catch_unwind has already unwound the panic), a sibling test's spawn
    // could have recycled the freed pid, which is the exact same class of
    // race B3 fixed, just relocated into this assertion instead of removed.
    // `wait_bounded` instead asserts internally, at the moment of reap, that
    // `status` shows a genuine kill()-caused termination (`termination_proof`
    // in its panic message: `signal=Some(SIGKILL)` on Unix, `code=Some(1)`
    // on Windows) — data only a real kill()-then-wait() can produce, so a
    // panic message that merely CLAIMS "confirmed it reaped" without doing
    // so has no way to also produce it. We only need to confirm that proof
    // reached this message, not re-derive it via a second, racy probe.
    assert!(msg.contains("confirmed it reaped"), "got: {msg}");
    #[cfg(unix)]
    assert!(
        msg.contains(&format!("signal=Some({})", libc::SIGKILL)),
        "expected SIGKILL termination proof in message: {msg}"
    );
    #[cfg(windows)]
    assert!(
        msg.contains("code=Some(1)"),
        "expected TerminateProcess termination proof in message: {msg}"
    );
}
