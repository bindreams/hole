//! Unit tests for `wait_bounded`. Uses `crash_child`'s
//! `TOMBSTONE_TEST_HANG_FOREVER`/`TOMBSTONE_TEST_EXIT_FAST` test doubles
//! instead of a real native fault, so these tests are deterministic and fast
//! (bounds here are small — a few hundred ms — unlike `CHILD_WAIT_BOUND`'s
//! production 60s).

use crate::{crash_child_bin, scrub_reexec_env, wait_bounded};
use std::time::Duration;

fn spawn_double(env_var: &str) -> std::process::Child {
    let mut cmd = std::process::Command::new(crash_child_bin());
    // Scrub first, THEN set `env_var` — scrubbing after would remove the
    // very double this call is trying to select.
    scrub_reexec_env(&mut cmd);
    cmd.env(env_var, "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn crash_child test double")
}

#[skuld::test]
fn wait_bounded_returns_promptly_when_child_exits() {
    let child = spawn_double("TOMBSTONE_TEST_EXIT_FAST");
    // Generous bound relative to an immediate `return`. We assert only on
    // the returned `Output`, not on wall-clock elapsed time: a hard
    // elapsed-time ceiling here would be a scheduling assertion on shared CI
    // hardware, not a regression signal. `status.success()` already tells
    // the two paths apart — a `wait_bounded` that fell through to its
    // SIGKILL arm would report a killed, non-success status instead.
    let bound = Duration::from_secs(10);
    let output = wait_bounded(child, bound);
    assert!(output.status.success(), "status: {:?}", output.status);
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
    // must confirm `child` actually reached a reaped terminal state before
    // reporting failure, to avoid racing a same-pid-reused victim process
    // into a raw-pid kill. Proving that here is NOT a second, later check
    // of `pid`'s liveness — this suite runs
    // many crash_child's concurrently, so by the time a check ran here
    // (after catch_unwind has already unwound the panic), a sibling test's
    // spawn could have recycled the freed pid, reintroducing that exact race
    // in a new spot. `wait_bounded` instead names, at the moment of reap,
    // which of its two possible outcomes `status` shows
    // (`termination_proof` in its panic message: `we killed it:
    // signal=Some(SIGKILL)` on Unix / `we killed it: code=Some(1)` on
    // Windows, vs. the child having already self-exited) — data only a real
    // kill()-then-wait() can produce, so a panic message that merely claims
    // a reap without doing so has no way to also produce it. This double
    // (hang forever) never exits on its own, so the outcome here is always
    // "we killed it".
    assert!(msg.contains("reaped with status"), "got: {msg}");
    #[cfg(unix)]
    assert!(
        msg.contains(&format!("we killed it: signal=Some({})", libc::SIGKILL)),
        "expected SIGKILL termination proof in message: {msg}"
    );
    #[cfg(windows)]
    assert!(
        msg.contains("we killed it: code=Some(1)"),
        "expected TerminateProcess termination proof in message: {msg}"
    );
}
