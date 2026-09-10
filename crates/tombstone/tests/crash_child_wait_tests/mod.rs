//! Unit tests for `wait_bounded`/`kill_pid_best_effort` (bindreams/hole#842,
//! #719). Uses `crash_child`'s `TOMBSTONE_TEST_HANG_FOREVER`/
//! `TOMBSTONE_TEST_EXIT_FAST` test doubles instead of a real native fault, so
//! these tests are deterministic and fast (bounds here are small — a few
//! hundred ms — unlike `CHILD_WAIT_BOUND`'s production 60s).

use crate::{crash_child_bin, kill_pid_best_effort, wait_bounded};
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
    let output = wait_bounded(child, Duration::from_secs(10));
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
}

#[skuld::test]
fn kill_pid_best_effort_terminates_a_running_child() {
    let child = spawn_double("TOMBSTONE_TEST_HANG_FOREVER");
    let pid = child.id();

    kill_pid_best_effort(pid);

    // Confirm the SIGKILL actually took effect, bounded the same way
    // production code is — a hung kill is exactly the failure this test
    // exists to catch.
    let output = wait_bounded(child, Duration::from_secs(10));
    assert!(
        !output.status.success(),
        "killed child must not report success: {:?}",
        output.status
    );
}
