//! Unit tests for `wait_bounded`. Uses `crash_child`'s
//! `TOMBSTONE_TEST_HANG_FOREVER`/`TOMBSTONE_TEST_EXIT_FAST` test doubles
//! instead of a real native fault, so these tests are deterministic and fast
//! (bounds here are small — a few hundred ms — unlike `CHILD_WAIT_BOUND`'s
//! production 60s).

use crate::{crash_child_bin, scrub_reexec_env, wait_bounded};
use std::time::Duration;

fn spawn_double(env_var: &str) -> std::process::Child {
    spawn_double_with_stdout(env_var, std::process::Stdio::null())
}

fn spawn_double_with_stdout(env_var: &str, stdout: std::process::Stdio) -> std::process::Child {
    let mut cmd = std::process::Command::new(crash_child_bin());
    // Scrub first, THEN set `env_var` — scrubbing after would remove the
    // very double this call is trying to select.
    scrub_reexec_env(&mut cmd);
    cmd.env(env_var, "1")
        .stdin(std::process::Stdio::null())
        .stdout(stdout)
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

// `wait_bounded`'s child must be killed and reaped on EVERY exit from its
// body, not just the two it returns from. wait-timeout 0.2.1 panics in four
// places inside `wait_timeout` itself — three of them holding its
// process-global `Mutex<StateMap>`, which the panic then poisons, so every
// later call in the process panics at the lock before its child is
// registered anywhere. `std::process::Child::drop` neither kills nor reaps,
// and this suite's stalled double is `loop { park() }`, so each such unwind
// would leave a child that outlives the test binary on the runner.
//
// The panic is raised directly here rather than provoked out of
// `wait_timeout`: what must hold is that ANY unwind through the guarded
// region ends with the child dead and reaped, and wait-timeout's own panic
// sites are not reachable on demand.
#[skuld::test]
fn an_unwind_through_the_guard_kills_and_reaps_the_child() {
    let mut child = spawn_double_with_stdout("TOMBSTONE_TEST_HANG_FOREVER", std::process::Stdio::piped());
    let pid = child.id();
    // The child's end of this pipe is closed by the OS when it dies, so
    // reading it to EOF is a rendezvous on its death, not a poll.
    let mut stdout = child.stdout.take().expect("piped stdout");

    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = crate::ReapOnDrop::new(child);
        panic!("models a panic unwinding out of wait_timeout");
    }));
    assert!(unwound.is_err(), "the region must have unwound");

    // Reaped: this process no longer has such a child, which only the
    // guard's own `wait()` can have made true. A still-running leak answers
    // 0 instead, and an unreaped zombie answers `pid`.
    #[cfg(unix)]
    {
        let mut status = 0i32;
        let r = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
        let errno = std::io::Error::last_os_error().raw_os_error();
        assert_eq!(
            (r, errno),
            (-1, Some(libc::ECHILD)),
            "crash_child (pid {pid}) was not reaped by the guard: waitpid said ({r}, {errno:?})"
        );
    }

    // Dead: every write end of the pipe is closed, and the child held the
    // only one.
    use std::io::Read;
    let mut out = Vec::new();
    stdout.read_to_end(&mut out).expect("read the child's stdout to EOF");
    assert!(
        out.is_empty(),
        "the hang-forever double (pid {pid}) writes nothing: {out:?}"
    );
}
