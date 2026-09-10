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
    let pid = child.id();
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
    // making a raw-pid kill race a pid-reuse victim). Proving that here
    // means checking the process is actually dead by pid, independent of
    // wait_bounded's own internal bookkeeping.
    assert!(msg.contains("confirmed it reaped"), "got: {msg}");
    assert!(
        !process_alive(pid),
        "child (pid {pid}) must be confirmed dead by the time wait_bounded panics"
    );
}

/// True if `pid` still names a live process. Unix: `kill(pid, 0)` is the
/// standard existence probe (no signal delivered) — success or `EPERM`
/// means the pid is alive, `ESRCH` means it is not. Windows: opening the
/// process for `SYNCHRONIZE` and checking it hasn't signalled is the
/// equivalent probe.
#[cfg(unix)]
fn process_alive(pid: u32) -> bool {
    // SAFETY: kill() with signal 0 delivers no signal — it is a pure
    // existence/permission probe, sound to call with any pid value.
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(windows)]
fn process_alive(pid: u32) -> bool {
    use windows::Win32::Foundation::{CloseHandle, WAIT_TIMEOUT};
    use windows::Win32::System::Threading::{OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE};

    // SAFETY: plain Win32 handle open/wait/close with a caller-owned HANDLE;
    // no aliasing requirements beyond closing what we open, which we do.
    unsafe {
        let Ok(handle) = OpenProcess(PROCESS_SYNCHRONIZE, false, pid) else {
            // No such process (or no permission to open a dead one's slot).
            return false;
        };
        let alive = WaitForSingleObject(handle, 0) == WAIT_TIMEOUT;
        let _ = CloseHandle(handle);
        alive
    }
}
