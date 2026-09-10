//! Out-of-process per-fault-class crash tests.
//!
//! A native fault terminates the process, so the child crashes and the
//! PARENT (this test) asserts on the marker file the signal-safe `on_crash`
//! wrote BEFORE termination. The child is the dedicated `crash_child` bin.
//! Waiting on the child's exit is the sanctioned external-process-exit
//! no-sleep exception (the marker write happens-before the parent read via
//! process exit). We do NOT assert on the exit STATUS — a native fault's
//! exit code is non-deterministic across platforms/fault-classes.
//!
//! Integration-test target, not a unit-test module, because
//! `CARGO_BIN_EXE_crash_child` is only set for `tests/*.rs` (and benches),
//! never for the lib's own unit tests. This mirrors the workspace's
//! `handle-holders/tests/live_holders.rs`, which the `crash_child` bin is
//! itself modeled on.
//!
//! EVERYTHING here is gated behind `#[cfg(feature = "crash-child")]`: it
//! references `CARGO_BIN_EXE_crash_child`, which only exists when the
//! crash_child bin is built (its `required-features = ["crash-child"]`).
//! Under a plain `cargo build --workspace` (no crash-child) the bin is skipped
//! and this target compiles down to a bare test runner. See review M1/M2.

// Install the workspace test subscriber + panic hook. See
// `crates/test-observability/` and bindreams/hole#301.
hole_test_observability::register!();

fn main() {
    skuld::run_all();
}

#[cfg(feature = "crash-child")]
fn crash_child_bin() -> std::path::PathBuf {
    // Prefer the runtime `CARGO_BIN_EXE_crash_child` env var (set by nextest's
    // archive workflow when the binary is extracted to a temp dir on the
    // runner). Fall back to the compile-time value via `env!()` for plain
    // `cargo test` invocations on the build host. Mirrors live_holders.rs.
    std::path::PathBuf::from(
        std::env::var("CARGO_BIN_EXE_crash_child").unwrap_or_else(|_| env!("CARGO_BIN_EXE_crash_child").to_string()),
    )
}

// Production bound for waiting on a crash_child to exit. 60s is ~2 orders
// of magnitude above every observed passing run (<1s) and exists ONLY as
// the failure bound surfaced to a human when a child genuinely never exits
// (the sanctioned no-sleep exception: "awaiting … a child-process exit …
// where the timeout is the failure bound surfaced to a human," never a bet
// that N is long enough for the happy path). It is a SAFETY NET, not the
// fix for bindreams/hole#842/#719: the actual cause — macOS's SIGABRT relay
// taking a second trip through the host crash reporter — is addressed
// structurally in `crash::is_macos_sigabrt_relay`/`on_crash`, which stops
// `crash_marker_abort`'s child from ever reaching the reporter. This bound
// still earns its keep independently: it turns ANY future test-child stall,
// for ANY reason (a new fault class, a reporter regression, a platform
// change), into one test failing loudly in ~60s instead of silently
// consuming the entire darwin/amd64 job's 90-minute wall — which is exactly
// what happened before (observed: orphaned crash_child/crash_child-2fe/
// cargo-nextest processes reaped at the wall, still waiting on each other).
#[cfg(feature = "crash-child")]
const CHILD_WAIT_BOUND: std::time::Duration = std::time::Duration::from_secs(60);

#[cfg(feature = "crash-child")]
fn run_crash_child(class: &str, log_dir: &std::path::Path) -> std::process::Output {
    let child = std::process::Command::new(crash_child_bin())
        .env("TOMBSTONE_CRASH_CLASS", class)
        .env("TOMBSTONE_LOG_DIR", log_dir)
        // Scrub re-exec env so the child doesn't take a foreign branch.
        .env_remove("HOLE_LOGGING_TEST_KIND")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn crash_child");
    wait_bounded(child, CHILD_WAIT_BOUND)
}

/// Wait for `child` to exit, bounded by `bound`. The wait itself is a real
/// blocking `Child::wait()` on a dedicated thread — NOT a sleep/poll loop —
/// relayed back via a channel so it can be raced against the bound with
/// `recv_timeout`. On timeout, best-effort SIGKILLs the child (so it cannot
/// itself go on to hang some *other* process, e.g. a wedged system crash
/// reporter) and panics with a message naming the pid and the bound, per
/// this codebase's rule that a timeout here must be a clearly-reported
/// failure bound, never a synchronization assumption.
#[cfg(feature = "crash-child")]
fn wait_bounded(mut child: std::process::Child, bound: std::time::Duration) -> std::process::Output {
    let pid = child.id();
    let (tx, rx) = std::sync::mpsc::channel();
    // The child is fully redirected to Stdio::null() (see run_crash_child),
    // so there is no pipe to drain concurrently with wait() the way
    // Child::wait_with_output's reader threads exist for — a single
    // blocking wait() on this thread is sufficient.
    std::thread::spawn(move || {
        let status = child.wait();
        // A disconnected receiver only means the timeout arm already fired
        // and moved on; nothing left to report to.
        let _ = tx.send(status);
    });

    match rx.recv_timeout(bound) {
        Ok(Ok(status)) => std::process::Output {
            status,
            stdout: Vec::new(),
            stderr: Vec::new(),
        },
        Ok(Err(e)) => panic!("crash_child (pid {pid}): wait() failed: {e}"),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            kill_pid_best_effort(pid);
            panic!(
                "crash_child (pid {pid}) did not exit within {bound:?} — sent SIGKILL as a \
                 safety net. This is the child-process-exit failure bound from \
                 bindreams/hole#842/#719, not a synchronization timeout: if this fires, the \
                 child genuinely stalled (most likely exposure to the macOS crash reporter that \
                 `crash::is_macos_sigabrt_relay` is meant to prevent) and needs investigation, \
                 not a longer bound."
            );
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            panic!("crash_child (pid {pid}): wait thread dropped its sender without a result")
        }
    }
}

/// Best-effort SIGKILL (unix) / TerminateProcess (Windows) by raw pid. Takes
/// a bare pid rather than `&Child` because by the time a caller needs this
/// (a bounded wait timed out), the `Child` handle has already been moved
/// into the wait thread — see `wait_bounded`. SIGKILL is chosen deliberately
/// over a milder signal: it terminates a process even mid-exception-handling
/// (XNU cannot mask SIGKILL), which is the exact state this helper exists to
/// break out of. Errors (already exited, no such pid, permission) are
/// swallowed — a target that is already gone is not a bug here.
#[cfg(all(feature = "crash-child", unix))]
fn kill_pid_best_effort(pid: u32) {
    // SAFETY: libc::kill with any pid value is always sound to call — it is
    // a plain syscall wrapper with no aliasing/lifetime requirements; the
    // kernel itself rejects an invalid target (ESRCH), which is ignored
    // here (best-effort).
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGKILL);
    }
}

#[cfg(all(feature = "crash-child", windows))]
fn kill_pid_best_effort(pid: u32) {
    let _ = std::process::Command::new("taskkill")
        .args(["/F", "/PID", &pid.to_string()])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

#[cfg(feature = "crash-child")]
fn assert_marker(log_dir: &std::path::Path, expect_code_nonzero: bool) {
    // Find the single crash-test-*.marker the child wrote.
    let marker = std::fs::read_dir(log_dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("crash-test-") && n.ends_with(".marker"))
                .unwrap_or(false)
        })
        .expect("crash marker exists");
    let text = std::fs::read_to_string(&marker).expect("read marker");
    // Integration tests cannot reach the crate-internal `parse_marker`
    // (`pub(crate)`), so assert on the marker's keyed text directly. The
    // round-trip of `format_marker_into`/`parse_marker` is covered by the
    // in-crate unit tests; here we only verify on_crash wrote the right
    // fields on a real fault.
    assert!(text.starts_with("tombstone-marker v1\n"), "marker magic: {text}");
    assert!(text.contains("\nkind=test\n"), "marker kind: {text}");
    let pid = marker_field(&text, "pid").expect("pid field present");
    assert_ne!(pid, "0", "marker pid set: {text}");
    if expect_code_nonzero {
        let code = marker_field(&text, "code").expect("code field present");
        assert_ne!(code, "0x0", "marker code set: {text}");
    }
}

#[cfg(feature = "crash-child")]
fn marker_field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines()
        .filter_map(|l| l.split_once('='))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
}

// Every generated test is gated `#[cfg(feature = "crash-child")]` (it spawns
// the crash_child bin, which only exists under that feature). The optional
// `$cfg` adds the per-class platform gate on top. See review M1/M2.
macro_rules! crash_class_test {
    ($name:ident, $class:literal $(, $cfg:meta)?) => {
        #[cfg(feature = "crash-child")]
        $(#[cfg($cfg)])?
        #[skuld::test]
        fn $name() {
            let dir = tempfile::tempdir().expect("tempdir");
            let _ = run_crash_child($class, dir.path());
            assert_marker(dir.path(), true);
        }
    };
}

// Cross-platform fault classes.
crash_class_test!(crash_marker_segfault, "segfault");
crash_class_test!(crash_marker_stack_overflow, "stack_overflow");
crash_class_test!(crash_marker_abort, "abort");
crash_class_test!(crash_marker_illegal_instruction, "illegal_instruction");
crash_class_test!(crash_marker_trap, "trap");

// x86-only: integer divide-by-zero raises SIGFPE on x86, but is non-trapping on
// AArch64 (the ISA returns 0 instead of faulting). There is no crash to observe
// on arm64, so this fault class can't be exercised there.
crash_class_test!(
    crash_marker_floating_point,
    "floating_point_exception",
    not(target_arch = "aarch64")
);

// Windows-only fault classes.
crash_class_test!(crash_marker_purecall, "purecall", windows);
crash_class_test!(crash_marker_invalid_parameter, "invalid_parameter", windows);
crash_class_test!(crash_marker_heap_corruption, "heap_corruption", windows);

// Unix-only fault class.
crash_class_test!(crash_marker_bus, "bus", unix);

// Gated on BOTH features (crash-dumps = the .dmp branch under test;
// crash-child = it spawns the crash_child bin via run_crash_child) AND on
// Win/mac — Linux intentionally writes NO in-process .dmp (the carve-out),
// so this assertion is meaningful only on the platforms with a dump branch.
#[cfg(all(feature = "crash-dumps", feature = "crash-child", any(windows, target_os = "macos")))]
#[skuld::test]
fn crash_writes_minidump_segfault() {
    let dir = tempfile::tempdir().expect("tempdir");
    let _ = run_crash_child("segfault", dir.path());
    // The .dmp sits next to the marker: crash-test-<pid>.dmp.
    let dmp = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("crash-test-") && n.ends_with(".dmp"))
                .unwrap_or(false)
        });
    let dmp = dmp.expect("minidump written under crash-dumps feature");
    let len = std::fs::metadata(&dmp).expect("dmp metadata").len();
    assert!(len > 0, "minidump is non-empty");
}

// `tests/crash_child_wait_tests/mod.rs`, NOT a bare `tests/crash_child_wait_tests.rs`
// — Cargo autodiscovers every top-level `tests/*.rs` file as its OWN
// integration-test binary, which would double-compile this module as a
// standalone (harness-having, `fn main`-less) target and fail with
// "unresolved import" on its sibling helpers. The `<dir>/mod.rs` form is
// invisible to that autodiscovery glob. See `crates/garter/tests/common/`
// for the established precedent.
#[cfg(feature = "crash-child")]
mod crash_child_wait_tests;
