//! Out-of-process per-fault-class crash tests.
//!
//! A native fault terminates the process, so the child crashes and the
//! PARENT (this test) asserts on the marker file the signal-safe `on_crash`
//! wrote BEFORE termination. The child is the dedicated `crash_child` bin.
//! Waiting on the child's exit is the sanctioned external-process-exit
//! no-sleep exception (the marker write happens-before the parent read via
//! process exit). We do NOT assert on the exit STATUS for most classes — a
//! native fault's exit code is non-deterministic across platforms/fault
//! classes. The one deliberate exception is `crash_marker_abort` on macOS,
//! where `crash::on_crash`'s `_exit(EX_SOFTWARE)` bypass makes the exit
//! status a controlled, assertable fact instead of "whatever the OS's
//! default disposition for this signal happens to produce" — see that test
//! and review B5.
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
        // Scrub re-exec env so the child doesn't take a foreign branch — this
        // includes crash_child.rs's OWN test-double vars (checked before its
        // TOMBSTONE_CRASH_CLASS dispatch), not just HOLE_LOGGING_TEST_KIND: an
        // inherited TOMBSTONE_TEST_HANG_FOREVER/EXIT_FAST from a parent test
        // process would silently divert this child away from the real fault
        // class it was just told to raise.
        .env_remove("HOLE_LOGGING_TEST_KIND")
        .env_remove("TOMBSTONE_TEST_HANG_FOREVER")
        .env_remove("TOMBSTONE_TEST_EXIT_FAST")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn crash_child");
    wait_bounded(child, CHILD_WAIT_BOUND)
}

/// Wait for `child` to exit, bounded by `bound`. Uses
/// `wait_timeout::ChildExt::wait_timeout`, which races a real blocking wait
/// against the bound WITHOUT ever moving `child` off this stack frame — NOT
/// a sleep/poll loop, and critically NOT the earlier design's background
/// thread + channel, which could report `Timeout` after the *thread* had
/// already reaped the pid, racing a same-pid-reused victim process into
/// `kill_pid_best_effort`. Because `child` is never handed to another
/// thread, `Ok(None)` (timeout) is a hard guarantee that this exact pid has
/// not yet been reaped — `child.kill()` cannot target a process the OS has
/// recycled. See bindreams/hole#842/#719 review B3.
#[cfg(feature = "crash-child")]
fn wait_bounded(mut child: std::process::Child, bound: std::time::Duration) -> std::process::Output {
    use wait_timeout::ChildExt;

    let pid = child.id();
    match child.wait_timeout(bound) {
        Ok(Some(status)) => std::process::Output {
            status,
            stdout: Vec::new(),
            stderr: Vec::new(),
        },
        Ok(None) => {
            // Timed out — `child` is still live and still ours (see doc
            // comment above), so `kill()` + `wait()` cannot hit a recycled
            // pid. SIGKILL is deliberate over a milder signal: it terminates
            // a process even mid-exception-handling (XNU cannot mask
            // SIGKILL), which is the exact state this exists to break out
            // of. `wait()` after `kill()` confirms the kill actually landed
            // before we report failure, rather than merely asserting we
            // asked.
            child.kill().expect("SIGKILL a timed-out crash_child");
            let status = child.wait().expect("reap crash_child after SIGKILL");
            panic!(
                "crash_child (pid {pid}) did not exit within {bound:?} — sent SIGKILL as a \
                 safety net and confirmed it reaped with status {status:?}. This is the \
                 child-process-exit failure bound from bindreams/hole#842/#719, not a \
                 synchronization timeout: if this fires, the child genuinely stalled (most \
                 likely exposure to the macOS crash reporter that `crash::is_macos_sigabrt_relay` \
                 is meant to prevent) and needs investigation, not a longer bound."
            );
        }
        Err(e) => panic!("crash_child (pid {pid}): wait_timeout() failed: {e}"),
    }
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
crash_class_test!(crash_marker_illegal_instruction, "illegal_instruction");
crash_class_test!(crash_marker_trap, "trap");

// `abort` is written by hand, NOT via `crash_class_test!`, because — unlike
// every other class, whose exit status is genuinely non-deterministic
// across platforms (see the file header) — macOS's abort case is made
// deterministic on purpose by `crash::on_crash`'s `_exit(EX_SOFTWARE)`
// bypass (bindreams/hole#842/#719 review B4/B5), and that determinism is
// exactly what this test needs somewhere to assert on.
#[cfg(feature = "crash-child")]
#[skuld::test]
fn crash_marker_abort() {
    let dir = tempfile::tempdir().expect("tempdir");
    let output = run_crash_child("abort", dir.path());
    assert_marker(dir.path(), true);

    // macOS only: this is the one platform/class combination where
    // `on_crash`'s `_exit(EX_SOFTWARE)` bypass fires (see
    // `is_macos_sigabrt_relay`), so it is the one place an exit-status
    // assertion is meaningful rather than a coin flip. It exists to catch a
    // regression in the bypass itself: delete the `_exit` call, or weaken
    // its `#[cfg(all(target_os = "macos", feature = "crash-child"))]`/
    // `kind == "test"` conjunction, and this assertion fails — either the
    // child goes on to deliver a raw, differently-coded `SIGABRT`, or (the
    // actual #842/#719 bug) it hangs and `wait_bounded`'s 60s bound fails
    // the test instead.
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(
            output.status.signal(),
            None,
            "abort child must exit via _exit(EX_SOFTWARE), not be killed by a signal: {:?}",
            output.status
        );
        assert_eq!(
            output.status.code(),
            Some(70),
            "abort child must exit with EX_SOFTWARE (70): {:?}",
            output.status
        );
    }
    // Non-macOS: `output` is read only inside the block above.
    #[cfg(not(target_os = "macos"))]
    let _ = &output;
}

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
