//! Out-of-process per-fault-class crash tests.
//!
//! A native fault terminates the process, so the child crashes and the
//! PARENT (this test) asserts on the marker file the signal-safe `on_crash`
//! wrote BEFORE termination. The child is the dedicated `crash_child` bin.
//! Waiting on the child's exit is the sanctioned external-process-exit
//! no-sleep exception (the marker write happens-before the parent read via
//! process exit).
//!
//! On Windows and Linux a native fault's exit status is whatever the OS's
//! default disposition produces, so nothing here asserts on it. On macOS it
//! is a controlled fact for EVERY class: `crash::on_crash` never returns
//! there, it `_exit(70)`s. `assert_macos_terminated_by_tombstone` pins that
//! on each class, and is what fails — instead of `wait_bounded`'s bound
//! expiring — if the termination is ever weakened.
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
// fix for the underlying hang: that is addressed structurally in
// `crash::on_crash`, which on macOS terminates the process itself rather
// than returning into machinery this process cannot bound. This bound
// still earns its keep independently: it turns ANY future test-child stall,
// for ANY reason (a new fault class, a reporter regression, a platform
// change), into one test failing loudly in ~60s instead of silently
// consuming the entire darwin/amd64 job's 90-minute wall.
#[cfg(feature = "crash-child")]
const CHILD_WAIT_BOUND: std::time::Duration = std::time::Duration::from_secs(60);

// Scrub re-exec env on EVERY spawn of `crash_child_bin()` in this binary, so
// a value inherited from this process (or, since the suite runs many
// crash_child's concurrently, from a sibling test process) can't silently
// divert the child onto a branch the caller didn't ask for. This covers
// crash_child.rs's OWN test-double vars (checked before its
// TOMBSTONE_CRASH_CLASS dispatch), not just HOLE_LOGGING_TEST_KIND: an
// inherited TOMBSTONE_TEST_HANG_FOREVER would divert a real fault-class spawn
// (or an EXIT_FAST-requesting spawn) into parking forever instead. One
// helper for both spawn sites (`run_crash_child` here and `spawn_double` in
// `crash_child_wait_tests`) so the two lists cannot drift apart.
#[cfg(feature = "crash-child")]
fn scrub_reexec_env(cmd: &mut std::process::Command) -> &mut std::process::Command {
    cmd.env_remove("HOLE_LOGGING_TEST_KIND")
        .env_remove("TOMBSTONE_TEST_HANG_FOREVER")
        .env_remove("TOMBSTONE_TEST_EXIT_FAST")
        .env_remove("TOMBSTONE_TEST_ATTACH_KIND")
}

#[cfg(feature = "crash-child")]
fn run_crash_child(class: &str, log_dir: &std::path::Path) -> std::process::Output {
    run_crash_child_with_attach_kind(class, log_dir, "crash-child")
}

// Like `run_crash_child`, but overrides the child's attach kind instead of
// letting it default to `"crash-child"` — used to simulate a different real
// caller (e.g. `hole-common`'s log-bridge test helpers, which attach under
// `"test"`) hitting the same fault class.
#[cfg(feature = "crash-child")]
fn run_crash_child_with_attach_kind(class: &str, log_dir: &std::path::Path, attach_kind: &str) -> std::process::Output {
    let mut cmd = std::process::Command::new(crash_child_bin());
    scrub_reexec_env(&mut cmd);
    let child = cmd
        .env("TOMBSTONE_CRASH_CLASS", class)
        .env("TOMBSTONE_LOG_DIR", log_dir)
        .env("TOMBSTONE_TEST_ATTACH_KIND", attach_kind)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn crash_child");
    wait_bounded(child, CHILD_WAIT_BOUND)
}

/// Owns a spawned `crash_child` for the whole of `wait_bounded` and kills +
/// reaps it on EVERY exit from that body, `std::process::Child`'s own `Drop`
/// doing neither. The path this exists for is a panic unwinding out of
/// `wait_timeout` itself: wait-timeout 0.2.1 panics in four places inside
/// that call, three of them while holding its process-global
/// `Mutex<StateMap>`, which the panic then POISONS — so every later
/// `wait_bounded` in the process panics at the lock too, before its child is
/// registered anywhere. Each such unwind would otherwise strand a
/// `loop { park() }` child that outlives the test binary on the runner.
///
/// `disarm` is for the arms that reaped the child themselves: once reaped,
/// the pid is recyclable and must never be signalled again.
#[cfg(feature = "crash-child")]
struct ReapOnDrop {
    child: std::process::Child,
    reaped: bool,
}

#[cfg(feature = "crash-child")]
impl ReapOnDrop {
    fn new(child: std::process::Child) -> Self {
        Self { child, reaped: false }
    }

    fn disarm(&mut self) {
        self.reaped = true;
    }
}

#[cfg(feature = "crash-child")]
impl Drop for ReapOnDrop {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        // Best-effort by necessity: this runs while unwinding, with nothing
        // left to report an error to. `kill()` on a child that already
        // self-exited lands on a zombie and is a no-op, and `wait()` then
        // reaps whichever status is the real one.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Wait for `child` to exit, bounded by `bound`. Uses
/// `wait_timeout::ChildExt::wait_timeout` — the sanctioned child-process-exit
/// exception to the no-sleep/no-poll rule: `bound` is the failure bound
/// surfaced to a human, not a bet that `bound` is "long enough" for the
/// happy path.
///
/// What it actually does, verified against `wait-timeout` 0.2.1's vendored
/// source (`src/unix.rs`) rather than assumed from its doc comment: on
/// first use it installs a PROCESS-GLOBAL `SIGCHLD` `sigaction`; each call
/// then runs a `libc::poll(2)` loop bounded by `dur` over a per-call
/// self-pipe plus that process-global SIGCHLD self-pipe, reaping via
/// `try_wait()` (`WNOHANG`) whenever a SIGCHLD wakes it. `child` is
/// inserted, for the duration of the call, into a process-global
/// `Mutex<HashMap<*mut Child, _>>`, and `State::process_sigchlds`
/// dereferences and `try_wait()`s every entry in that map from WHICHEVER
/// thread's `poll` happens to drain the shared SIGCHLD pipe first — not
/// necessarily this one, since every thread currently waiting has that same
/// fd registered. The crate's own doc comment warns "if your application is
/// otherwise handling SIGCHLD then bugs may arise"; no other code in this
/// workspace installs a SIGCHLD handler today, but `crash_child` (which
/// attaches tombstone's own crash handler) is exactly the kind of target
/// where that caveat would matter if it ever did.
///
/// The guarantee `Ok(None)` (timeout) actually gives: this call's own
/// SIGCHLD-driven reap never observed `child` exit, so `child`'s pid is
/// unreaped and therefore not recyclable — `child.kill()` cannot target a
/// process the OS has freed and reassigned. It does NOT guarantee `child`
/// is still running: the loop's final iteration can find `elapsed >= dur`
/// and return before draining a SIGCHLD that arrived moments earlier, so a
/// child that exits right at the bound is a live, unreaped ZOMBIE when
/// `Ok(None)` returns. `kill()` on a zombie is a harmless no-op (POSIX:
/// signal delivery to a zombie has no effect), and the following `wait()`
/// then reaps the child's OWN exit status, not one our SIGKILL caused — see
/// the `Ok(None)` arm below, which asserts accordingly.
#[cfg(feature = "crash-child")]
fn wait_bounded(child: std::process::Child, bound: std::time::Duration) -> std::process::Output {
    use wait_timeout::ChildExt;

    // Every exit from here on is covered by the guard, including an unwind
    // out of `wait_timeout` itself; the arms that reap the child themselves
    // disarm it.
    let mut guard = ReapOnDrop::new(child);
    let pid = guard.child.id();
    match guard.child.wait_timeout(bound) {
        Ok(Some(status)) => {
            // wait_timeout reaped it.
            guard.disarm();
            std::process::Output {
                status,
                stdout: Vec::new(),
                stderr: Vec::new(),
            }
        }
        Ok(None) => {
            // kill() here is safe even if `child` already self-exited into a
            // zombie (doc comment above) — it's a no-op, and wait() below
            // reaps the real exit status.
            guard.child.kill().expect("SIGKILL a timed-out crash_child");
            let status = guard.child.wait().expect("reap crash_child after SIGKILL");
            // Reaped above, so the pid is recyclable from here: the guard
            // must not signal it again on the way out through the panic.
            guard.disarm();
            // kill()-then-wait() proves only that THIS Child reached SOME
            // reaped terminal state — not which of the two races above
            // produced it, so name the outcome rather than assume the
            // SIGKILL one. Unix `kill()` delivers SIGKILL, so
            // `signal() == Some(SIGKILL)` means our kill landed on a live
            // process; any other terminal status means the child had
            // already self-exited before `kill()` ran. Windows `kill()` is
            // `TerminateProcess(_, 1)`, so `code() == Some(1)` is the
            // equivalent "we killed it" signature there.
            #[cfg(unix)]
            let termination_proof = {
                use std::os::unix::process::ExitStatusExt;
                if status.signal() == Some(libc::SIGKILL) {
                    format!("we killed it: signal={:?}", status.signal())
                } else {
                    format!(
                        "it had already self-exited before our kill() landed: signal={:?} code={:?}",
                        status.signal(),
                        status.code()
                    )
                }
            };
            #[cfg(windows)]
            let termination_proof = {
                if status.code() == Some(1) {
                    format!("we killed it: code={:?}", status.code())
                } else {
                    format!(
                        "it had already self-exited before our kill() landed: code={:?}",
                        status.code()
                    )
                }
            };
            panic!(
                "crash_child (pid {pid}) did not exit within {bound:?} — reaped with status \
                 {status:?} ({termination_proof}). This is the child-process-exit failure \
                 bound, not a synchronization timeout: if this fires, the child genuinely \
                 stalled and needs investigation, not a longer bound. On macOS `crash::on_crash` \
                 terminates the process itself, so a stall there means it never reached that \
                 call — e.g. the marker write itself blocked."
            );
        }
        Err(e) => {
            // wait_timeout() itself failed (not a timeout) — `child` may
            // still be running with no disposition recorded anywhere. Left
            // ARMED: the guard kills and reaps it as this panic unwinds.
            panic!("crash_child (pid {pid}): wait_timeout() failed: {e}")
        }
    }
}

#[cfg(feature = "crash-child")]
fn assert_marker(log_dir: &std::path::Path, kind: &str, expect_code_nonzero: bool) {
    // Find the single crash-<kind>-*.marker the child wrote.
    let prefix = format!("crash-{kind}-");
    let marker = std::fs::read_dir(log_dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with(&prefix) && n.ends_with(".marker"))
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
    assert!(text.contains(&format!("\nkind={kind}\n")), "marker kind: {text}");
    let pid = marker_field(&text, "pid").expect("pid field present");
    assert_ne!(pid, "0", "marker pid set: {text}");
    if expect_code_nonzero {
        let code = marker_field(&text, "code").expect("code field present");
        assert_ne!(code, "0x0", "marker code set: {text}");
    }
}

/// macOS: `crash::on_crash` never returns — it writes the marker and then
/// `_exit(EX_SOFTWARE)`s, for every fault class and every attach kind. So
/// the child's exit status is a controlled fact rather than whatever the
/// OS's default disposition for that signal would produce, and asserting on
/// it pins the termination directly.
///
/// This is the one assertion that catches a weakened termination as a
/// FAILURE rather than as `wait_bounded`'s bound expiring: neutralise the
/// `_exit`, or make it conditional on the fault class / attach kind / a
/// cargo feature again, and the affected classes die by their raw signal
/// here instead.
#[cfg(all(feature = "crash-child", target_os = "macos"))]
fn assert_macos_terminated_by_tombstone(output: &std::process::Output, case: &str) {
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(
        output.status.signal(),
        None,
        "{case}: on_crash must terminate the child itself, not let it die by a signal: {:?}",
        output.status
    );
    assert_eq!(
        output.status.code(),
        Some(70),
        "{case}: child must exit with EX_SOFTWARE (70): {:?}",
        output.status
    );
}

/// Windows/Linux keep the OS default disposition, so there is no controlled
/// exit status to assert. Taking `output` anyway keeps every call site
/// uniform, and the call site's BORROW of it is what reads `output` on
/// non-macOS builds — ownership stays with the caller, so nothing needs an
/// `unused` shim.
#[cfg(all(feature = "crash-child", not(target_os = "macos")))]
fn assert_macos_terminated_by_tombstone(_output: &std::process::Output, _case: &str) {}

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
            let output = run_crash_child($class, dir.path());
            assert_marker(dir.path(), "crash-child", true);
            assert_macos_terminated_by_tombstone(&output, $class);
        }
    };
}

// Cross-platform fault classes. Every one of them asserts the macOS exit
// status, because the termination there is unconditional across classes —
// `stack_overflow` included, which matters most: it arrives as a genuine
// `EXC_BAD_ACCESS` guard-page fault, and terminating on that first delivery
// means Rust's own stack-overflow handler (which responds by calling
// `abort()`) never runs at all.
crash_class_test!(crash_marker_segfault, "segfault");
crash_class_test!(crash_marker_abort, "abort");
crash_class_test!(crash_marker_stack_overflow, "stack_overflow");
crash_class_test!(crash_marker_illegal_instruction, "illegal_instruction");
crash_class_test!(crash_marker_trap, "trap");

// The one class NOT covered by `crash_class_test!`, because it varies the
// attach KIND rather than the fault class. `crash::on_crash`'s macOS
// termination deliberately has no `kind` discriminator: `kind` never
// identified a process in the first place (`hole-common`'s log-bridge test
// helpers attach as `"test"`, the same string a `hole` test process uses),
// and a shipped `hole`/`hole bridge`/`galoshes` must not hang either.
// Re-introduce any `self.state.kind == …` guard and this child — attaching
// under a kind the guard would not name — dies by raw SIGABRT instead.
#[cfg(feature = "crash-child")]
#[skuld::test]
fn crash_marker_abort_under_a_foreign_attach_kind_terminates_the_same_way() {
    let dir = tempfile::tempdir().expect("tempdir");
    let output = run_crash_child_with_attach_kind("abort", dir.path(), "test");
    assert_marker(dir.path(), "test", true);
    assert_macos_terminated_by_tombstone(&output, "abort under kind=test");
}

// `TOMBSTONE_TEST_ATTACH_KIND` set to something that is not valid Unicode is
// a DIFFERENT thing from it being unset: the variable was provided and could
// not be read, which is a test-authoring bug. Folding it into the
// "not present" default would attach under `"crash-child"` and let the run
// look like it proved something about a kind it never used, so the child
// must die on it instead. Every other env read in that bin fails loudly the
// same way.
#[cfg(feature = "crash-child")]
#[skuld::test]
fn a_non_unicode_attach_kind_fails_loudly_instead_of_defaulting_to_crash_child() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cmd = std::process::Command::new(crash_child_bin());
    scrub_reexec_env(&mut cmd);
    let mut child = cmd
        .env("TOMBSTONE_CRASH_CLASS", "abort")
        .env("TOMBSTONE_LOG_DIR", dir.path())
        .env("TOMBSTONE_TEST_ATTACH_KIND", non_unicode_attach_kind())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn crash_child");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let output = wait_bounded(child, CHILD_WAIT_BOUND);

    assert!(
        !output.status.success(),
        "child must not succeed on an unreadable attach kind: {:?}",
        output.status
    );
    let mut msg = String::new();
    std::io::Read::read_to_string(&mut stderr, &mut msg).expect("read the child's stderr to EOF");
    assert!(
        msg.contains("TOMBSTONE_TEST_ATTACH_KIND"),
        "the failure must name the variable that could not be read: {msg}"
    );
    // It must have died BEFORE attaching: a marker under any kind means it
    // fell through into the default and ran the crash class regardless.
    let markers: Vec<std::path::PathBuf> = std::fs::read_dir(dir.path())
        .expect("read log dir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.ends_with(".marker"))
                .unwrap_or(false)
        })
        .collect();
    assert!(markers.is_empty(), "no crash marker may be written: {markers:?}");
}

/// A `TOMBSTONE_TEST_ATTACH_KIND` value the OS accepts and `String` cannot
/// hold, so `std::env::var` yields `VarError::NotUnicode`.
#[cfg(all(feature = "crash-child", unix))]
fn non_unicode_attach_kind() -> std::ffi::OsString {
    // A lone 0xFF is not valid UTF-8 in any position.
    use std::os::unix::ffi::OsStringExt;
    std::ffi::OsString::from_vec(vec![b'k', 0xff, b'd'])
}

/// Windows twin of the above: an unpaired high surrogate is valid WTF-16 —
/// which is what the environment block stores — and not valid UTF-16.
#[cfg(all(feature = "crash-child", windows))]
fn non_unicode_attach_kind() -> std::ffi::OsString {
    use std::os::windows::ffi::OsStringExt;
    std::ffi::OsString::from_wide(&[0x006b, 0xd800, 0x0064])
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
// Windows — the only platform with an in-process dump branch left. Linux
// never had one (the carve-out); macOS gave its up so that `on_crash` can
// terminate without ever allocating (see `crash.rs`).
#[cfg(all(feature = "crash-dumps", feature = "crash-child", windows))]
#[skuld::test]
fn crash_writes_minidump_segfault() {
    let dir = tempfile::tempdir().expect("tempdir");
    let _ = run_crash_child("segfault", dir.path());
    // The .dmp sits next to the marker: crash-crash-child-<pid>.dmp.
    let dmp = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("crash-crash-child-") && n.ends_with(".dmp"))
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
