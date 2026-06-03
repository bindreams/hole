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

#[cfg(feature = "crash-child")]
fn run_crash_child(class: &str, log_dir: &std::path::Path) -> std::process::Output {
    std::process::Command::new(crash_child_bin())
        .env("TOMBSTONE_CRASH_CLASS", class)
        .env("TOMBSTONE_LOG_DIR", log_dir)
        // Scrub re-exec env so the child doesn't take a foreign branch.
        .env_remove("HOLE_LOGGING_TEST_KIND")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .expect("spawn crash_child")
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
crash_class_test!(crash_marker_floating_point, "floating_point_exception");
crash_class_test!(crash_marker_trap, "trap");

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
