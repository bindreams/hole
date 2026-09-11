//! Test helper for tombstone's per-fault-class crash tests. Reads the fault
//! class + log dir from the environment, attaches the crash handler, then
//! deterministically raises the requested native fault via sadness-generator.
//! The process terminates; the PARENT test asserts on the marker file that
//! the signal-safe on_crash wrote before termination.
//!
//! Also doubles as the child-process test double for
//! `tests/crash_child_wait_tests/mod.rs`'s `wait_bounded` unit tests:
//! `TOMBSTONE_TEST_HANG_FOREVER` and `TOMBSTONE_TEST_EXIT_FAST`, checked
//! before any crash-class handling below, give those tests a child whose
//! exit timing is deterministic without needing a real native fault.
//!
//! Attaches under its own dedicated `"crash-child"` kind by default, purely
//! so the marker filename is unambiguous when several tests run at once.
//! `crash::on_crash` does NOT branch on `kind`, and
//! `TOMBSTONE_TEST_ATTACH_KIND` lets a test prove it by attaching under a
//! kind a real `hole-{gui,bridge,common}` process would use.
//!
//! No sleeps. Modeled on crates/handle-holders/src/bin/hold_file.rs.

fn main() {
    // Test doubles ONLY — not part of the TOMBSTONE_CRASH_CLASS dispatch
    // below, and unconditionally return/park so a test setting either var
    // never falls through into real crash-class handling.
    if std::env::var_os("TOMBSTONE_TEST_HANG_FOREVER").is_some() {
        // Deliberately never exits on its own: models "a child process that
        // might genuinely never exit" so wait_bounded's own timeout path is
        // exercised against a real stalled child, not simulated. `park()`
        // blocks without polling — this is the test double's designed
        // behavior (there is nothing to wake it), not a synchronization
        // wait, so it does not fall under the no-sleep/no-poll rule.
        loop {
            std::thread::park();
        }
    }
    if std::env::var_os("TOMBSTONE_TEST_EXIT_FAST").is_some() {
        return;
    }

    let class = std::env::var("TOMBSTONE_CRASH_CLASS").expect("TOMBSTONE_CRASH_CLASS env var required");
    let log_dir = std::env::var_os("TOMBSTONE_LOG_DIR").expect("TOMBSTONE_LOG_DIR env var required");
    let log_dir = std::path::PathBuf::from(log_dir);

    // Defaults to this binary's own dedicated kind (see the module doc
    // comment); a test can override it to simulate a different real caller.
    // `Box::leak` is fine here: this process crashes or exits within
    // milliseconds of this call.
    let kind: &'static str = match std::env::var("TOMBSTONE_TEST_ATTACH_KIND") {
        Ok(k) => Box::leak(k.into_boxed_str()),
        Err(_) => "crash-child",
    };
    tombstone::attach(kind, &log_dir);

    // SAFETY: each raise_* deterministically triggers its fault class and
    // does not return (-> !). This is the entire purpose of this binary.
    unsafe {
        match class.as_str() {
            "segfault" => sadness_generator::raise_segfault(),
            "stack_overflow" => sadness_generator::raise_stack_overflow(),
            "abort" => sadness_generator::raise_abort(),
            "illegal_instruction" => sadness_generator::raise_illegal_instruction(),
            "floating_point_exception" => sadness_generator::raise_floating_point_exception(),
            "trap" => sadness_generator::raise_trap(),
            #[cfg(windows)]
            "purecall" => sadness_generator::raise_purecall(),
            #[cfg(windows)]
            "invalid_parameter" => sadness_generator::raise_invalid_parameter(),
            #[cfg(windows)]
            "heap_corruption" => sadness_generator::raise_heap_corruption(),
            #[cfg(unix)]
            "bus" => sadness_generator::raise_bus(),
            other => panic!("unknown crash class: {other}"),
        }
    }
}
