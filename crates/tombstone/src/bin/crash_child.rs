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
        Err(std::env::VarError::NotPresent) => "crash-child",
        // Set but unreadable is a test-authoring bug, not the default case:
        // attaching under "crash-child" here would let the run look like it
        // proved something about a kind it never used.
        Err(e @ std::env::VarError::NotUnicode(_)) => {
            panic!("TOMBSTONE_TEST_ATTACH_KIND is set to a value that is not valid Unicode: {e}")
        }
    };
    tombstone::attach(kind, &log_dir);
    plant_after_attach(kind, &log_dir);

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

/// What a user of the log directory could do between `attach` and a crash, done by the test double itself so the
/// parent needs no rendezvous with the child. `TOMBSTONE_TEST_PLANT` names it, `TOMBSTONE_TEST_VICTIM` is the file
/// (`symlink`) or directory (`swap_dir`) the plant points at, and `TOMBSTONE_TEST_MOVED` is where `swap_dir` moves
/// the log directory to.
///
/// - `symlink`: a symlink to the victim at the name the crash marker will take.
/// - `swap_dir`: the log directory renamed away and a symlink to the victim put at its path.
fn plant_after_attach(kind: &str, log_dir: &std::path::Path) {
    let plant = match std::env::var("TOMBSTONE_TEST_PLANT") {
        Ok(plant) => plant,
        Err(std::env::VarError::NotPresent) => return,
        Err(e) => panic!("TOMBSTONE_TEST_PLANT is unreadable: {e}"),
    };
    let victim = std::path::PathBuf::from(std::env::var_os("TOMBSTONE_TEST_VICTIM").expect("TOMBSTONE_TEST_VICTIM"));
    match plant.as_str() {
        "symlink" => {
            let marker = log_dir.join(format!("crash-{kind}-{}.marker", std::process::id()));
            #[cfg(unix)]
            std::os::unix::fs::symlink(&victim, &marker).expect("plant the symlink");
            #[cfg(windows)]
            std::os::windows::fs::symlink_file(&victim, &marker).expect("plant the symlink");
        }
        "swap_dir" => {
            let moved =
                std::path::PathBuf::from(std::env::var_os("TOMBSTONE_TEST_MOVED").expect("TOMBSTONE_TEST_MOVED"));
            std::fs::rename(log_dir, &moved).expect("move the log directory away");
            #[cfg(unix)]
            std::os::unix::fs::symlink(&victim, log_dir).expect("plant the directory symlink");
            #[cfg(windows)]
            std::os::windows::fs::symlink_dir(&victim, log_dir).expect("plant the directory symlink");
        }
        other => panic!("unknown TOMBSTONE_TEST_PLANT: {other}"),
    }
}
