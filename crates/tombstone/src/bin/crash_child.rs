//! Test helper for tombstone's per-fault-class crash tests. Reads the fault
//! class + log dir from the environment, attaches the crash handler, then
//! deterministically raises the requested native fault via sadness-generator.
//! The process terminates; the PARENT test asserts on the marker file that
//! the signal-safe on_crash wrote before termination.
//!
//! No sleeps. Modeled on crates/handle-holders/src/bin/hold_file.rs.

fn main() {
    let class = std::env::var("TOMBSTONE_CRASH_CLASS").expect("TOMBSTONE_CRASH_CLASS env var required");
    let log_dir = std::env::var_os("TOMBSTONE_LOG_DIR").expect("TOMBSTONE_LOG_DIR env var required");
    let log_dir = std::path::PathBuf::from(log_dir);

    tombstone::attach("test", &log_dir);

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
