pub mod config;
pub mod import;
pub mod logging;
pub mod paths;
pub mod protocol;
pub mod version;

#[cfg(test)]
fn main() {
    // FD-redirect tests in `logging_tests.rs` re-invoke the test binary as a
    // child with `HOLE_LOGGING_TEST_KIND` set. Dispatch into the child-side
    // helper before skuld touches anything so the redirect can't corrupt
    // sibling tests.
    if let Ok(kind) = std::env::var("HOLE_LOGGING_TEST_KIND") {
        logging::logging_test_helpers::run_child(&kind);
        std::process::exit(0);
    }
    skuld::run_all();
}

#[cfg(test)]
#[allow(clippy::assertions_on_constants)]
#[skuld::test]
fn debug_assertions_enabled() {
    assert!(
        cfg!(debug_assertions),
        "tests must be compiled with debug assertions enabled"
    );
}
