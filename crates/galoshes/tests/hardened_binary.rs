//! The shipped `galoshes` binary does not search its own folder for libraries (`build.rs` calls `libsearch_guard::bins()`).

hole_test_observability::register!();

/// Reads `CARGO_BIN_EXE_galoshes` at run time first: a nextest archive run remaps it.
#[skuld::test]
fn galoshes_is_hardened() {
    let exe = std::env::var_os("CARGO_BIN_EXE_galoshes").unwrap_or_else(|| env!("CARGO_BIN_EXE_galoshes").into());
    libsearch_guard::verify(&exe).unwrap_or_else(|e| {
        panic!(
            "{}: {e}; the crate's build.rs must call libsearch_guard::bins()",
            exe.to_string_lossy()
        )
    });
}

fn main() {
    skuld::run_all();
}
