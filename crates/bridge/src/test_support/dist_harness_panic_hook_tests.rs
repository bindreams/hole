//! Subprocess re-exec regression test for the workspace panic-dump
//! dispatcher chain.
//!
//! Verifies that when a panic fires inside `rt().block_on(...)` with
//! a `DistHarness` alive, the full hook chain runs in order:
//!
//! 1. `hole_test_observability::panic_dump` dispatcher — writes
//!    `BridgeChildLogSource`'s `---- full <bridge.log> ----` framing
//!    to stderr.
//! 2. `hole_common::logging::install_panic_hook` — emits
//!    `tracing::error!(target: "hole::panic", ...)` into the global
//!    subscriber, which the test-observability subscriber writes to
//!    stderr.
//! 3. Libtest panic printer — `panicked at ...`.
//!
//! Pattern mirrors `crates/common/src/logging/logging_tests.rs`:
//! parent re-execs the current test binary with
//! `HOLE_DIST_HARNESS_PANIC_TEST=1`; `lib.rs::main` short-circuits
//! into [`run_child`] before `skuld::run_all`.
//!
//! See bindreams/hole#303 (regression gate (b)).

use crate::test_support::dist_fixture::stage_dist_bin_dir;
use crate::test_support::dist_harness::DistHarness;
use crate::test_support::rt;
use std::process::Command;

/// Child-side: spawn a `DistHarness`, then panic. The installed panic
/// hooks run during unwind and write to stderr (which the parent has
/// piped). The panic propagates out of `block_on` and out of
/// `run_child`; with no `catch_unwind` in the chain, the process
/// aborts with exit code 101.
pub(crate) fn run_child() {
    // Stage the dist directory using the non-fixture helper (skuld
    // fixtures require DI, which is unavailable here — `main` runs
    // before skuld initializes).
    let dist_bin_dir = match stage_dist_bin_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[child] stage_dist_bin_dir failed: {e}");
            std::process::exit(2);
        }
    };

    let runtime = rt();
    // Hold `_harness` across the second `block_on` so its
    // `BridgeChildLogSource` is still registered when the panic hook
    // iterates. The panic hook fires from inside `panic_impl` BEFORE
    // any local drop runs — `_harness` is live, the registry contains
    // the source. Only AFTER the hook returns does unwind continue and
    // drop `_harness`, which in turn runs `DistHarness::Drop`'s
    // `_panic_dump_guard.take()` unregister. Hook reads before unregister.
    let _harness = runtime.block_on(async { DistHarness::spawn(&dist_bin_dir).await.expect("DistHarness::spawn") });

    // Deliberate panic INSIDE `rt().block_on(...)` — the exact
    // tokio-worker-thread panic scenario the original DistHarness
    // hook was designed to handle (see #200 H3). Panic propagates out
    // of `block_on`, then out of `run_child`, then out of `main`.
    // Default unwind → libtest panic printer → exit 101.
    runtime.block_on(async {
        panic!("DistHarness-panic-hook-regression-test-marker");
    });

    // Defense-in-depth: if some future change makes `block_on`
    // swallow the panic (it currently does NOT — panics in the
    // top-level future propagate out), force a non-zero exit so the
    // parent's `!output.status.success()` assertion still fires with a
    // useful diagnostic. Without this safety net, a silent
    // panic-swallow would make the test pass under a broken hook
    // chain.
    eprintln!("[child] panic did not propagate out of block_on — this indicates a regression");
    std::process::exit(2);
}

#[skuld::test]
fn panic_hook_chain_dumps_bridge_log_and_libtest_message() {
    let exe = std::env::current_exe().expect("current_exe");
    let output = Command::new(&exe)
        .env("HOLE_DIST_HARNESS_PANIC_TEST", "1")
        // Scrub env vars that other test-support code in the workspace
        // interprets as "I am a child of a re-exec test", to avoid the
        // child taking the wrong branch in `crates/common/src/lib.rs::main`
        // or short-circuiting `hole_test_observability::install` (which
        // would skip installing the dispatcher under test). Inheriting
        // an accidentally-set value from the parent process would make
        // this test silently pass under a broken chain.
        .env_remove("HOLE_LOGGING_TEST_KIND")
        // `output()` captures both stdout and stderr. The child
        // dispatches into `run_child` via the `lib.rs` branch BEFORE
        // libtest's arg parsing, so we don't need any --nocapture /
        // filter flags.
        .output()
        .expect("spawn child");

    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    assert!(
        !output.status.success(),
        "child should exit non-zero after panic; status={:?}, stderr:\n{stderr}",
        output.status
    );

    // Gate 1: panic_dump dispatcher fired — `BridgeChildLogSource`
    // wrote its framing to stderr.
    assert!(
        stderr.contains("[DistHarness panic hook] live harness pid="),
        "panic_dump dispatcher must dump the harness header. stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("[DistHarness panic hook] ---- full"),
        "panic_dump dispatcher must include the bridge.log framing. stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("[panic_dump] dispatcher fired:"),
        "panic_dump dispatcher must emit its fired-marker line. stderr:\n{stderr}"
    );

    // Gate 2: hole_common tracing-emit hook fired — the panic event
    // reaches the global subscriber and is formatted with the
    // `hole::panic` target.
    assert!(
        stderr.contains("hole::panic"),
        "hole_common::logging::install_panic_hook must emit a \
         target=\"hole::panic\" tracing event. stderr:\n{stderr}"
    );

    // Gate 3: libtest's panic printer fired — final `panicked at`
    // message is preserved.
    assert!(
        stderr.contains("panicked at") && stderr.contains("DistHarness-panic-hook-regression-test-marker"),
        "libtest's panic printer must run last and preserve the \
         original panic message. stderr:\n{stderr}"
    );

    // Negative gate: the safety-net `eprintln!` MUST NOT appear — if
    // it does, `block_on` swallowed the panic and the chain didn't get
    // to fire at all (or fired without the panic value reaching the
    // libtest printer).
    assert!(
        !stderr.contains("panic did not propagate out of block_on"),
        "panic was swallowed by block_on or runtime — chain ordering \
         is broken. stderr:\n{stderr}"
    );

    // Ordering gate: the dispatcher must fire FIRST, then the
    // hole_common tracing-emit hook, then libtest's panic printer.
    // `contains`-based gates above would still pass if the chain
    // silently reversed; this find-based check catches that regression.
    //
    // Note "panicked at" appears in BOTH the dispatcher's prologue
    // (`writeln!(stderr, "[panic_dump] dispatcher fired: {info}")` —
    // `PanicInfo`'s Display impl includes the "panicked at" line) AND
    // libtest's panic printer. To identify libtest's line uniquely we
    // search for the `thread '` prefix that libtest writes ahead of
    // its `panicked at`; no other hook in the chain produces that
    // prefix.
    let pos_dispatcher = stderr
        .find("[panic_dump] dispatcher fired:")
        .expect("dispatcher marker");
    let pos_tracing = stderr.find("hole::panic").expect("hole::panic tracing event");
    let pos_libtest = stderr
        .find("thread '")
        .expect("libtest thread-prefixed panicked-at line");
    assert!(
        pos_dispatcher < pos_tracing,
        "panic_dump dispatcher must run before the hole_common tracing-emit hook; \
         dispatcher@{pos_dispatcher}, tracing@{pos_tracing}. stderr:\n{stderr}"
    );
    assert!(
        pos_tracing < pos_libtest,
        "hole_common tracing-emit hook must run before libtest's panic printer; \
         tracing@{pos_tracing}, libtest@{pos_libtest}. stderr:\n{stderr}"
    );
}
