//! Process-global test observability for the Hole workspace.
//!
//! Each test-bearing crate invokes [`register!`] from its `lib.rs`. The
//! macro expands to a `#[cfg(test)]` `ctor::declarative::ctor!` block
//! in the **consumer** crate (not this rlib) that calls [`install`]
//! before `main` runs. [`install`] is idempotent.
//!
//! What gets installed:
//!
//! * `RUST_BACKTRACE=full` (if unset) so the stdlib panic hook prints
//!   a usable backtrace.
//! * Windows only: `XDG_RUNTIME_DIR=<workspace>/target/galoshes-runtime` (if unset or empty), so each
//!   worktree's galoshes extracts its ex-ray into its own directory. If that directory cannot be created, prints
//!   one line to stderr and goes on without the isolation.
//! * A global `tracing` subscriber writing to stderr. Skuld's
//!   FD-level capture (under bare `cargo test`) and nextest's
//!   per-subprocess capture (under CI) buffer and dump the events on
//!   test failure. Filter defaults to a catch-all `info` with every
//!   Hole-side crate pinned to `debug`; override with
//!   `HOLE_TEST_LOG=...`.
//! * Hole's tracing-emitting panic hook
//!   (`hole_common::logging::install_panic_hook`) chained before the
//!   stdlib default — adds `target=hole::panic` events with
//!   `force_capture` backtraces.
//!
//! ## Why a separate crate (vs feature on hole-common)
//!
//! * `dev-dependencies` only — never linked into production binaries.
//! * Single ownership for the `pub use ::ctor;` re-export and the
//!   `register!` macro.
//!
//! ## Avoiding the `LogTracer` perf trap
//!
//! `tracing_subscriber::fmt().init()` (and any `SubscriberInitExt::try_init`)
//! calls `tracing_log::LogTracer::init()` as a side effect. That sets
//! `log::max_level()` to `Trace` and routes every `log::debug!` /
//! `log::trace!` from `shadowsocks-service`, `tokio`, `mio`, `hyper`
//! through tracing. That per-event allocation in `tracing-log` pushed
//! `server_test_tests` (real localhost TCP, 5 s timeouts) into a timeout on
//! GitHub Actions Windows runners. We install via the bare
//! `tracing::subscriber::set_global_default` (not `try_init`), but the
//! load-bearing safeguard is the EnvFilter default: the noisy
//! third-party namespaces stay at `info` so their `log::trace!` /
//! `log::debug!` events are level-rejected at `Dispatch::enabled()`
//! before `tracing-log` allocates an `Event`. `lib_tests.rs` pins that
//! rejection.

use std::io::Write;
use std::sync::Once;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::EnvFilter;

pub mod egress;
pub mod panic_dump;

/// Re-exported `ctor` crate so consumer crates don't need to add
/// `ctor` to their own dev-dependencies. The [`register!`] macro
/// invokes `ctor::declarative::ctor!` against this re-export — the
/// declarative form is required because `default-features = false`
/// in the workspace turns off the proc-macro `#[ctor]` attribute
/// (which would otherwise emit absolute `::ctor::…` paths in
/// consumer crates that don't depend on `ctor` directly).
#[doc(hidden)]
pub use ::ctor;

/// Default `EnvFilter` directives. Catch-all `info`; every Hole-side
/// crate is pinned to `debug` for diagnostic depth. Third-party
/// crates stay at `info` — enough to keep `log::trace!` from
/// `shadowsocks-service` / `tokio` / `mio` level-rejected before
/// `tracing-log` allocates an Event.
///
/// Override per-binary with `HOLE_TEST_LOG=...`.
const DEFAULT_FILTER: &str = "info,\
    hole=debug,\
    hole_common=debug,\
    hole_bridge=debug,\
    hole_test_observability=debug,\
    tun_engine=debug,\
    tun_engine_macros=debug,\
    garter=debug,\
    garter_bin=debug,\
    galoshes=debug,\
    dump=debug,\
    dump_macros=debug,\
    handle_holders=debug";

/// Point galoshes at a per-worktree runtime directory (Windows).
///
/// galoshes extracts its embedded ex-ray to one file per user, and every worktree builds
/// different ex-ray bytes, so two worktrees running tests at once make one galoshes fail with
/// "Access is denied".
/// A non-empty `XDG_RUNTIME_DIR` already in the environment wins. If the directory cannot be created
/// (a staged binary run from another tree, a missing drive) it prints one line to stderr and goes on
/// without the isolation: this runs inside a ctor, where a panic aborts the process and would lose every
/// test of the binary, even during `nextest --list`.
///
/// Called only from [`install`]'s one-time block, which runs single-threaded (pre-main under
/// `register!()`, or at the top of this crate's own test `main`), so `set_var` cannot race an env read.
#[cfg(windows)]
fn isolate_galoshes_runtime_dir() {
    if std::env::var_os("XDG_RUNTIME_DIR").is_some_and(|v| !v.is_empty()) {
        return;
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/test-observability is two levels below the workspace root");
    let dir = root.join("target").join("galoshes-runtime");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        // Best-effort: a closed stderr must not turn a skipped isolation into a ctor panic.
        let _ = writeln!(
            std::io::stderr(),
            "hole-test-observability: cannot create {}: {e}; continuing without a per-worktree galoshes runtime dir (set XDG_RUNTIME_DIR to a writable dir)",
            dir.display()
        );
        return;
    }
    // SAFETY: see the function doc.
    unsafe { std::env::set_var("XDG_RUNTIME_DIR", &dir) };
}

/// Install the global subscriber, panic hook, `RUST_BACKTRACE`, and (Windows) `XDG_RUNTIME_DIR`.
///
/// Idempotent: subsequent calls are no-ops. The first call sets environment variables, so it must
/// run before any other thread starts: from `register!()`'s ctor, or as the first thing in a custom
/// `main`.
///
/// When `HOLE_LOGGING_TEST_KIND` is set, applies the Windows runtime-dir isolation and then skips the
/// subscriber and panic-hook setup: the FD-redirect child-process branch in
/// `crates/common/src/lib.rs::main` re-dispatches into
/// `logging_test_helpers::run_child` which installs its OWN
/// `set_global_default`. Pre-installing here would make that call
/// panic on the "already set" error. The child branch short-circuits
/// `skuld::run_all` before any test body runs, so the global
/// subscriber serves no diagnostic purpose there anyway.
pub fn install() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        #[cfg(windows)]
        isolate_galoshes_runtime_dir();
        if std::env::var_os("HOLE_LOGGING_TEST_KIND").is_some() {
            return;
        }
        // SAFETY: see `install`'s doc: this runs before any other thread starts.
        if std::env::var_os("RUST_BACKTRACE").is_none() {
            unsafe { std::env::set_var("RUST_BACKTRACE", "full") };
        }

        // Layer `HOLE_TEST_LOG` ON TOP of the default filter so users
        // who pass e.g. `HOLE_TEST_LOG=hole_bridge=debug` get THAT
        // directive in addition to the catch-all `info` and the
        // per-crate `debug` pins — not in place of them.
        let mut env_filter = EnvFilter::new(DEFAULT_FILTER);
        if let Ok(extra) = std::env::var("HOLE_TEST_LOG") {
            for directive in extra.split(',') {
                let directive = directive.trim();
                if directive.is_empty() {
                    continue;
                }
                match directive.parse() {
                    Ok(d) => env_filter = env_filter.add_directive(d),
                    Err(e) => {
                        let _ = writeln!(
                            std::io::stderr(),
                            "hole-test-observability: ignoring invalid HOLE_TEST_LOG directive {directive:?}: {e}"
                        );
                    }
                }
            }
        }

        let subscriber = tracing_subscriber::registry().with(env_filter).with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_ansi(false)
                .with_target(true)
                .with_level(true),
        );

        // set_global_default — bare function, NOT
        // SubscriberInitExt::try_init() — so we do not call
        // LogTracer::init() ourselves. The EnvFilter handles noisy
        // third-party log events whether or not LogTracer ends up
        // installed by another code path.
        //
        // If a foreign global subscriber was installed before our ctor,
        // fail loud to stderr rather than silently swallow — this
        // crate's whole purpose is to NOT drop diagnostics silently.
        if let Err(e) = tracing::subscriber::set_global_default(subscriber) {
            let _ = writeln!(
                std::io::stderr(),
                "hole-test-observability: set_global_default failed; \
                 a foreign subscriber pre-empted ours: {e}"
            );
        }

        // Hole's tracing-emitting panic hook. Chains before the
        // stdlib default. Idempotent via its own AtomicBool, so
        // safe alongside the production caller `init_multi` (which also calls `install_panic_hook`).
        // Gated to Mac/Windows because `hole-common` only compiles
        // on those platforms (see this crate's Cargo.toml); elsewhere
        // the stdlib default panic hook + `RUST_BACKTRACE=full` above
        // is the fallback diagnostic.
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        hole_common::logging::install_panic_hook();

        // Workspace-shared panic-dump dispatcher. Chains over the
        // hole_common tracing-emit hook (which chains over libtest's
        // panic printer). Test-support consumers register sources
        // via `panic_dump::register(Arc<dyn PanicDumpSource>)` —
        // no per-consumer hook installation needed.
        panic_dump::install_panic_hook_once();
    });
}

/// Invoke from each test-bearing crate's `lib.rs` or integration
/// test file's top level:
///
/// ```ignore
/// hole_test_observability::register!();
/// ```
///
/// Expands to a `#[cfg(test)]` private module containing a
/// `ctor::declarative::ctor!` block that calls [`install`]. The
/// declarative form emits its `#[used]` static in the **consumer**
/// crate's object file — sidestepping rlib dead-code-elimination
/// across linker variants (MSVC link.exe / lld / ld / ld64).
///
/// One invocation per crate root (including each `tests/foo.rs`
/// integration-test target). The expanded module name is fixed, so
/// invoking twice in the same crate root would collide; that's
/// intentional — one entry-point per test binary.
#[macro_export]
macro_rules! register {
    () => {
        #[cfg(test)]
        #[doc(hidden)]
        mod _hole_test_observability_init {
            $crate::ctor::declarative::ctor! {
                #[ctor(unsafe)]
                fn init() {
                    $crate::install();
                }
            }
        }
    };
}

#[cfg(test)]
mod lib_tests;

#[cfg(test)]
fn main() {
    // No `register!()` here, so install by hand (see `install`).
    install();
    skuld::run_all();
}
