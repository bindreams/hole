//! Self-reinvoke child modes for xtask's signal tests (mirrors
//! crates/dev-console/src/test_child.rs). When `XTASK_TEST_CHILD` is set,
//! `maybe_run` takes over the process and never returns.

#![allow(clippy::disallowed_methods)] // dev tooling, never privileged

use std::io::{Read as _, Write as _};
use std::net::TcpStream;

pub const MODE_ENV: &str = "XTASK_TEST_CHILD";
/// File the `strip-then-handed-down-root` mode writes the root it found to.
pub const OUT_ENV: &str = "XTASK_TEST_OUT";
pub const CONTROL_ENV: &str = "XTASK_TEST_CONTROL";
/// Grandchild's clean-release exit code (shared so the test can't drift).
pub const CHILD_RELEASE_EXIT: i32 = 42;
/// Grandchild's error-path exit code — a read error must NOT masquerade as the
/// clean-release code.
pub const CHILD_ERROR_EXIT: i32 = 99;

pub fn maybe_run() {
    let Ok(mode) = std::env::var(MODE_ENV) else { return };
    match mode.as_str() {
        "interrupt-parent" => run_interrupt_parent(),
        "interrupt-child" => run_interrupt_child(),
        "list-env" => list_env(),
        "strip-then-list-env-in-child" => strip_then_list_env_in_child(),
        "strip-then-repo-root" => strip_then_repo_root(),
        "strip-then-handed-down-root" => strip_then_handed_down_root(),
        "forward-nextest-list" => forward_nextest_list(),
        "emit-compiling-stderr" => emit_compiling_stderr(),
        other => {
            eprintln!("unknown {MODE_ENV} mode: {other}");
            std::process::exit(2);
        }
    }
}

/// Process under test: install the transparent handler, spawn the grandchild,
/// announce "about to wait", then wait. Exit code encodes the grandchild's fate
/// so the test asserts on it: a clean exit forwards its code; a signal death
/// maps to 128+signum (shell convention).
fn run_interrupt_parent() -> ! {
    crate::install_transparent_interrupt();
    let addr = std::env::var(CONTROL_ENV).expect("control env");
    let mut cmd = std::process::Command::new(std::env::current_exe().expect("current_exe"));
    cmd.env(MODE_ENV, "interrupt-child").env(CONTROL_ENV, &addr);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        cmd.creation_flags(0x0000_0200); // CREATE_NEW_PROCESS_GROUP — isolate the grandchild from the parent-group CTRL_BREAK
    }
    let mut child = cmd.spawn().expect("spawn grandchild");
    // Announce AFTER spawning that we have committed to waiting; the test
    // SIGINTs only after reading this. (The handler was installed before the
    // spawn, so the parent survives wherever the signal lands relative to wait.)
    {
        let mut conn = TcpStream::connect(&addr).expect("dial control (parent)");
        conn.write_all(b"P\n").expect("parent readiness");
    }
    let status = child.wait().expect("wait grandchild");
    std::process::exit(encode_exit(status));
}

/// Encode a child's outcome as an exit code the test asserts on: a clean exit
/// forwards its code; on unix a signal death maps to 128+signum. On Windows a
/// process always carries an exit code (even a CTRL_BREAK kill), so `code()` is
/// authoritative.
fn encode_exit(status: std::process::ExitStatus) -> i32 {
    #[cfg(unix)]
    {
        match status.code() {
            Some(c) => c,
            None => {
                use std::os::unix::process::ExitStatusExt as _;
                128 + status.signal().unwrap_or(0)
            }
        }
    }
    #[cfg(windows)]
    {
        status.code().unwrap_or(-1)
    }
}

/// Grandchild: installs NO handler (its disposition reflects what it inherited
/// across exec). Announce readiness with our pid, then block until the control
/// socket closes (clean EOF -> CHILD_RELEASE_EXIT). A read error is distinct so
/// a broken rendezvous can't masquerade as a clean release.
fn run_interrupt_child() -> ! {
    let addr = std::env::var(CONTROL_ENV).expect("control env");
    let mut conn = TcpStream::connect(addr).expect("dial control (child)");
    conn.write_all(format!("C{}\n", std::process::id()).as_bytes())
        .expect("child readiness");
    let mut buf = [0u8; 64];
    loop {
        match conn.read(&mut buf) {
            Ok(0) => std::process::exit(CHILD_RELEASE_EXIT), // clean EOF => release
            Ok(_) => {}                                      // ignore stray bytes
            Err(_) => std::process::exit(CHILD_ERROR_EXIT),
        }
    }
}

/// Print the name of every variable this process has, one per line.
fn list_env() -> ! {
    for (name, _) in std::env::vars_os() {
        println!("{}", name.to_string_lossy());
    }
    std::process::exit(0);
}

/// Strip the way `main` does, then report what a spawned child inherits.
fn strip_then_list_env_in_child() -> ! {
    crate::child_env::strip_run_injected();
    let out = std::process::Command::new(std::env::current_exe().expect("current_exe"))
        .env(MODE_ENV, "list-env")
        .output()
        .expect("spawn child");
    print!("{}", String::from_utf8_lossy(&out.stdout));
    std::process::exit(i32::from(!out.status.success()));
}

/// Strip the way `main` does, then locate the workspace the way every subcommand does.
fn strip_then_repo_root() -> ! {
    crate::child_env::strip_run_injected();
    match crate::repo_root() {
        Ok(root) => {
            println!("{}", root.display());
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("{e:#}");
            std::process::exit(1);
        }
    }
}

/// Run `run_nextest_list` against a stand-in listing child (this binary in
/// `emit-compiling-stderr` mode), so the test can read what reaches this
/// process's own stderr.
fn forward_nextest_list() -> ! {
    std::env::set_var(MODE_ENV, "emit-compiling-stderr");
    let exe = std::env::current_exe()
        .expect("current_exe")
        .to_string_lossy()
        .into_owned();
    let root = crate::repo_root().expect("repo root");
    match crate::skuld_label_coverage::run_nextest_list(&root, &[exe], None) {
        Ok(_) => std::process::exit(0),
        Err(e) => {
            eprintln!("{e:#}");
            std::process::exit(1);
        }
    }
}

/// What a stale `cargo nextest list` does: `Compiling` on stderr, JSON on stdout.
fn emit_compiling_stderr() -> ! {
    eprintln!("   Compiling stand-in v0.0.0");
    println!(r#"{{"rust-suites":{{}}}}"#);
    std::process::exit(0);
}

/// Strip the way `main` does, then look the root up the way dev-console does,
/// and write it to the file named by [`OUT_ENV`].
fn strip_then_handed_down_root() -> ! {
    crate::child_env::strip_run_injected();
    let root = xtask_lib::repo_root::repo_root_from_launch_dir().expect("a root");
    let out = std::env::var_os(OUT_ENV).expect("out env");
    std::fs::write(out, root.to_string_lossy().as_bytes()).expect("write the root");
    std::process::exit(0);
}
