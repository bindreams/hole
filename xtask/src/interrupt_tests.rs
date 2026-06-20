//! Unix-gated and nextest-isolated: run with `cargo nextest run` so each test
//! is its own process; self-`raise(SIGINT)` would otherwise hit the shared
//! `cargo test` process (skuld runs in-process). Mirrors
//! crates/dev-console/src/interrupts_tests.rs.

/// After installing the transparent handler, a SIGINT must NOT terminate the
/// process (default disposition would). Reaching the line past the raise is the
/// proof of survival — no timing (raise delivers synchronously before return).
#[cfg(unix)]
#[skuld::test]
fn transparent_handler_survives_sigint() {
    crate::install_transparent_interrupt();
    // SAFETY: raising SIGINT to our own process is sound; the no-op handler
    // installed above replaced the default (terminate) disposition.
    assert_eq!(unsafe { libc::raise(libc::SIGINT) }, 0);
    // If the handler were absent, the process would have died on the line above.
}

/// Spawn the parent-under-test and rendezvous: returns the parent handle, the
/// parent's readiness conn (parent announced "about to wait"), the grandchild's
/// conn (held open by the caller — drop it to release the grandchild), and the
/// grandchild's pid. Sleep-free: both readiness lines must arrive before we act.
#[cfg(unix)]
fn spawn_and_rendezvous() -> (std::process::Child, std::net::TcpStream, std::net::TcpStream, u32) {
    use std::io::{BufRead as _, BufReader};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind control");
    let addr = listener.local_addr().unwrap().to_string();
    let parent = std::process::Command::new(std::env::current_exe().unwrap())
        .env(crate::test_child::MODE_ENV, "interrupt-parent")
        .env(crate::test_child::CONTROL_ENV, &addr)
        .spawn()
        .expect("spawn parent-under-test");

    let (mut parent_conn, mut child_conn, mut child_pid) = (None, None, None);
    for _ in 0..2 {
        let (conn, _) = listener.accept().expect("accept readiness");
        let mut br = BufReader::new(conn);
        let mut line = String::new();
        br.read_line(&mut line).expect("read readiness line");
        let conn = br.into_inner();
        match line.trim_end() {
            "P" => parent_conn = Some(conn),
            other => {
                let pid = other.strip_prefix('C').expect("readiness 'P' or 'C<pid>'");
                child_pid = Some(pid.parse().expect("grandchild pid"));
                child_conn = Some(conn);
            }
        }
    }
    (parent, parent_conn.unwrap(), child_conn.unwrap(), child_pid.unwrap())
}

/// The real #568 regression: SIGINT delivered to a launcher WHILE it waits must
/// not kill the launcher; it keeps waiting and returns the child's exit code.
#[cfg(unix)]
#[skuld::test]
fn parent_survives_sigint_and_forwards_child_exit() {
    let (mut parent, _parent_conn, child_conn, _child_pid) = spawn_and_rendezvous();
    // Parent announced "about to wait" -> SIGINT it now (mid-wait), parent pid
    // only (not the group, so the grandchild is untouched). A regressed parent
    // dies here. SAFETY: kill(2) to a pid we own.
    assert_eq!(unsafe { libc::kill(parent.id() as libc::pid_t, libc::SIGINT) }, 0);
    drop(child_conn); // release the grandchild -> it exits CHILD_RELEASE_EXIT
    let status = parent.wait().unwrap();
    assert_eq!(
        status.code(),
        Some(crate::test_child::CHILD_RELEASE_EXIT),
        "parent must survive SIGINT and forward the child's exit code, not die from the signal (got {status:?})"
    );
}

/// The handler must be a HANDLER, not SIG_IGN: a handler resets to the default
/// disposition across exec, so a grandchild that installs nothing dies on
/// SIGINT. (SIG_IGN would be inherited across exec and the grandchild would
/// ignore the signal — the parent's wait would never return and this test would
/// fail via the per-test timeout.)
#[cfg(unix)]
#[skuld::test]
fn child_sigint_disposition_resets_across_exec() {
    let (mut parent, _parent_conn, _child_conn, child_pid) = spawn_and_rendezvous();
    // Do NOT release the grandchild; SIGINT IT. SAFETY: kill(2) to a pid our
    // descendant reported.
    assert_eq!(unsafe { libc::kill(child_pid as libc::pid_t, libc::SIGINT) }, 0);
    let status = parent.wait().unwrap();
    assert_eq!(
        status.code(),
        Some(128 + libc::SIGINT),
        "grandchild must inherit the DEFAULT SIGINT disposition across exec (got {status:?})"
    );
}
