//! Nextest-isolated: run with `cargo nextest run` so each test is its own
//! process; self-`raise(SIGINT)` (unix) / CTRL_BREAK to a process group
//! (windows) would otherwise hit the shared `cargo test` process (skuld runs
//! in-process). The unix tests are `#[cfg(unix)]`, the CTRL_BREAK e2e is
//! `#[cfg(windows)]`; `spawn_and_rendezvous` is shared. Mirrors
//! crates/dev-console/src/interrupts_tests.rs.

#![allow(clippy::disallowed_methods)] // dev tooling, never privileged

use super::Interrupt;

/// A raised flag ends a wait that would otherwise last an hour. The raise may land before or after the
/// waiter blocks; the wait must return either way.
#[skuld::test]
fn raise_wakes_a_waiter() {
    let interrupt = Interrupt::new();
    let interrupted = std::thread::scope(|scope| {
        scope.spawn(|| interrupt.raise());
        interrupt.sleep(std::time::Duration::from_secs(3600))
    });
    assert!(interrupted);
    assert!(interrupt.is_raised());
}

/// A wait nobody interrupts runs its whole delay and reports no interrupt.
#[skuld::test]
fn an_unraised_wait_runs_to_its_end() {
    let interrupt = Interrupt::new();
    assert!(!interrupt.sleep(std::time::Duration::ZERO));
    assert!(!interrupt.is_raised());
}

/// The flag is sticky: a later wait returns at once.
#[skuld::test]
fn a_raised_flag_stays_raised() {
    let interrupt = Interrupt::new();
    interrupt.raise();
    assert!(interrupt.sleep(std::time::Duration::from_secs(3600)));
    assert!(interrupt.sleep(std::time::Duration::from_secs(3600)));
}

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

/// A download has no child to receive Ctrl-C, so the attempt itself must notice the interrupt while the body
/// is still arriving. The server raises [`crate::interrupt::PROCESS`] (what the handler does) between the
/// response head and the body bytes, then leaves the body unfinished: without a check inside the read loop the
/// client waits for the rest of the body until its body timeout. Whether the raise lands before or after the
/// client's first check, the loop reads the flag again once the partial body arrives.
#[skuld::test]
fn an_interrupt_ends_a_download_in_flight() {
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/artifact", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0u8; 1024];
        let _ = stream.read(&mut request);
        stream
            .write_all(
                b"HTTP/1.1 200 OK
Content-Length: 100
Connection: close

",
            )
            .unwrap();
        crate::interrupt::PROCESS.raise();
        let _ = stream.write_all(b"partial");
        // Hold the connection open until the client gives up on it.
        let _ = stream.read(&mut request);
    });
    let err = crate::download::fetch_verified("test artifact", &url, 1 << 20, "0").unwrap_err();
    assert!(crate::retry::is_interrupted(&err), "{err:#}");
    server.join().unwrap();
}

/// The link from the installed handler to the retry loop: SIGINT (unix) / CTRL_BREAK (windows) delivered to a
/// process running `until_ok` over an operation that never succeeds ends the loop. A handler that does not
/// raise [`crate::interrupt::PROCESS`], or a loop watching another flag, leaves the child retrying forever.
#[skuld::test]
fn the_installed_handler_ends_an_uncapped_retry_loop() {
    use std::io::{BufRead as _, BufReader};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind control");
    let addr = listener.local_addr().unwrap().to_string();
    let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
    cmd.env(crate::test_child::MODE_ENV, "retry-loop")
        .env(crate::test_child::CONTROL_ENV, &addr);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        cmd.creation_flags(0x0000_0200); // CREATE_NEW_PROCESS_GROUP, so CTRL_BREAK to it won't hit the test console
    }
    let mut child = cmd.spawn().expect("spawn the retry loop");
    let (conn, _) = listener.accept().expect("accept readiness");
    let mut line = String::new();
    BufReader::new(conn).read_line(&mut line).expect("read readiness");
    assert_eq!(line.trim_end(), "R");
    // The loop is entered (or about to be) with the handler installed; the sticky flag makes the order irrelevant.
    #[cfg(unix)]
    // SAFETY: kill(2) to a pid we own.
    assert_eq!(unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGINT) }, 0);
    #[cfg(windows)]
    {
        use windows::Win32::System::Console::{GenerateConsoleCtrlEvent, CTRL_BREAK_EVENT};
        // The child was spawned with CREATE_NEW_PROCESS_GROUP, so its group id is its pid.
        // SAFETY: FFI call into kernel32; the group id is our live child's pid.
        unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, child.id()) }
            .expect("GenerateConsoleCtrlEvent(CTRL_BREAK)");
    }
    let status = child.wait().unwrap();
    assert_eq!(
        status.code(),
        Some(crate::test_child::RETRY_LOOP_INTERRUPTED_EXIT),
        "the loop must end with the interrupted error (got {status:?})"
    );
}

/// Spawn the parent-under-test and rendezvous: returns the parent handle, the
/// parent's readiness conn (parent announced "about to wait"), the grandchild's
/// conn (held open by the caller — drop it to release the grandchild), and the
/// grandchild's pid. Sleep-free: both readiness lines must arrive before we act.
fn spawn_and_rendezvous() -> (std::process::Child, std::net::TcpStream, std::net::TcpStream, u32) {
    use std::io::{BufRead as _, BufReader};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind control");
    let addr = listener.local_addr().unwrap().to_string();
    let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
    cmd.env(crate::test_child::MODE_ENV, "interrupt-parent")
        .env(crate::test_child::CONTROL_ENV, &addr);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        cmd.creation_flags(0x0000_0200); // CREATE_NEW_PROCESS_GROUP — parent's group == its pid; CTRL_BREAK to it won't hit the test console
    }
    let parent = cmd.spawn().expect("spawn parent-under-test");

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

/// Windows analog of `parent_survives_sigint_and_forwards_child_exit`: a
/// CTRL_BREAK delivered to the launcher's (isolated) process group mid-wait must
/// not kill it — `ctrlc`'s handler returns TRUE for every console event — so it
/// keeps waiting and forwards the grandchild's exit code. CTRL_BREAK (not
/// CTRL_C) because only it can target a single new process group without hitting
/// the test runner's console.
#[cfg(windows)]
#[skuld::test]
fn parent_survives_ctrl_break_and_forwards_child_exit() {
    use windows::Win32::System::Console::{GenerateConsoleCtrlEvent, CTRL_BREAK_EVENT};
    let (mut parent, _parent_conn, child_conn, _child_pid) = spawn_and_rendezvous();
    // The parent was spawned with CREATE_NEW_PROCESS_GROUP, so its group id == its pid.
    // SAFETY: FFI call into kernel32; the group id is our live child's pid.
    unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, parent.id()) }.expect("GenerateConsoleCtrlEvent(CTRL_BREAK)");
    drop(child_conn); // release the grandchild -> it exits CHILD_RELEASE_EXIT
    let status = parent.wait().expect("wait parent");
    assert_eq!(
        status.code(),
        Some(crate::test_child::CHILD_RELEASE_EXIT),
        "parent must survive CTRL_BREAK and forward the child's exit code, not die from it (got {status:?})"
    );
}
