//! A Windows service has no standard handles, and neither has a GUI-subsystem program
//! nobody redirected: `GetStdHandle` answers null for all three. Hole's bridge is both.
//! It starts every plugin through `BinaryPlugin`, which pipes the plugin's stdout and
//! stderr and leaves its stdin to inherit, so the plugin inherits a null handle. A spawn
//! that cannot pass "nothing" on fails there and nowhere else: every other test in this
//! package hosts its plugins in the test process, whose handles the test runner supplied.
//!
//! So the plugin here is hosted by a helper that nulls its own three handles first
//! (`MOCK_PLUGIN_NULL_STD_HOST`, src/bin/mock-plugin.rs) and then starts a plugin
//! through garter's production spawn. The helper stands in for one difference between
//! a test and the installed service; `msi-installer/tests/installed/test_connect.py`
//! asks the service itself.

#![allow(clippy::disallowed_methods)] // test fixture: spawns the workspace's own mock-plugin binary, not an OS tool

#[cfg(windows)]
mod common;

#[cfg(windows)]
#[skuld::test]
async fn a_plugin_starts_from_a_process_with_no_standard_handles() {
    use tokio::io::{AsyncBufReadExt, BufReader};

    let control = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();

    // The helper is not contained: like the bridge, it is the root its plugin's tree hangs from.
    let mut cmd = cosca::tokio::Command::new();
    cmd.executable(common::mock_plugin_path())
        .arg(common::mock_plugin_path())
        .env("MOCK_PLUGIN_NULL_STD_HOST", control.local_addr().unwrap().to_string())
        .kill_on_drop(true);
    cmd.stdin(cosca::Stdio::null()).unwrap();
    cmd.stdout(cosca::Stdio::null()).unwrap();
    cmd.stderr(cosca::Stdio::null()).unwrap();
    let mut helper = cmd.spawn().unwrap();

    // Biased: a helper that dialled, reported and exited before this is polled leaves both branches ready, and its
    // report is the one to read.
    let conn = tokio::select! {
        biased;
        accepted = control.accept() => accepted.expect("the helper dials the control channel").0,
        exited = helper.wait() => panic!("the helper exited before dialling the control channel: {exited:?}"),
    };
    let verdict = BufReader::new(conn)
        .lines()
        .next_line()
        .await
        .unwrap()
        .expect("the helper reports how the start ended");
    assert_eq!(
        verdict, "ready",
        "a host with no standard handles could not start its plugin"
    );

    helper.wait().await.unwrap();
}

hole_test_observability::register!();

fn main() {
    skuld::run_all();
}
