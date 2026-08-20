//! The property the whole cosca migration turns on: a contained spawn made from
//! inside an already-contained process JOINS the ancestor's tree rather than
//! creating a second one, and is still independently reachable by the cooperative
//! shutdown signal. That is the production shape of galoshes spawning its embedded
//! ex-ray, and nothing else in garter's suite asserts it — the tree tests are
//! root-only or force-kill-only.

use cosca::tokio::Command;
use cosca::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::net::TcpListener;

mod common;
use common::mock_plugin_path;

#[skuld::test]
async fn nested_contained_child_is_delegated_and_dies_to_the_cooperative_signal() {
    let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_addr = control.local_addr().unwrap();

    // The helper is a contained ROOT with `Nesting::Mark`, so the marker is in its
    // environment and the spawn it makes in turn is the nested one under test.
    let mut cmd = Command::new();
    cmd.executable(mock_plugin_path())
        .arg(mock_plugin_path())
        .env("MOCK_PLUGIN_NEST_PROBE", control_addr.to_string())
        .kill_on_drop(true)
        .contain()
        .nesting(cosca::containment::Nesting::Mark);
    cmd.stdin(Stdio::null()).unwrap();
    cmd.stdout(Stdio::pipe()).unwrap();
    cmd.stderr(Stdio::null()).unwrap();
    let mut helper = cmd.spawn().unwrap();

    // The GRANDCHILD dials, not the helper — accepting proves the innermost level
    // is alive, with no pid and no poll.
    let (mut grandchild_conn, _) = control
        .accept()
        .await
        .expect("the grandchild dials the control channel");

    let mut report = BufReader::new(helper.stdout().expect("the helper's stdout was piped")).lines();
    let containment = report
        .next_line()
        .await
        .unwrap()
        .expect("the helper reports the grandchild's containment");
    let outcome = report
        .next_line()
        .await
        .unwrap()
        .expect("the helper reports the grandchild's shutdown outcome");

    // A nested spawn that wrongly created its own group would read `job object` /
    // `process group` / `inherited-fd marker` here, and an uncontained one `none`.
    assert_eq!(containment, "delegated");

    // The cooperative end, not the escalation: `code=1` here would mean the signal
    // arrived and was ignored, which is a different bug from a refused one.
    #[cfg(unix)]
    assert!(
        outcome.contains("signal=15"),
        "expected a SIGTERM death, got {outcome:?}"
    );
    #[cfg(windows)]
    assert!(
        outcome.contains("code=-1073741510"),
        "expected STATUS_CONTROL_C_EXIT, got {outcome:?}"
    );

    // Independent confirmation that the reported status belongs to a real death
    // rather than to a status the helper mis-rendered: only the grandchild's own
    // process can hold this connection.
    let mut buf = [0u8; 1];
    match grandchild_conn.read(&mut buf).await {
        Ok(0) => {}
        Ok(n) => panic!("the grandchild sent {n} unexpected byte(s); it must only hold the connection open"),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
            ) => {}
        Err(e) => panic!("unexpected error reading the grandchild's control connection: {e}"),
    }

    // `kill_tree` is signal-only, so the wait is what reaps (and what proves the
    // helper is gone before this test's process exits).
    helper.kill_tree().unwrap();
    helper.wait().await.unwrap();
}

hole_test_observability::register!();

fn main() {
    skuld::run_all();
}
