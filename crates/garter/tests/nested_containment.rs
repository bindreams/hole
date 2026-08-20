//! The property the whole cosca migration turns on: a contained spawn made from
//! inside an already-contained process JOINS the ancestor's tree rather than
//! creating a second one, and is still independently reachable by the cooperative
//! shutdown signal. That is the production shape of galoshes spawning its embedded
//! ex-ray, and nothing else in garter's suite asserts it — the tree tests are
//! root-only or force-kill-only.
//!
//! The `Nesting::Opaque` half is the inverse property, and the dev-console
//! bridge is its production user: an opaque root creates its own containment
//! but writes NO marker, so the garter inside its child is itself a root and
//! keeps containing its own plugin chains.

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

/// `Nesting::Opaque`: the root contains itself but does NOT mark its
/// descendants, so the spawn made inside the child is a ROOT of its own tree,
/// not a delegated member of this one. dev-console spawns the bridge this way
/// precisely so the bridge's own garter keeps containing its plugin chains —
/// the deleted kill-group suite pinned it as `opaque_root_does_not_mark_descendants`,
/// and nothing else here exercises `Opaque` at all.
#[skuld::test]
async fn opaque_root_child_creates_its_own_containment() {
    let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_addr = control.local_addr().unwrap();

    let mut cmd = Command::new();
    cmd.executable(mock_plugin_path())
        .arg(mock_plugin_path())
        .env("MOCK_PLUGIN_NEST_PROBE", control_addr.to_string())
        .kill_on_drop(true)
        .contain()
        .nesting(cosca::containment::Nesting::Opaque);
    cmd.stdin(Stdio::null()).unwrap();
    cmd.stdout(Stdio::pipe()).unwrap();
    cmd.stderr(Stdio::null()).unwrap();
    let mut helper = cmd.spawn().unwrap();

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

    // The exact root mechanism is host-detected (job object / cgroup v2 /
    // process group / inherited-fd marker), so pin the decision instead of the
    // mechanism: it must be a real containment of its own, and specifically NOT
    // a delegated member of the opaque root's tree.
    assert_ne!(
        containment, "delegated",
        "an opaque root must not mark its descendants: the inner spawn joined this tree instead of creating one"
    );
    assert_ne!(
        containment, "none",
        "the inner spawn asked to be contained and must be: it is the root of the bridge's own plugin chains"
    );

    // Positive proof that the containment it created is real and reachable: the
    // cooperative signal still ends it, as it does for the delegated case.
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

    helper.kill_tree().unwrap();
    helper.wait().await.unwrap();
}

hole_test_observability::register!();

fn main() {
    skuld::run_all();
}
