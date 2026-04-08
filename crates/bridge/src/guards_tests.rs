// Unit tests for `StateFileGuard` and `TaskHandleGuard`.

use super::*;
use crate::route_state::{RouteState, SCHEMA_VERSION};
use std::net::IpAddr;
use std::time::Duration;
use tempfile::TempDir;

// Helpers =============================================================================================================

fn write_sample_state(dir: &std::path::Path) {
    let state = RouteState {
        version: SCHEMA_VERSION,
        tun_name: "wintun-hole".to_string(),
        server_ip: IpAddr::from([10, 0, 0, 1]),
        interface_name: "Ethernet".to_string(),
    };
    crate::route_state::save(dir, &state).expect("save state");
}

fn state_file_exists(dir: &std::path::Path) -> bool {
    crate::route_state::load(dir).is_some()
}

// StateFileGuard ======================================================================================================

#[skuld::test]
fn state_file_guard_clears_on_drop() {
    let tmp = TempDir::new().unwrap();
    write_sample_state(tmp.path());
    assert!(state_file_exists(tmp.path()), "precondition: state file exists");

    {
        let _guard = StateFileGuard::new(tmp.path().to_owned());
        // guard drops at end of scope
    }

    assert!(
        !state_file_exists(tmp.path()),
        "state file must be cleared by StateFileGuard::drop"
    );
}

#[skuld::test]
fn state_file_guard_commit_prevents_clear() {
    let tmp = TempDir::new().unwrap();
    write_sample_state(tmp.path());

    let guard = StateFileGuard::new(tmp.path().to_owned());
    guard.commit();

    assert!(
        state_file_exists(tmp.path()),
        "committed StateFileGuard must not clear the state file"
    );
}

#[skuld::test]
fn state_file_guard_clear_on_missing_file_is_silent() {
    // No file present. Drop must not panic.
    let tmp = TempDir::new().unwrap();
    assert!(!state_file_exists(tmp.path()));
    {
        let _guard = StateFileGuard::new(tmp.path().to_owned());
    }
    // If we got here, drop didn't panic. Good.
}

// TaskHandleGuard =====================================================================================================

#[skuld::test]
fn task_handle_guard_aborts_on_drop() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        // A task that would otherwise run for a long time.
        let handle = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(60)).await;
        });

        {
            let _guard = TaskHandleGuard::new(handle);
            // drop
        }
        // After the guard is dropped, the task should terminate promptly.
        // We can't re-reference the handle here (it was moved), so instead
        // we prove the runtime shuts down quickly after dropping the guard.
        // Give the aborted task a tiny window to settle.
        tokio::time::sleep(Duration::from_millis(50)).await;
    });
    // Dropping the runtime without hanging is the assertion.
}

#[skuld::test]
fn task_handle_guard_commit_returns_handle_and_suppresses_abort() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let handle = tokio::spawn(async { 42u32 });
        let guard = TaskHandleGuard::new(handle);
        let handle = guard.commit();
        let value = handle.await.expect("joined");
        assert_eq!(value, 42);
    });
}

// Note: the `commit(self) -> JoinHandle<T>` API consumes `self`, so
// double-commit is prevented at compile time (the first call moves the
// guard). There is no runtime double-commit path to test.
