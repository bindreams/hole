//! Privileged-lane cutover proofs (the bindreams/hole#165 isolation contract,
//! TUN lane). Real rename/SCM/renamex_np FFI driven through `hole_bridge`'s
//! public API. NOT `#[ignore]`d and do NOT skip on missing privilege — a default
//! `cargo nextest` run on an unelevated box runs them and FAILS LOUD; opting out
//! is the explicit `SKULD_LABELS="!tun"` filter, and CI provisions the elevation.
//!
//! These key on SERVICE-STATE transitions (`NotifyServiceStatusChange`), the
//! on-disk `same_file::Handle` identity FLIP, and the `/v1/version` flip — NEVER
//! loopback. The GitHub Actions Windows runner drops inbound loopback to the test
//! exe, so a loopback probe cannot tell a working cutover from a broken one (the
//! PR1 lesson); the egress/identity/service-state signals are the only reliable
//! ones on the runner.
//!
//! An INTEGRATION test (not a lib module) on purpose: Cargo guarantees the
//! `test_idle` helper `[[bin]]` is built before this target and injects
//! `CARGO_BIN_EXE_test_idle` (a lib unit-test target gets neither).
//!
//! Cross-binary serialization of the global WFP/pf/TUN state these touch lives in
//! `.config/nextest.toml` (`global-net-state` test-group) — skuld's `serial = TUN`
//! only serializes within one binary, and this is a third binary alongside the
//! bridge + tun-engine lib-test binaries.
//!
//! COUPLED NAMES: that group's filter matches these tests by the
//! `cutover_global_net_state_` name prefix. Renaming the prefix WITHOUT updating
//! `.config/nextest.toml` drops the test from the group → a silent cross-binary
//! race with the other real-net tests. Change both together.

hole_test_observability::register!();

fn main() {
    skuld::run_all();
}

#[skuld::label]
const TUN: skuld::Label;

/// The on-disk image identity must FLIP across a rename-away-then-move-in swap
/// (the GUI self-heal precondition: `same_file::Handle` inequality is what makes
/// `decide_self_heal` return Relaunch), and the swap must succeed WHILE the image
/// is mapped by a running process (the running-exe rename held `FILE_SHARE_DELETE`
/// — the load-bearing D1 premise). Non-privileged, but joins the TUN lane so it
/// serializes with the real-net tests.
///
/// Spawns a COPY of the idle helper in a tempdir — never the cargo target bin,
/// whose path cargo's macOS uplift removes+recreates on every no-op build.
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn cutover_global_net_state_running_exe_rename_flips_handle_identity() {
    let dir = tempfile::tempdir().unwrap();
    let idle = std::path::Path::new(env!("CARGO_BIN_EXE_test_idle"));
    let exe = dir.path().join("live.exe");
    std::fs::copy(idle, &exe).unwrap();
    let mut child = std::process::Command::new(&exe).spawn().expect("spawn the idle image");

    let before = same_file::Handle::from_path(&exe).unwrap();
    let renamed = dir.path().join("live.exe.old-0.3.0");
    // The cutover primitive: rename the LIVE binary aside (POSIX-semantics rename
    // of an image held FILE_SHARE_DELETE), then move new bytes onto the canonical
    // path. A copy of the same helper stands in for the "new" image.
    std::fs::rename(&exe, &renamed).expect("rename a running exe must succeed (FILE_SHARE_DELETE)");
    std::fs::copy(idle, &exe).unwrap();
    let after = same_file::Handle::from_path(&exe).unwrap();

    assert_ne!(
        before, after,
        "same_file::Handle identity must FLIP across the swap (the self-heal precondition)"
    );
    assert!(
        child.try_wait().unwrap().is_none(),
        "the child must still be running after its image was renamed underneath it"
    );
    let _ = child.kill();
    let _ = child.wait();
}

/// The real SCM restart must gate strictly on a RUNNING callback from
/// `NotifyServiceStatusChange` — never a loopback reachability probe. Drives the
/// real `SystemScmActor` against the installed `HoleBridge` service: stop → wait
/// STOPPED → start → wait RUNNING, then re-arms + re-waits to confirm RUNNING
/// (service-state keyed).
///
/// CI provisions an installed `HoleBridge` service for this lane; on a box without
/// it, `SystemScmActor::open` fails loud (the test errors rather than skipping).
#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn cutover_global_net_state_real_scm_restart_gates_on_running_callback() {
    use hole_bridge::cutover::scm_wait::{restart_via_notify, ScmActor, SystemScmActor, WantState};
    use hole_bridge::platform::os::SERVICE_NAME;

    let mut actor = SystemScmActor::open(SERVICE_NAME)
        .expect("open the HoleBridge SCM handle (CI provisions the service for the TUN lane)");

    // Restart via the real event-driven sequence: it returns only once a RUNNING
    // callback fired — no sleep, no loopback probe.
    restart_via_notify(&mut actor).expect("SCM restart must reach RUNNING via NotifyServiceStatusChange");

    actor.arm(WantState::Running).unwrap();
    assert_eq!(
        actor.wait_callback().unwrap(),
        WantState::Running,
        "post-restart the service must report RUNNING (service-state keyed, not loopback)"
    );
}

/// macOS: renamex_np-swap the `.app` (a dir) + plain-rename the helper (a file)
/// via the production `execute_swap`, and assert the on-disk identity flipped
/// (RENAME_SWAP exchanged the directory entries). Real `renamex_np` FFI; runs
/// under `sudo` on the TUN lane. The all-or-nothing rollback ordering is unit-
/// proven cfg-free in `platform::swap_tests`; this proves the real primitive.
#[cfg(target_os = "macos")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn cutover_global_net_state_swap_running_helper_preserves_identity() {
    use hole_bridge::platform::swap::{execute_swap, plan_swap, volume_supports_rename_swap};

    let dir = tempfile::tempdir().unwrap();
    // RENAME_SWAP is a per-volume capability; the tempdir's volume must advertise
    // it (APFS does). Fail loud if not — the destination volume is wrong.
    assert!(
        volume_supports_rename_swap(dir.path()).unwrap(),
        "the destination volume must support RENAME_SWAP (APFS)"
    );

    // Staged `.app` (a dir) + old counterpart at the dest; staged helper file +
    // old helper at the dest. Staging + dest share a volume (one tempdir).
    let app_dest = dir.path().join("Hole.app");
    let app_staging = dir.path().join(".Hole.app.staging");
    std::fs::create_dir_all(app_dest.join("Contents/MacOS")).unwrap();
    std::fs::write(app_dest.join("Contents/MacOS/hole"), b"old-app").unwrap();
    std::fs::create_dir_all(app_staging.join("Contents/MacOS")).unwrap();
    std::fs::write(app_staging.join("Contents/MacOS/hole"), b"new-app").unwrap();
    let helper_dest = dir.path().join("com.hole.bridge");
    let helper_staging = dir.path().join("com.hole.bridge.new");
    std::fs::write(&helper_dest, b"old-helper").unwrap();
    std::fs::write(&helper_staging, b"new-helper").unwrap();

    let before_app = same_file::Handle::from_path(app_dest.join("Contents/MacOS/hole")).unwrap();
    let plan = plan_swap(&app_staging, &app_dest, &helper_staging, &helper_dest);
    execute_swap(&plan).expect("real renamex_np + rename swap must succeed on APFS");

    // The dest now holds the NEW bytes (identity flipped); the helper too.
    assert_eq!(std::fs::read(app_dest.join("Contents/MacOS/hole")).unwrap(), b"new-app");
    assert_eq!(std::fs::read(&helper_dest).unwrap(), b"new-helper");
    let after_app = same_file::Handle::from_path(app_dest.join("Contents/MacOS/hole")).unwrap();
    assert_ne!(
        before_app, after_app,
        "the `.app` image identity must FLIP across RENAME_SWAP"
    );
}
