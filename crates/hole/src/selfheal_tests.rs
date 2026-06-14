use super::*;

// `decide` is pure and `#[cfg]`-free; identities are any `PartialEq` token
// (`u8` here, `same_file::Handle` in production).

#[skuld::test]
fn matched_operates() {
    assert_eq!(decide("7", Some("7"), 1u8, Some(1u8)), SelfHealAction::Operate);
}

#[skuld::test]
fn stale_image_relaunches() {
    // running != canonical, version differs ⇒ an update swapped us underneath.
    assert_eq!(decide("6", Some("7"), 1u8, Some(2u8)), SelfHealAction::Relaunch);
}

#[skuld::test]
fn absent_header_with_stale_image_relaunches() {
    // old bridge (no version header) + stale image ⇒ still relaunch.
    assert_eq!(decide("6", None, 1u8, Some(2u8)), SelfHealAction::Relaunch);
}

#[skuld::test]
fn same_image_mismatch_is_reinstall() {
    // I am the installed image but the bridge differs ⇒ genuine misconfig.
    assert_eq!(decide("7", Some("6"), 1u8, Some(1u8)), SelfHealAction::Reinstall);
}

#[skuld::test]
fn canonical_absent_is_transient() {
    // installed file momentarily missing mid-swap ⇒ retry, never fatal.
    assert_eq!(decide("6", Some("7"), 1u8, None::<u8>), SelfHealAction::Transient);
}

// run_with: action dispatch via the injected seam (no real relaunch/dialog/exit).

#[derive(Default)]
struct Spy {
    spawned: bool,
    dialoged: bool,
    exited: bool,
    spawn_ok: bool,
}

impl Spy {
    fn ok() -> Self {
        Self {
            spawn_ok: true,
            ..Self::default()
        }
    }
}

impl SelfHealOs for Spy {
    fn spawn_successor(&mut self) -> std::io::Result<()> {
        self.spawned = true;
        if self.spawn_ok {
            Ok(())
        } else {
            Err(std::io::Error::other("spawn failed"))
        }
    }
    fn show_reinstall_dialog(&mut self) {
        self.dialoged = true;
    }
    fn request_exit(&mut self) {
        self.exited = true;
    }
}

#[skuld::test]
fn dispatch_relaunch_spawns_then_exits() {
    let mut spy = Spy::ok();
    dispatch(SelfHealAction::Relaunch, &mut spy);
    assert!(spy.spawned && spy.exited && !spy.dialoged);
}

#[skuld::test]
fn dispatch_reinstall_dialogs_then_exits() {
    let mut spy = Spy::ok();
    dispatch(SelfHealAction::Reinstall, &mut spy);
    assert!(spy.dialoged && spy.exited && !spy.spawned);
}

#[skuld::test]
fn dispatch_operate_does_nothing() {
    let mut spy = Spy::ok();
    dispatch(SelfHealAction::Operate, &mut spy);
    assert!(!spy.spawned && !spy.dialoged && !spy.exited);
}

#[skuld::test]
fn dispatch_transient_does_nothing() {
    let mut spy = Spy::ok();
    dispatch(SelfHealAction::Transient, &mut spy);
    assert!(!spy.spawned && !spy.dialoged && !spy.exited);
}

#[skuld::test]
fn dispatch_relaunch_spawn_failure_does_not_exit() {
    let mut spy = Spy::default(); // spawn_ok = false
    dispatch(SelfHealAction::Relaunch, &mut spy);
    assert!(spy.spawned && !spy.exited);
}
