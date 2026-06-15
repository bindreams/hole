use super::*;

#[skuld::test]
fn swap_plan_app_uses_rename_swap_helper_uses_plain_rename() {
    let plan = plan_swap(
        std::path::Path::new("/Applications/.Hole.app.staging"),
        std::path::Path::new("/Applications/Hole.app"),
        std::path::Path::new("/Library/PrivilegedHelperTools/com.hole.bridge.new"),
        std::path::Path::new("/Library/PrivilegedHelperTools/com.hole.bridge"),
    );
    assert_eq!(plan.app.primitive, SwapPrimitive::RenameSwap, ".app is a non-empty dir");
    assert_eq!(
        plan.helper.primitive,
        SwapPrimitive::PlainRename,
        "helper is a single file"
    );
    // RENAME_SWAP leaves the old bundle at the staging path -> must be deleted.
    assert!(plan.app.delete_swapped_out_staging);
    assert!(!plan.helper.delete_swapped_out_staging);
}

#[skuld::test]
fn same_volume_check_rejects_cross_device() {
    // A DMG mount is a separate volume from /Applications -> EXDEV. The pure
    // checker keys on a caller-supplied (dev, dev) pair so we can table-test it.
    assert!(same_volume(42, 42));
    assert!(!same_volume(42, 7));
}

// All-or-nothing orchestration: the swap of the `.app` (RENAME_SWAP) followed by
// the helper (plain rename) must roll the `.app` back if the helper fails, and
// must defer deleting the swapped-out staging until BOTH succeed — otherwise a
// helper failure leaves a swapped `.app` against an OLD helper (a mixed set) and
// the deleted staging makes the `.app` unrecoverable. Tested via the pure
// orchestrator with a recording fake (no FFI, no privilege).

use std::cell::RefCell;

#[derive(Default)]
struct FakeOps {
    log: RefCell<Vec<String>>,
    /// Image index (0 = app, 1 = helper) whose `swap` should fail.
    fail_swap_on: Option<usize>,
}

impl SwapOps for FakeOps {
    fn swap(&self, img: &ImageSwap, index: usize) -> std::io::Result<()> {
        if self.fail_swap_on == Some(index) {
            self.log.borrow_mut().push(format!("swap-FAIL[{index}]"));
            return Err(std::io::Error::other("injected swap failure"));
        }
        self.log
            .borrow_mut()
            .push(format!("swap[{index}] {:?}->{:?}", img.staging, img.dest));
        Ok(())
    }
    fn reswap(&self, img: &ImageSwap, index: usize) {
        self.log
            .borrow_mut()
            .push(format!("reswap[{index}] {:?}->{:?}", img.dest, img.staging));
    }
    fn delete_staging(&self, img: &ImageSwap, index: usize) {
        self.log
            .borrow_mut()
            .push(format!("delete-staging[{index}] {:?}", img.staging));
    }
}

fn sample_plan() -> SwapPlan {
    plan_swap(
        std::path::Path::new("/Applications/.Hole.app.staging"),
        std::path::Path::new("/Applications/Hole.app"),
        std::path::Path::new("/Library/PrivilegedHelperTools/com.hole.bridge.new"),
        std::path::Path::new("/Library/PrivilegedHelperTools/com.hole.bridge"),
    )
}

#[skuld::test]
fn execute_plan_helper_failure_rolls_back_the_app_and_deletes_nothing() {
    let plan = sample_plan();
    let ops = FakeOps {
        fail_swap_on: Some(1), // helper swap fails after the app swap committed
        ..Default::default()
    };
    let err = execute_plan(&plan, &ops).expect_err("a helper failure must error");
    assert_eq!(err.kind(), std::io::ErrorKind::Other);

    let log = ops.log.borrow();
    assert_eq!(
        *log,
        vec![
            "swap[0] \"/Applications/.Hole.app.staging\"->\"/Applications/Hole.app\"".to_string(),
            "swap-FAIL[1]".to_string(),
            // The .app swap is rolled back; NO staging is deleted (deferred).
            "reswap[0] \"/Applications/Hole.app\"->\"/Applications/.Hole.app.staging\"".to_string(),
        ],
        "helper failure must reswap the app and delete no staging (no mixed set)"
    );
}

#[skuld::test]
fn execute_plan_app_failure_touches_nothing_else() {
    let plan = sample_plan();
    let ops = FakeOps {
        fail_swap_on: Some(0), // the very first swap fails
        ..Default::default()
    };
    let err = execute_plan(&plan, &ops).expect_err("an app failure must error");
    assert_eq!(err.kind(), std::io::ErrorKind::Other);
    // Nothing committed, so nothing to reswap or delete.
    assert_eq!(*ops.log.borrow(), vec!["swap-FAIL[0]".to_string()]);
}

#[skuld::test]
fn execute_plan_full_success_deletes_swapped_out_staging_after_both() {
    let plan = sample_plan();
    let ops = FakeOps::default();
    execute_plan(&plan, &ops).unwrap();

    let log = ops.log.borrow();
    // Both swaps run FIRST; only then is the app's swapped-out staging deleted
    // (the helper's `delete_swapped_out_staging` is false). The delete must NOT
    // interleave with the swaps (else a rollback after the delete is impossible).
    assert_eq!(
        *log,
        vec![
            "swap[0] \"/Applications/.Hole.app.staging\"->\"/Applications/Hole.app\"".to_string(),
            "swap[1] \"/Library/PrivilegedHelperTools/com.hole.bridge.new\"->\"/Library/PrivilegedHelperTools/com.hole.bridge\"".to_string(),
            "delete-staging[0] \"/Applications/.Hole.app.staging\"".to_string(),
        ]
    );
}
