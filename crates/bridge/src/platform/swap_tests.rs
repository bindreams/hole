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
