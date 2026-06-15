use super::*;

#[cfg(target_os = "windows")]
#[skuld::test]
fn msiexec_admin_args_are_quiet_admin_install_to_targetdir() {
    let args = msiexec_admin_args(
        Path::new(r"C:\dl\hole.msi"),
        Path::new(r"C:\Program Files\hole\.update-staging"),
    );
    assert_eq!(args[0], "/a", "admin (extract-only) install");
    assert!(args.iter().any(|a| a == r"C:\dl\hole.msi"), "the MSI path");
    assert!(args.iter().any(|a| a == "/qn"), "admin install must be silent");
    assert!(
        args.iter().any(|a| a.starts_with("TARGETDIR=")),
        "must target the staging dir"
    );
}

#[skuld::test]
fn reverify_rejects_a_missing_payload() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope.msi");
    assert!(reverify(&missing).is_err(), "missing payload must fail closed");
}

#[skuld::test]
fn reverify_rejects_a_directory_payload() {
    let dir = tempfile::tempdir().unwrap();
    assert!(reverify(dir.path()).is_err(), "a directory is not a payload file");
}

#[skuld::test]
fn reverify_accepts_a_present_file() {
    let dir = tempfile::tempdir().unwrap();
    let payload = dir.path().join("hole.msi");
    std::fs::write(&payload, b"stub").unwrap();
    assert!(reverify(&payload).is_ok());
}
