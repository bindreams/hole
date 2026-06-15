use super::*;

#[skuld::test]
fn old_name_appends_dotold_version_keeping_dir() {
    let installed = Path::new(r"C:\Program Files\hole\hole.exe");
    let old = old_name(installed, "0.3.0");
    assert_eq!(old, Path::new(r"C:\Program Files\hole\hole.exe.old-0.3.0"));
}

#[skuld::test]
fn old_name_handles_extensionless_binary() {
    let installed = Path::new(r"C:\Program Files\hole\galoshes");
    let old = old_name(installed, "0.3.0");
    assert_eq!(old, Path::new(r"C:\Program Files\hole\galoshes.old-0.3.0"));
}
