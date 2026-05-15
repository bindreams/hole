use std::path::PathBuf;

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    // `CARGO_MANIFEST_DIR` is `<repo>/crates/garter-bin`; walk up twice.
    let repo_root = PathBuf::from(&manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .to_path_buf();

    let git_dir = repo_root.join(".git");
    println!("cargo:rerun-if-changed={}", git_dir.join("HEAD").display());
    if let Ok(head) = std::fs::read_to_string(git_dir.join("HEAD")) {
        if let Some(refpath) = head.trim().strip_prefix("ref: ") {
            println!("cargo:rerun-if-changed={}", git_dir.join(refpath).display());
        }
    }
    println!("cargo:rerun-if-changed={}", git_dir.join("refs").join("tags").display());
    println!("cargo:rerun-if-changed={}", git_dir.join("packed-refs").display());

    let version = xtask_lib::version::display_version(&repo_root, xtask_lib::version::Group::Garter);
    println!("cargo:rustc-env=GARTER_VERSION={version}");
}
