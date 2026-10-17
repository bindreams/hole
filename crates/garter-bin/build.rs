use std::path::PathBuf;

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    // `CARGO_MANIFEST_DIR` is `<repo>/crates/garter-bin`; walk up twice.
    let repo_root = PathBuf::from(&manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .to_path_buf();

    xtask_lib::git_rerun::emit_rerun_if_changed(&repo_root);

    let version = xtask_lib::version::display_version(&repo_root, xtask_lib::version::Group::Garter);
    println!("cargo:rustc-env=GARTER_VERSION={version}");
}
