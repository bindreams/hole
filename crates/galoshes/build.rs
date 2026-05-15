use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-check-cfg=cfg(v2ray_plugin_missing)");

    let target = std::env::var("TARGET").unwrap();
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    // `CARGO_MANIFEST_DIR` is `<repo>/crates/galoshes`; walk up twice to
    // reach the workspace root where `xtask v2ray-plugin` writes the
    // built binary under `.cache/v2ray-plugin/`.
    let repo_root = PathBuf::from(&manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .to_path_buf();
    let cache_dir = repo_root.join(".cache/v2ray-plugin");

    emit_version_env(&repo_root);

    let ext = if target.contains("windows") { ".exe" } else { "" };
    let binary_path = cache_dir.join(format!("v2ray-plugin-{target}{ext}"));

    if binary_path.exists() {
        println!("cargo:rustc-env=V2RAY_PLUGIN_PATH={}", binary_path.display());
        println!("cargo:rerun-if-changed={}", binary_path.display());

        let data = std::fs::read(&binary_path).unwrap();
        let hash = sha256(&data);
        println!("cargo:rustc-env=V2RAY_SHA256={hash}");
    } else {
        println!("cargo:warning=v2ray-plugin binary not found at {}. Run `cargo xtask v2ray-plugin` to build it. Galoshes will compile but panic at runtime.", binary_path.display());
        println!("cargo:rustc-cfg=v2ray_plugin_missing");
    }
}

fn emit_version_env(repo_root: &std::path::Path) {
    let git_dir = repo_root.join(".git");
    println!("cargo:rerun-if-changed={}", git_dir.join("HEAD").display());
    if let Ok(head) = std::fs::read_to_string(git_dir.join("HEAD")) {
        if let Some(refpath) = head.trim().strip_prefix("ref: ") {
            println!("cargo:rerun-if-changed={}", git_dir.join(refpath).display());
        }
    }
    println!("cargo:rerun-if-changed={}", git_dir.join("refs").join("tags").display());
    println!("cargo:rerun-if-changed={}", git_dir.join("packed-refs").display());

    let version = xtask_lib::version::display_version(repo_root, xtask_lib::version::Group::Galoshes);
    println!("cargo:rustc-env=GALOSHES_VERSION={version}");
}

fn sha256(data: &[u8]) -> String {
    use std::fmt::Write;
    let digest = <sha2::Sha256 as sha2::Digest>::digest(data);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        write!(hex, "{byte:02x}").unwrap();
    }
    hex
}
