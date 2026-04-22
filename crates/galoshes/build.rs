use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-check-cfg=cfg(v2ray_plugin_missing)");

    let target = std::env::var("TARGET").unwrap();
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let cache_dir = PathBuf::from(&manifest_dir)
        .parent()
        .unwrap()
        .join(".cache/v2ray-plugin");

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

fn sha256(data: &[u8]) -> String {
    use std::fmt::Write;
    let digest = <sha2::Sha256 as sha2::Digest>::digest(data);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        write!(hex, "{byte:02x}").unwrap();
    }
    hex
}
