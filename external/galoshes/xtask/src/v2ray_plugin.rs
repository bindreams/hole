use std::path::PathBuf;
use std::process::Command;

/// Build v2ray-plugin from the vendored Go source.
pub fn build(target: Option<&str>) -> anyhow::Result<()> {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let source_dir = workspace_root.join("external/v2ray-plugin");
    let cache_dir = workspace_root.join(".cache/v2ray-plugin");

    anyhow::ensure!(
        source_dir.exists(),
        "v2ray-plugin source not found at {}. Run `git subrepo clone` first.",
        source_dir.display(),
    );

    std::fs::create_dir_all(&cache_dir)?;

    let host_target = guess_host_target();
    let target = target.unwrap_or(&host_target);

    let (goos, goarch) = target_to_go(target)?;
    let ext = if goos == "windows" { ".exe" } else { "" };
    let output = cache_dir.join(format!("v2ray-plugin-{target}{ext}"));

    eprintln!("Building v2ray-plugin for {target} (GOOS={goos}, GOARCH={goarch})");

    let status = Command::new("go")
        .arg("build")
        .arg("-trimpath")
        .arg("-ldflags=-s -w")
        .arg("-o")
        .arg(&output)
        .arg(".")
        .current_dir(&source_dir)
        .env("CGO_ENABLED", "0")
        .env("GOOS", &goos)
        .env("GOARCH", &goarch)
        .status()?;

    anyhow::ensure!(status.success(), "go build failed with status {status}");

    eprintln!("Built: {}", output.display());
    Ok(())
}

fn target_to_go(target: &str) -> anyhow::Result<(String, String)> {
    let goos = if target.contains("linux") {
        "linux"
    } else if target.contains("darwin") || target.contains("apple") {
        "darwin"
    } else if target.contains("windows") {
        "windows"
    } else {
        anyhow::bail!("unsupported target OS in: {target}");
    };

    let goarch = if target.contains("x86_64") || target.contains("amd64") {
        "amd64"
    } else if target.contains("aarch64") || target.contains("arm64") {
        "arm64"
    } else {
        anyhow::bail!("unsupported target arch in: {target}");
    };

    Ok((goos.into(), goarch.into()))
}

fn guess_host_target() -> String {
    let arch = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "unknown"
    };

    let os = if cfg!(target_os = "linux") {
        "unknown-linux-gnu"
    } else if cfg!(target_os = "macos") {
        "apple-darwin"
    } else if cfg!(target_os = "windows") {
        "pc-windows-msvc"
    } else {
        "unknown"
    };

    format!("{arch}-{os}")
}
