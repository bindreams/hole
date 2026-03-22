/// Validate that installer.wxs compiles with the bundled WiX toolset.
///
/// This test catches WiX schema/syntax errors (like using deprecated element
/// syntax) before they reach a real build. It creates dummy source files so
/// WiX can resolve bindpath references.
#[cfg(target_os = "windows")]
#[skuld::test]
fn installer_wxs_compiles() {
    let wix_exe = cargo_wix::toolchain::ensure_wix().expect("failed to ensure WiX");

    // Create a temp staging dir with dummy files that the .wxs references
    let stage = tempfile::tempdir().expect("failed to create temp dir");
    for name in ["hole.exe", "v2ray-plugin.exe", "wintun.dll"] {
        std::fs::write(stage.path().join(name), b"dummy").expect("failed to write dummy file");
    }

    // Locate the .wxs file relative to the crate root
    let wxs = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("installer.wxs");
    assert!(wxs.exists(), "installer.wxs not found at {}", wxs.display());

    // Run wix build with dummy files — validates XML schema and element syntax
    let output_dir = stage.path().join("out");
    std::fs::create_dir_all(&output_dir).expect("failed to create output dir");
    let output_msi = output_dir.join("test.msi");

    let result = std::process::Command::new(&wix_exe)
        .args([
            "build",
            &wxs.to_string_lossy(),
            "-bindpath",
            &format!("BinDir={}", stage.path().display()),
            "-d",
            "ProductVersion=0.0.0",
            "-o",
            &output_msi.to_string_lossy(),
        ])
        .output()
        .expect("failed to run wix.exe");

    if !result.status.success() {
        let stdout = String::from_utf8_lossy(&result.stdout);
        let stderr = String::from_utf8_lossy(&result.stderr);
        panic!(
            "wix build failed (exit code {}):\nstdout:\n{stdout}\nstderr:\n{stderr}",
            result.status.code().unwrap_or(-1)
        );
    }

    assert!(output_msi.exists(), "MSI was not produced");
}
