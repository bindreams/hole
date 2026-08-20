use crate::steps::{resolve_tool, stage_dir_path, StageDirGuard};

#[skuld::test]
fn stage_dir_is_per_pid_under_temp() {
    let p = stage_dir_path(1234);
    assert_eq!(p, std::env::temp_dir().join("hole-dev-1234"));
}

/// The `.cmd`/PATHEXT trap (dev.py §5.17/§6.4): `which` must resolve a
/// PATH name to a spawnable file. Hermetic targets: `cargo` exists on every
/// dev/CI host running these tests; on Windows additionally pin that a
/// builtin-shaped name resolves to a real `.exe`/`.cmd` path.
#[skuld::test]
fn resolve_tool_finds_cargo() {
    let p = resolve_tool("cargo").expect("cargo is on PATH wherever tests run");
    assert!(p.is_absolute());
}

#[cfg(windows)]
#[skuld::test]
fn resolve_tool_appends_windows_extension() {
    let p = resolve_tool("cmd").expect("cmd is on PATH on Windows");
    let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
    assert!(
        ext == "exe" || ext == "cmd" || ext == "bat",
        "PATHEXT resolution produced {p:?}"
    );
}

/// The guard is registered BEFORE the dir is created (dev.py §5.11: a
/// partially-created dir still gets removed) and removes it on drop.
#[skuld::test]
fn guard_removes_dir_even_when_created_after_registration() {
    let base = tempfile::tempdir().unwrap();
    let dir = base.path().join("hole-dev-test");
    let guard = StageDirGuard::register(dir.clone());
    assert!(!dir.exists(), "registration must not create the dir");
    std::fs::create_dir_all(dir.join("nested")).unwrap();
    drop(guard);
    assert!(!dir.exists());
}

#[skuld::test]
fn guard_tolerates_never_created_dir() {
    let base = tempfile::tempdir().unwrap();
    drop(StageDirGuard::register(base.path().join("never-created")));
}

// npm launch resolution (the cmd.exe trap) ============================================================================

/// Build a synthetic Node install: `npm.cmd` beside `node.exe` and the npm CLI
/// entry script, which is the layout the official installer, fnm and nvm all
/// produce. `node` is a copy of THIS test binary, so the resulting launch is
/// really spawnable and can be asked what argv it received.
#[cfg(windows)]
fn fake_node_install() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let npm_cmd = root.join("npm.cmd");
    std::fs::write(&npm_cmd, b"@ECHO OFF\r\n").unwrap();
    std::fs::copy(std::env::current_exe().unwrap(), root.join("node.exe")).unwrap();
    let bin = root.join("node_modules").join("npm").join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(bin.join("npm-cli.js"), b"// npm\n").unwrap();
    (dir, npm_cmd)
}

/// A non-batch npm (every POSIX host, and a `.exe` shim on Windows) is spawned
/// directly: the launch is the resolved path with nothing in front of it.
#[skuld::test]
fn npm_launch_leaves_a_real_image_alone() {
    let dir = tempfile::tempdir().unwrap();
    let npm = dir.path().join(if cfg!(windows) { "npm.exe" } else { "npm" });
    std::fs::write(&npm, b"#!/bin/sh\n").unwrap();
    let launch = crate::steps::npm_launch_for(npm.clone()).unwrap();
    assert_eq!(launch.program(), npm);
    assert_eq!(
        launch.argv(&["run", "dev"]),
        [npm.as_os_str(), "run".as_ref(), "dev".as_ref()]
    );
}

/// `npm.cmd` is routed to `node node_modules/npm/bin/npm-cli.js` — the same
/// thing `npm.cmd` itself runs — because cosca refuses to spawn a batch file.
#[cfg(windows)]
#[skuld::test]
fn npm_launch_routes_a_batch_wrapper_through_node() {
    let (dir, npm_cmd) = fake_node_install();
    let launch = crate::steps::npm_launch_for(npm_cmd).unwrap();
    assert_eq!(launch.program(), dir.path().join("node.exe"));
    assert_eq!(
        launch.argv(&["run", "dev"]),
        [
            dir.path().join("node.exe").as_os_str(),
            dir.path()
                .join("node_modules")
                .join("npm")
                .join("bin")
                .join("npm-cli.js")
                .as_os_str(),
            "run".as_ref(),
            "dev".as_ref(),
        ]
    );
}

/// A batch wrapper with no Node entry script beside it fails LOUDLY and names
/// both paths, rather than silently falling back to a route that would drop the
/// handle-list hygiene.
#[cfg(windows)]
#[skuld::test]
fn npm_launch_without_an_entry_script_fails_loudly() {
    let dir = tempfile::tempdir().unwrap();
    let npm_cmd = dir.path().join("npm.cmd");
    std::fs::write(&npm_cmd, b"@ECHO OFF\r\n").unwrap();
    let err = crate::steps::npm_launch_for(npm_cmd).unwrap_err().to_string();
    assert!(err.contains("npm-cli.js"), "must name the missing entry script: {err}");
}

/// The two legs that make this whole resolution necessary, in one test so
/// neither can pass vacuously: cosca REFUSES the batch wrapper (the hazard is
/// real), and the resolved launch SPAWNS and receives the argv we intended.
#[cfg(windows)]
#[skuld::test]
async fn resolved_npm_launch_spawns_where_the_batch_wrapper_is_refused() {
    let (dir, npm_cmd) = fake_node_install();

    // Leg 1 — the hazard. Spawning the batch wrapper the way production spawns
    // Vite is refused outright; this is what broke `cargo xtask run hole`.
    let mut batch = cosca::tokio::Command::new();
    batch.executable(&npm_cmd);
    batch.arg(&npm_cmd);
    batch.stdin(cosca::Stdio::null()).unwrap();
    let err = batch.spawn().expect_err("cosca must refuse a .cmd program");
    assert!(
        err.to_string().contains("batch"),
        "the refusal must be the batch one, not an unrelated failure: {err}"
    );

    // Leg 2 — the resolution. `node` here is a copy of this test binary, so it
    // reports the argv it actually received.
    let launch = crate::steps::npm_launch_for(npm_cmd).unwrap();
    let argv = launch.argv(&["run", "dev"]);
    let mut cmd = cosca::tokio::Command::new();
    cmd.executable(launch.program());
    cmd.args(&argv);
    cmd.env(crate::test_child::MODE_ENV, "echo-argv");
    cmd.stdin(cosca::Stdio::null()).unwrap();
    cmd.stdout(cosca::Stdio::pipe()).unwrap();
    cmd.kill_on_drop(true)
        .contain()
        .nesting(cosca::containment::Nesting::Mark);
    let mut child = cmd.spawn().expect("the resolved launch must spawn");

    use tokio::io::AsyncBufReadExt as _;
    let mut received = Vec::new();
    let mut lines = tokio::io::BufReader::new(child.stdout().unwrap()).lines();
    while let Some(line) = lines.next_line().await.unwrap() {
        received.push(std::ffi::OsString::from(line));
    }
    child.wait().await.unwrap();
    assert_eq!(received, argv);
    drop(dir);
}
