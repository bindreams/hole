#![allow(clippy::disallowed_methods)] // dev tooling, never privileged

use crate::child_env::is_run_injected;
use crate::test_child::MODE_ENV;
use std::path::PathBuf;

#[skuld::test]
fn the_package_environment_cargo_run_injects_is_recognized() {
    // Measured: `cargo run` (cargo 1.99.0) exports exactly these to the program it launches.
    for name in [
        "CARGO_MANIFEST_DIR",
        "CARGO_MANIFEST_PATH",
        "CARGO_PKG_AUTHORS",
        "CARGO_PKG_DESCRIPTION",
        "CARGO_PKG_HOMEPAGE",
        "CARGO_PKG_LICENSE",
        "CARGO_PKG_LICENSE_FILE",
        "CARGO_PKG_NAME",
        "CARGO_PKG_README",
        "CARGO_PKG_REPOSITORY",
        "CARGO_PKG_RUST_VERSION",
        "CARGO_PKG_VERSION",
        "CARGO_PKG_VERSION_MAJOR",
        "CARGO_PKG_VERSION_MINOR",
        "CARGO_PKG_VERSION_PATCH",
        "CARGO_PKG_VERSION_PRE",
    ] {
        assert!(is_run_injected(name), "{name}");
    }
}

/// Configuration the user or CI chose for every cargo they run is not injected,
/// and removing it would change what the child builds.
#[skuld::test]
fn settings_a_caller_chose_are_not_recognized() {
    for name in [
        "CARGO",
        "CARGO_HOME",
        "CARGO_INCREMENTAL",
        "CARGO_TARGET_DIR",
        "CARGO_TERM_COLOR",
        "CARGO_BUILD_JOBS",
        "RUSTC_WRAPPER",
        "RUSTFLAGS",
        "PATH",
        "HOME",
    ] {
        assert!(!is_run_injected(name), "{name}");
    }
}

/// Names of the variables a process launched in `mode` reports, with the
/// injected package environment and one caller setting present in its own.
fn reported_env_names(mode: &str) -> Vec<String> {
    let out = std::process::Command::new(std::env::current_exe().expect("current_exe"))
        .env(MODE_ENV, mode)
        .env("CARGO_MANIFEST_DIR", "/injected")
        .env("CARGO_PKG_NAME", "injected")
        .env("CARGO_INCREMENTAL", "0")
        .output()
        .expect("spawn the process under test");
    assert!(
        out.status.success(),
        "{mode}: {:?}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .expect("utf-8 names")
        .lines()
        .map(str::to_string)
        .collect()
}

/// Stripping once at startup is what keeps every spawn clean: a process that has
/// stripped hands no child the injected variables, whatever spawns it, and keeps
/// the settings the caller chose. The control run shows the probe does see the
/// variables when nothing strips them.
#[skuld::test]
fn a_child_spawned_after_the_startup_strip_does_not_inherit_the_injected_variables() {
    let control = reported_env_names("list-env");
    assert!(
        control.iter().any(|n| n == "CARGO_MANIFEST_DIR"),
        "control saw {control:?}"
    );
    assert!(control.iter().any(|n| n == "CARGO_PKG_NAME"), "control saw {control:?}");

    let stripped = reported_env_names("strip-then-list-env-in-child");
    assert!(
        stripped.iter().any(|n| n == "CARGO_INCREMENTAL"),
        "a caller's setting must survive the strip, saw {stripped:?}"
    );
    let leaked: Vec<&String> = stripped
        .iter()
        .filter(|n| crate::child_env::is_run_injected(n))
        .collect();
    assert!(leaked.is_empty(), "children inherited {leaked:?}");
}

/// The strip is sound only while `main` is single-threaded, and `ctrlc` (behind
/// `install_transparent_interrupt`) starts a thread: the strip must be the
/// first statement of `main`, ahead of everything else.
#[skuld::test]
fn main_strips_before_anything_else_runs() {
    let main_rs = std::fs::read_to_string(crate::repo_root().expect("repo root").join("xtask/src/main.rs"))
        .expect("read xtask/src/main.rs");
    let body = main_rs
        .split_once("fn main() -> ExitCode {")
        .expect("main's signature")
        .1;
    let first_statement = body
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with("//"))
        .expect("main has a body");
    assert_eq!(first_statement, "xtask::child_env::strip_run_injected();");
}

/// Run a copy of this binary, placed in a throwaway workspace of its own (stand-in
/// for a `CARGO_TARGET_DIR` or `build.target-dir` elsewhere), in
/// `strip-then-repo-root` mode from there too, with `CARGO_MANIFEST_DIR` set as
/// `cargo run` sets it. Returns the root the copy found.
///
/// The throwaway workspace has its own manifest, so the walk up from the copy
/// stops there wherever `TMPDIR` points, even inside this repository.
fn repo_root_from_a_binary_outside_the_repo(manifest_dir: Option<&std::path::Path>) -> std::path::PathBuf {
    let outside = fake_workspace();
    let exe = outside
        .path()
        .join(std::env::current_exe().expect("current_exe").file_name().unwrap());
    std::fs::copy(std::env::current_exe().expect("current_exe"), &exe).expect("copy the binary out of the repo");
    let mut cmd = std::process::Command::new(&exe);
    cmd.env(MODE_ENV, "strip-then-repo-root").current_dir(outside.path());
    match manifest_dir {
        Some(dir) => cmd.env("CARGO_MANIFEST_DIR", dir),
        // The test runner has its own; the control must not inherit it.
        None => cmd.env_remove("CARGO_MANIFEST_DIR"),
    };
    let out = cmd.output().expect("spawn the copied binary");
    assert!(
        out.status.success(),
        "{:?}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let found = PathBuf::from(String::from_utf8(out.stdout).expect("utf-8 path").trim());
    assert!(found.is_dir(), "{found:?}");
    found.canonicalize().expect("found root exists")
}

/// `cargo run` tells the program where its crate is, and the strip removes that
/// before any subcommand looks for the workspace. Every subcommand must still
/// find it, whatever the target directory.
#[skuld::test]
fn the_workspace_root_is_found_after_the_strip_when_the_binary_lives_outside_the_repo() {
    let xtask_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let expected = xtask_dir.parent().expect("the xtask crate sits in the workspace");

    // Control: with no `CARGO_MANIFEST_DIR` to start from, the copy can only find
    // the workspace it sits in, so the next assertion proves the pin.
    let control = repo_root_from_a_binary_outside_the_repo(None);
    assert_ne!(control, expected.canonicalize().expect("expected root exists"));

    let found = repo_root_from_a_binary_outside_the_repo(Some(xtask_dir));
    assert_eq!(found, expected.canonicalize().expect("expected root exists"));
}

/// A relative or empty `CARGO_MANIFEST_DIR` is refused with an error naming it,
/// even after the strip removed the variable and even where the binary sits in
/// a workspace that would otherwise answer: the strip must not launder it into
/// the exe-based lookup.
#[skuld::test]
fn a_relative_or_empty_manifest_dir_is_reported_after_the_strip_not_replaced_by_the_exe_lookup() {
    let outside = fake_workspace();
    let exe = outside
        .path()
        .join(std::env::current_exe().expect("current_exe").file_name().unwrap());
    std::fs::copy(std::env::current_exe().expect("current_exe"), &exe).expect("copy the binary");
    for bad in ["crates/xtask", ""] {
        let out = std::process::Command::new(&exe)
            .env(MODE_ENV, "strip-then-repo-root")
            .env("CARGO_MANIFEST_DIR", bad)
            .current_dir(outside.path())
            .output()
            .expect("spawn the copied binary");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success(),
            "{bad:?} must be refused, found {}",
            String::from_utf8_lossy(&out.stdout)
        );
        assert!(stderr.contains("CARGO_MANIFEST_DIR"), "{bad:?}: {stderr}");
    }
}

/// A workspace root the test creates: a directory with a `[workspace]` manifest.
fn fake_workspace() -> tempfile::TempDir {
    let ws = tempfile::tempdir().expect("tempdir");
    std::fs::write(ws.path().join("Cargo.toml"), "[workspace]\nmembers = []\n").expect("write manifest");
    ws
}

/// [`fake_workspace`] that is also a hole root (has `crates/hole`).
fn fake_hole_workspace() -> tempfile::TempDir {
    let ws = fake_workspace();
    std::fs::create_dir_all(ws.path().join("crates").join("hole")).expect("create crates/hole");
    ws
}

/// Launch a copy of this binary at `exe_dir/<name>` as a `process:` step run
/// from `step_root`, the way `cargo xtask run hole` launches dev-console, in the
/// mode that reports the root the lookup dev-console uses finds. Returns it.
fn root_found_by_a_step_launched_binary(exe_dir: &std::path::Path, step_root: &std::path::Path) -> std::path::PathBuf {
    std::fs::create_dir_all(exe_dir).expect("create the binary's dir");
    let exe = exe_dir.join(std::env::current_exe().expect("current_exe").file_name().unwrap());
    std::fs::copy(std::env::current_exe().expect("current_exe"), &exe).expect("copy the binary");
    let out = tempfile::tempdir().expect("tempdir");
    let out_file = out.path().join("root.txt");
    let step = crate::manifest::Step::Process {
        args: vec![exe.to_string_lossy().into_owned()],
        environment: [
            (MODE_ENV.to_string(), "strip-then-handed-down-root".to_string()),
            (
                crate::test_child::OUT_ENV.to_string(),
                out_file.to_string_lossy().into_owned(),
            ),
        ]
        .into_iter()
        .collect(),
    };
    crate::orchestrate::run_step(&step, step_root).expect("the step runs");
    PathBuf::from(
        std::fs::read_to_string(&out_file)
            .expect("the child reported a root")
            .trim(),
    )
}

fn same_dir(a: &std::path::Path, b: &std::path::Path) -> bool {
    a.canonicalize().expect("exists") == b.canonicalize().expect("exists")
}

/// `cargo xtask run hole` launches dev-console as a `process:` step whose
/// working directory is the root xtask pinned before stripping
/// `CARGO_MANIFEST_DIR`. The child's own lookup must honour that directory when
/// its binary does not live under the workspace (a `target/` that is a symlink
/// out of it resolves to its canonical path on Linux).
#[skuld::test]
fn a_step_launched_binary_outside_the_workspace_finds_the_root_it_was_launched_from() {
    let ws = fake_hole_workspace();
    let elsewhere = tempfile::tempdir().expect("tempdir");
    let found = root_found_by_a_step_launched_binary(&elsewhere.path().join("bin"), ws.path());
    assert!(
        same_dir(&found, ws.path()),
        "found {found:?}, launched from {:?}",
        ws.path()
    );
}

/// `cargo xtask run hole` hands the root it pinned to the child explicitly, so a
/// binary whose location is inside a *different* hole checkout still resolves the
/// pinned one. Three ways the location gets there, one lookup input: the
/// executable under another hole root, the working directory the pinned root.
///
/// `target/` symlinked into another checkout (a canonical `current_exe`, as on
/// Linux) and `CARGO_TARGET_DIR` pointed into another checkout:
#[skuld::test]
fn a_step_launched_binary_in_another_hole_checkout_resolves_the_root_xtask_pinned() {
    let pinned = fake_hole_workspace();
    let other = fake_hole_workspace();
    let found = root_found_by_a_step_launched_binary(&other.path().join("target").join("debug"), pinned.path());
    assert!(
        same_dir(&found, pinned.path()),
        "found {found:?}, pinned {:?}, binary in {:?}",
        pinned.path(),
        other.path()
    );
}

/// A worktree nested under the main checkout (this project's layout) whose
/// `target` points at the main checkout's.
#[skuld::test]
fn a_step_launched_binary_in_the_checkout_enclosing_the_pinned_worktree_resolves_the_worktree() {
    let main = fake_hole_workspace();
    let worktree = main.path().join(".tmp").join("claude").join("wt").join("pinned");
    std::fs::create_dir_all(worktree.join("crates").join("hole")).expect("create the worktree");
    std::fs::write(worktree.join("Cargo.toml"), "[workspace]\nmembers = []\n").expect("write manifest");
    let found = root_found_by_a_step_launched_binary(&main.path().join("target").join("debug"), &worktree);
    assert!(
        same_dir(&found, &worktree),
        "found {found:?}, pinned {worktree:?}, binary in {:?}",
        main.path()
    );
}

/// The same binary run by hand (no handoff) belongs to the checkout it sits in,
/// whatever the working directory: the answer main always gave.
#[skuld::test]
fn a_hand_run_binary_resolves_the_checkout_it_sits_in() {
    let sits_in = fake_hole_workspace();
    let cwd = fake_hole_workspace();
    let exe_dir = sits_in.path().join("target").join("debug");
    std::fs::create_dir_all(&exe_dir).expect("create the binary's dir");
    let exe = exe_dir.join(std::env::current_exe().expect("current_exe").file_name().unwrap());
    std::fs::copy(std::env::current_exe().expect("current_exe"), &exe).expect("copy the binary");
    let out = tempfile::tempdir().expect("tempdir");
    let out_file = out.path().join("root.txt");
    let status = std::process::Command::new(&exe)
        .env(MODE_ENV, "strip-then-handed-down-root")
        .env(crate::test_child::OUT_ENV, &out_file)
        .env_remove(xtask_lib::repo_root::DEV_REPO_ROOT_ENV)
        .current_dir(cwd.path())
        .status()
        .expect("spawn the binary");
    assert!(status.success(), "{status:?}");
    let found = PathBuf::from(std::fs::read_to_string(&out_file).expect("reported a root").trim());
    assert!(
        same_dir(&found, sits_in.path()),
        "found {found:?}, binary in {:?}",
        sits_in.path()
    );
}

/// dev-console must use that lookup; the plain one accepts any workspace.
#[skuld::test]
fn dev_console_looks_the_root_up_by_the_launch_directory() {
    let src = std::fs::read_to_string(
        crate::repo_root()
            .expect("repo root")
            .join("crates/dev-console/src/supervise.rs"),
    )
    .expect("read supervise.rs");
    assert!(
        src.contains("xtask_lib::repo_root::repo_root_from_launch_dir()"),
        "dev-console's run() must call repo_root_from_launch_dir"
    );
}
