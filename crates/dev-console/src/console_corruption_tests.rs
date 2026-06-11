//! Port of scripts/test_console_corruption.py — the stdin=null contract.
//! Label `windows_console`: needs a real interactive console and npm.
//! Run locally:
//! `SKULD_LABELS=windows_console cargo nextest run -p dev-console -E 'test(null_stdin_child_cannot_corrupt_console_mode)'`

use windows::Win32::System::Console::{GetConsoleMode, GetStdHandle, SetConsoleMode, CONSOLE_MODE, STD_INPUT_HANDLE};

#[skuld::label]
const WINDOWS_CONSOLE: skuld::Label;

fn console_input_mode() -> Option<u32> {
    // SAFETY: querying our own console handles.
    unsafe {
        let h = GetStdHandle(STD_INPUT_HANDLE).ok()?;
        let mut mode = CONSOLE_MODE::default();
        GetConsoleMode(h, &mut mode).ok()?;
        Some(mode.0)
    }
}

/// Restore-on-drop guard so leg 1's deliberate corruption can't poison
/// leg 2 or the terminal (ports test_console_corruption.py:110-113).
struct ConsoleModeGuard(u32);
impl Drop for ConsoleModeGuard {
    fn drop(&mut self) {
        // SAFETY: restoring the mode we snapshotted on our own console.
        unsafe {
            if let Ok(h) = GetStdHandle(STD_INPUT_HANDLE) {
                let _ = SetConsoleMode(h, CONSOLE_MODE(self.0));
            }
        }
    }
}

/// Run `npm run dev` with the given stdin, wait for Vite's ready marker,
/// kill the tree, and return the console input mode afterwards. Fails
/// LOUDLY if the marker never comes (the corruption check is meaningless
/// against a child that never initialized its console handlers — and Vite's
/// output format changing must break this test, not silently pass it).
/// The marker wait is a class-2 bound (third-party child; per-test timeout).
async fn run_vite_and_measure(stdin: std::process::Stdio) -> u32 {
    let npm = which::which("npm").expect("npm on PATH");
    let mut cmd = tokio::process::Command::new(npm);
    cmd.args(["run", "dev"]);
    // package.json lives at the workspace root; nextest's cwd is the crate
    // dir (the Python original ran from the repo root).
    cmd.current_dir(xtask_lib::repo_root::repo_root().expect("workspace root"));
    cmd.stdin(stdin)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    cmd.kill_on_drop(true);
    let mut gc = kill_group::GroupedChild::spawn(&mut cmd, kill_group::Nesting::Mark).unwrap();
    let stdout = gc.child.stdout.take().unwrap();
    use tokio::io::AsyncBufReadExt as _;
    let mut lines = tokio::io::BufReader::new(stdout).lines();
    loop {
        let line = lines
            .next_line()
            .await
            .unwrap()
            .expect("vite exited before its ready marker — output format changed or npm failed");
        let lower = line.to_lowercase();
        if lower.contains("ready in") || lower.contains("local:") {
            break;
        }
    }
    gc.kill_tree().await;
    console_input_mode().expect("console mode after")
}

/// BOTH legs of scripts/test_console_corruption.py — the vacuity guard
/// matters: if leg 1 (inherited stdin) no longer reproduces the corruption,
/// the stdin=null assertion in leg 2 proves nothing and the test must say so
/// (Python exits 1 with "bug did NOT reproduce", lines 124-147).
#[skuld::test(labels = [WINDOWS_CONSOLE])]
async fn null_stdin_child_cannot_corrupt_console_mode() {
    let Some(before) = console_input_mode() else {
        panic!("stdin is not a console — run from an interactive terminal (this test is label-gated for exactly that reason)");
    };
    let _restore = ConsoleModeGuard(before);

    // Leg 1: inherited stdin MUST corrupt (the bug repro / vacuity guard).
    let corrupted = run_vite_and_measure(std::process::Stdio::inherit()).await;
    assert_ne!(
        before, corrupted,
        "bug did NOT reproduce: an inherited-stdin Vite no longer alters the console mode \
         (Vite version change or non-interactive console?) — the stdin=null leg below would be vacuous"
    );
    // Restore before leg 2 (the guard also restores on panic).
    drop(ConsoleModeGuard(before));

    // Leg 2: null stdin must preserve the mode (the dev-console discipline).
    let after = run_vite_and_measure(std::process::Stdio::null()).await;
    assert_eq!(
        before, after,
        "a stdin=null child must not change the console input mode"
    );
}
