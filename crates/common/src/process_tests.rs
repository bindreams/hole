use super::*;

#[skuld::test]
fn own_process_has_a_start_time() {
    assert!(process_start_time(std::process::id()).is_some());
}

#[skuld::test]
fn absent_pid_has_no_start_time() {
    // PID 0 is never a real process (Windows reserves it; Unix uses it for the group).
    assert_eq!(process_start_time(0), None);
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn live_process_matches_and_alive() {
    let me = std::process::id();
    let start = process_start_time(me).unwrap();
    assert_eq!(process_matches_and_alive(me, start), Some(true));
    assert_eq!(process_matches_and_alive(me, start + 1), Some(false)); // PID-reuse guard
    assert_eq!(process_matches_and_alive(0, 0), Some(false)); // no such process
}

// A terminated child whose handle is still open (zombie) reads as confirmed-dead
// — for exit code 0 AND a non-zero exit (the exit-FILETIME check is code-agnostic).
#[cfg(target_os = "windows")]
#[skuld::test]
fn zombie_process_is_not_alive() {
    for args in [["/c", "exit"].as_slice(), ["/c", "exit 5"].as_slice()] {
        let mut child = std::process::Command::new("cmd").args(args).spawn().unwrap();
        let pid = child.id();
        let start = process_start_time(pid).unwrap();
        child.wait().unwrap(); // dead; `child` (handle) kept in scope → unreaped zombie
        assert_eq!(
            process_matches_and_alive(pid, start),
            Some(false),
            "an exited-but-unreaped process must read as confirmed-dead"
        );
        drop(child);
    }
}
