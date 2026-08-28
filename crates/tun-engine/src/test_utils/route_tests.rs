use super::{netstat_dest, route_added, route_removed};

fn output_with(success: bool, stderr: &str) -> std::process::Output {
    #[cfg(windows)]
    let status = {
        use std::os::windows::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(u32::from(!success))
    };
    #[cfg(not(windows))]
    let status = {
        use std::os::unix::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(if success { 0 } else { 1 << 8 })
    };
    std::process::Output {
        status,
        stdout: Vec::new(),
        stderr: stderr.as_bytes().to_vec(),
    }
}

/// Windows never needs the macOS stderr-parsing path — a bare exit status is
/// already a reliable oracle there (verified empirically against `netsh`).
/// This guards against `route_added`/`route_removed` accidentally routing a
/// Windows outcome through the macOS-specific predicate.
#[cfg(target_os = "windows")]
#[skuld::test]
fn route_added_and_removed_use_bare_exit_status_on_windows() {
    let success_with_failure_looking_stderr = output_with(true, "writing to routing socket: File exists");
    assert!(
        route_added(&success_with_failure_looking_stderr),
        "Windows must not parse stderr — exit 0 is success regardless of stderr content"
    );
    assert!(route_removed(&success_with_failure_looking_stderr));

    let failure = output_with(false, "");
    assert!(!route_added(&failure));
    assert!(!route_removed(&failure));
}

/// `netstat -rn` drops trailing zero octets, so the guard that searches its
/// output must derive its needle from the prefix the test installs — a
/// hardcoded literal goes stale the moment the prefix changes, and the
/// pre-existence guard then silently matches nothing.
#[skuld::test]
fn netstat_dest_drops_trailing_zero_octets() {
    assert_eq!(netstat_dest("198.51.100.0/24"), "198.51.100");
    assert_eq!(netstat_dest("203.0.113.0/24"), "203.0.113");
    assert_eq!(netstat_dest("10.0.0.0/8"), "10");
}

#[skuld::test]
fn netstat_dest_keeps_significant_octets() {
    assert_eq!(netstat_dest("198.51.100.7/32"), "198.51.100.7");
    assert_eq!(netstat_dest("192.168.10.0/23"), "192.168.10");
    assert_eq!(netstat_dest("8.8.8.8"), "8.8.8.8");
}

/// A destination that is all zeros keeps one octet rather than emptying out —
/// an empty needle would match every line of the routing table.
#[skuld::test]
fn netstat_dest_never_empties() {
    assert_eq!(netstat_dest("0.0.0.0/0"), "0");
}
