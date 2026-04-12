// Plugin process crash recovery.
//
// Reads `bridge-plugins.json` (written by `plugin_state`) and kills any
// tracked plugin processes that are still alive. Called at bridge startup
// and from the test harness on teardown.
//
// Each kill is targeted at a specific PID + start-time pair recorded by
// the bridge that spawned the process. PID reuse is guarded by verifying
// the process's actual start time matches the recorded one within a
// tolerance window.

use crate::plugin_state;
use std::path::Path;

const START_TIME_TOLERANCE_MS: u64 = 2000;

/// Clean up plugin processes left behind by a previous bridge run.
///
/// Called at bridge startup AFTER the IPC socket bind succeeds (same
/// ordering as `routing::recover_routes`). Best-effort — errors logged
/// at `warn`, returns `()`.
pub fn recover_plugins(state_dir: &Path) {
    let Some(state) = plugin_state::load(state_dir) else {
        return;
    };

    for record in &state.plugins {
        let Some(actual_start) = process_start_time(record.pid) else {
            tracing::debug!(pid = record.pid, "plugin process no longer exists, skipping");
            continue;
        };

        let diff = actual_start.abs_diff(record.start_time_unix_ms);
        if diff > START_TIME_TOLERANCE_MS {
            tracing::info!(
                pid = record.pid,
                recorded_ms = record.start_time_unix_ms,
                actual_ms = actual_start,
                "PID reused by a different process, skipping"
            );
            continue;
        }

        match kill_pid(record.pid) {
            Ok(()) => tracing::info!(pid = record.pid, "reaped leaked plugin process"),
            Err(e) => tracing::warn!(pid = record.pid, error = %e, "failed to kill leaked plugin"),
        }
    }

    if let Err(e) = plugin_state::clear(state_dir) {
        tracing::warn!(error = %e, "failed to clear plugin state file");
    }
}

// Platform helpers ====================================================================================================

/// Kill a process by PID. Best-effort: ESRCH / "not found" is treated as
/// success (process already exited). EPERM is treated as an error.
pub fn kill_pid(pid: u32) -> std::io::Result<()> {
    platform::kill_pid_impl(pid)
}

/// Read the start time of a process as Unix milliseconds. Returns `None`
/// if the process doesn't exist.
pub fn process_start_time(pid: u32) -> Option<u64> {
    platform::process_start_time_impl(pid)
}

#[cfg(target_os = "windows")]
mod platform {
    use std::io;

    pub fn kill_pid_impl(pid: u32) -> io::Result<()> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

        // ERROR_INVALID_PARAMETER (87) — PID 0 or invalid
        // ERROR_ACCESS_DENIED (5) — insufficient privileges
        // 0x80070057 (E_INVALIDARG) — non-existent PID on some Windows versions
        let handle = match unsafe { OpenProcess(PROCESS_TERMINATE, false, pid) } {
            Ok(h) => h,
            Err(e) => {
                let code = e.code().0 as u32;
                // Treat "not found" as success (process already dead).
                if code == 0x80070057 || code == 87 {
                    return Ok(());
                }
                return Err(io::Error::from(e));
            }
        };

        let result = unsafe { TerminateProcess(handle, 1) };
        let _ = unsafe { CloseHandle(handle) };
        match result {
            Ok(()) => Ok(()),
            Err(e) => {
                // TerminateProcess on an already-terminated process returns
                // E_ACCESSDENIED (0x80070005). Treat as success.
                let code = e.code().0 as u32;
                if code == 0x80070005 {
                    return Ok(());
                }
                Err(io::Error::from(e))
            }
        }
    }

    pub fn process_start_time_impl(pid: u32) -> Option<u64> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::Foundation::FILETIME;
        use windows::Win32::System::Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;

        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();

        let ok = unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) };
        let _ = unsafe { CloseHandle(handle) };
        ok.ok()?;

        // FILETIME is 100-nanosecond intervals since 1601-01-01.
        // Convert to Unix ms: subtract the epoch diff, divide by 10_000.
        let ft = ((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64;
        const EPOCH_DIFF_100NS: u64 = 116_444_736_000_000_000;
        let unix_ms = ft.checked_sub(EPOCH_DIFF_100NS)? / 10_000;
        Some(unix_ms)
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use std::io;

    pub fn kill_pid_impl(pid: u32) -> io::Result<()> {
        let pid = i32::try_from(pid).map_err(|_| io::Error::other("PID out of i32 range"))?;
        let ret = unsafe { libc::kill(pid, libc::SIGKILL) };
        if ret == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(err)
        }
    }

    pub fn process_start_time_impl(pid: u32) -> Option<u64> {
        // Use sysctl KERN_PROC to get process start time.
        let mut info: libc::kinfo_proc = unsafe { std::mem::zeroed() };
        let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid as i32];
        let mut size = std::mem::size_of::<libc::kinfo_proc>();

        let ret = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                &mut info as *mut _ as *mut libc::c_void,
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };

        if ret != 0 || size == 0 {
            return None;
        }

        let tv = info.kp_proc.p_starttime;
        let ms = tv.tv_sec as u64 * 1000 + tv.tv_usec as u64 / 1000;
        Some(ms)
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::io;

    pub fn kill_pid_impl(pid: u32) -> io::Result<()> {
        let pid = i32::try_from(pid).map_err(|_| io::Error::other("PID out of i32 range"))?;
        let ret = unsafe { libc::kill(pid, libc::SIGKILL) };
        if ret == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(err)
        }
    }

    pub fn process_start_time_impl(pid: u32) -> Option<u64> {
        // Read /proc/<pid>/stat, field 22 (starttime in clock ticks since boot).
        // Then read /proc/stat btime (boot time in seconds since epoch).
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;

        // Field 22 is after the comm field (which can contain spaces and parens).
        // Find the closing paren, then split the rest.
        let after_comm = stat.rfind(')')?.checked_add(2)?;
        let fields: Vec<&str> = stat[after_comm..].split_whitespace().collect();
        // Field index 0 after comm = field 3 in stat; field 19 after comm = field 22 (starttime)
        let starttime_ticks: u64 = fields.get(19)?.parse().ok()?;

        let btime_line = std::fs::read_to_string("/proc/stat")
            .ok()?
            .lines()
            .find(|l| l.starts_with("btime "))?
            .to_string();
        let btime_secs: u64 = btime_line.split_whitespace().nth(1)?.parse().ok()?;

        let ticks_per_sec = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
        let start_secs = btime_secs + starttime_ticks / ticks_per_sec;
        let start_ms = start_secs * 1000 + (starttime_ticks % ticks_per_sec) * 1000 / ticks_per_sec;
        Some(start_ms)
    }
}

#[cfg(test)]
#[path = "plugin_recovery_tests.rs"]
mod plugin_recovery_tests;
