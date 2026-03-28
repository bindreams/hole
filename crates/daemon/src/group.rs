// OS group management for IPC access control.
//
// Creates and manages a local "hole" group that gates access to the daemon's
// IPC socket/pipe. Members of this group (plus root/Administrators) can
// communicate with the daemon.

use std::io;

pub const GROUP_NAME: &str = "hole";

/// Create the `hole` group. Idempotent — succeeds if the group already exists.
pub fn create_group() -> io::Result<()> {
    os::create_group()
}

/// Delete the `hole` group. Idempotent — succeeds if the group doesn't exist.
pub fn delete_group() -> io::Result<()> {
    os::delete_group()
}

/// Add a user to the `hole` group.
pub fn add_user_to_group(username: &str) -> io::Result<()> {
    os::add_user_to_group(username)
}

/// Detect the real interactive user behind an elevated session.
///
/// On macOS: reads `SUDO_USER`, then `stat -f %Su /dev/console`, then `logname`.
/// On Windows: queries the physical console session via WTS APIs.
///
/// Returns `Err` if the user cannot be determined (e.g. headless install).
pub fn installing_username() -> io::Result<String> {
    os::installing_username()
}

/// Look up the SID of the `hole` group as a string (e.g. `S-1-5-21-...`).
#[cfg(target_os = "windows")]
pub fn group_sid() -> io::Result<String> {
    os::group_sid()
}

// macOS implementation ================================================================================================

#[cfg(target_os = "macos")]
mod os {
    use std::io;
    use std::process::Command;

    use super::GROUP_NAME;

    pub fn create_group() -> io::Result<()> {
        let output = Command::new("dseditgroup")
            .args(["-o", "create", GROUP_NAME])
            .output()?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        // "already exists" is not an error for our purposes
        if stderr.contains("already exists") {
            return Ok(());
        }

        Err(io::Error::other(format!(
            "dseditgroup create failed: {}",
            stderr.trim()
        )))
    }

    pub fn delete_group() -> io::Result<()> {
        let output = Command::new("dseditgroup")
            .args(["-o", "delete", GROUP_NAME])
            .output()?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        // Group not found is not an error for deletion
        if stderr.contains("not found") {
            return Ok(());
        }

        Err(io::Error::other(format!(
            "dseditgroup delete failed: {}",
            stderr.trim()
        )))
    }

    pub fn add_user_to_group(username: &str) -> io::Result<()> {
        let output = Command::new("dseditgroup")
            .args(["-o", "edit", "-a", username, "-t", "user", GROUP_NAME])
            .output()?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(io::Error::other(format!(
            "dseditgroup add user failed: {}",
            stderr.trim()
        )))
    }

    pub fn installing_username() -> io::Result<String> {
        // 1. Check SUDO_USER (set by sudo and osascript elevation)
        if let Ok(user) = std::env::var("SUDO_USER") {
            if !user.is_empty() && user != "root" {
                return Ok(user);
            }
        }

        // 2. stat /dev/console to find the GUI login user
        let output = Command::new("stat").args(["-f", "%Su", "/dev/console"]).output()?;
        if output.status.success() {
            let user = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !user.is_empty() && user != "root" {
                return Ok(user);
            }
        }

        // 3. logname as last resort
        let output = Command::new("logname").output()?;
        if output.status.success() {
            let user = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !user.is_empty() && user != "root" {
                return Ok(user);
            }
        }

        Err(io::Error::other("could not determine the installing user"))
    }
}

// Windows implementation ==============================================================================================

#[cfg(target_os = "windows")]
mod os {
    use std::io;
    use std::process::Command;

    use super::GROUP_NAME;

    pub fn create_group() -> io::Result<()> {
        let output = Command::new("net")
            .args(["localgroup", GROUP_NAME, "/add", "/comment:Hole daemon access"])
            .output()?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        // Error code 1379 = "The specified local group already exists."
        if stderr.contains("1379") || stderr.contains("already exists") {
            return Ok(());
        }

        Err(io::Error::other(format!(
            "net localgroup add failed: {}",
            stderr.trim()
        )))
    }

    pub fn delete_group() -> io::Result<()> {
        let output = Command::new("net")
            .args(["localgroup", GROUP_NAME, "/delete"])
            .output()?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        // Error code 1376 = "The specified local group does not exist."
        if stderr.contains("1376") || stderr.contains("does not exist") {
            return Ok(());
        }

        Err(io::Error::other(format!(
            "net localgroup delete failed: {}",
            stderr.trim()
        )))
    }

    pub fn add_user_to_group(username: &str) -> io::Result<()> {
        let output = Command::new("net")
            .args(["localgroup", GROUP_NAME, username, "/add"])
            .output()?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        // Error code 1378 = "The specified account name is already a member of the group."
        if stderr.contains("1378") || stderr.contains("already a member") {
            return Ok(());
        }

        Err(io::Error::other(format!(
            "net localgroup add user failed: {}",
            stderr.trim()
        )))
    }

    pub fn installing_username() -> io::Result<String> {
        use windows::core::PWSTR;
        use windows::Win32::System::RemoteDesktop::{
            WTSFreeMemory, WTSGetActiveConsoleSessionId, WTSQuerySessionInformationW, WTSUserName,
        };

        let session_id = unsafe { WTSGetActiveConsoleSessionId() };
        if session_id == 0xFFFFFFFF {
            return Err(io::Error::other(
                "no physical console session found (headless/RDP install)",
            ));
        }

        let mut buffer = PWSTR::null();
        let mut bytes_returned: u32 = 0;

        unsafe {
            WTSQuerySessionInformationW(
                None, // local server
                session_id,
                WTSUserName,
                &mut buffer as *mut PWSTR as *mut _,
                &mut bytes_returned,
            )
        }
        .map_err(|e| io::Error::other(format!("WTSQuerySessionInformationW failed: {e}")))?;

        let username = unsafe {
            let len = (bytes_returned as usize) / 2;
            let slice = std::slice::from_raw_parts(buffer.0, len);
            // Trim trailing null
            let end = slice.iter().position(|&c| c == 0).unwrap_or(len);
            String::from_utf16_lossy(&slice[..end])
        };

        unsafe {
            WTSFreeMemory(buffer.0 as *mut _);
        }

        if username.is_empty() {
            return Err(io::Error::other("console session has no user"));
        }

        Ok(username)
    }

    pub fn group_sid() -> io::Result<String> {
        use windows::core::PWSTR;
        use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
        use windows::Win32::Security::{LookupAccountNameW, SID_NAME_USE};

        let group_name: Vec<u16> = GROUP_NAME.encode_utf16().chain(std::iter::once(0)).collect();

        // First call: get required buffer sizes
        let mut sid_size: u32 = 0;
        let mut domain_size: u32 = 0;
        let mut sid_type = SID_NAME_USE::default();

        let _ = unsafe {
            LookupAccountNameW(
                None,
                windows::core::PCWSTR(group_name.as_ptr()),
                None,
                &mut sid_size,
                None,
                &mut domain_size,
                &mut sid_type,
            )
        };

        if sid_size == 0 {
            return Err(io::Error::other(format!("group '{}' not found", GROUP_NAME)));
        }

        // Second call: fill buffers
        let mut sid_buf = vec![0u8; sid_size as usize];
        let mut domain_buf = vec![0u16; domain_size as usize];
        let sid_ptr = windows::Win32::Security::PSID(sid_buf.as_mut_ptr() as *mut _);

        unsafe {
            LookupAccountNameW(
                None,
                windows::core::PCWSTR(group_name.as_ptr()),
                Some(sid_ptr),
                &mut sid_size,
                Some(PWSTR(domain_buf.as_mut_ptr())),
                &mut domain_size,
                &mut sid_type,
            )
        }
        .map_err(|e| io::Error::other(format!("LookupAccountNameW failed: {e}")))?;

        // Convert SID to string
        let mut string_sid = PWSTR::null();
        unsafe { ConvertSidToStringSidW(sid_ptr, &mut string_sid) }
            .map_err(|e| io::Error::other(format!("ConvertSidToStringSidW failed: {e}")))?;

        let sid_string = unsafe {
            let len = (0..).take_while(|&i| *string_sid.0.add(i) != 0).count();
            String::from_utf16_lossy(std::slice::from_raw_parts(string_sid.0, len))
        };

        unsafe {
            windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(string_sid.0 as *mut _)));
        }

        Ok(sid_string)
    }
}

#[cfg(test)]
#[path = "group_tests.rs"]
mod group_tests;
