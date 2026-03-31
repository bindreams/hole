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

/// Look up the SID of any account (user or group) as a string (e.g. `S-1-5-21-...`).
#[cfg(target_os = "windows")]
pub fn lookup_sid(name: &str) -> io::Result<String> {
    os::lookup_sid(name)
}

/// Look up the SID of the `hole` group as a string (e.g. `S-1-5-21-...`).
#[cfg(target_os = "windows")]
pub fn group_sid() -> io::Result<String> {
    lookup_sid(GROUP_NAME)
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

        // SAFETY: WTSGetActiveConsoleSessionId has no preconditions. Returns
        // 0xFFFFFFFF if no session is attached, which we check below.
        let session_id = unsafe { WTSGetActiveConsoleSessionId() };
        if session_id == 0xFFFFFFFF {
            return Err(io::Error::other(
                "no physical console session found (headless/RDP install)",
            ));
        }

        let mut buffer = PWSTR::null();
        let mut bytes_returned: u32 = 0;

        // SAFETY: `session_id` is a valid session (checked != 0xFFFFFFFF above).
        // `buffer` and `bytes_returned` are out-parameters; Windows allocates the
        // buffer via WTSFreeMemory-compatible allocator. We free it below.
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

        // SAFETY: The successful WTSQuerySessionInformationW call guarantees
        // `buffer.0` points to a valid UTF-16 string of `bytes_returned` bytes.
        // Windows always returns an even byte count for UTF-16 data (including the
        // null terminator). We convert to `len` u16 code units via from_raw_parts.
        let username = unsafe {
            debug_assert_eq!(bytes_returned % 2, 0, "WTS returned odd byte count");
            let len = (bytes_returned as usize) / 2;
            let slice = std::slice::from_raw_parts(buffer.0, len);
            // Trim trailing null
            let end = slice.iter().position(|&c| c == 0).unwrap_or(len);
            String::from_utf16_lossy(&slice[..end])
        };

        // SAFETY: `buffer.0` was allocated by WTSQuerySessionInformationW and must
        // be freed with WTSFreeMemory. We have finished reading the data above.
        unsafe {
            WTSFreeMemory(buffer.0 as *mut _);
        }

        if username.is_empty() {
            return Err(io::Error::other("console session has no user"));
        }

        Ok(username)
    }

    /// Look up any account name (user or group) and return its SID as a string.
    pub fn lookup_sid(name: &str) -> io::Result<String> {
        use windows::core::PWSTR;
        use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
        use windows::Win32::Security::{LookupAccountNameW, SID_NAME_USE};

        let account_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

        // First call: get required buffer sizes
        let mut sid_size: u32 = 0;
        let mut domain_size: u32 = 0;
        let mut sid_type = SID_NAME_USE::default();

        // SAFETY: First call to get required buffer sizes. `account_name` is a valid
        // null-terminated UTF-16 string kept alive for the call. Output buffer
        // pointers are None (size query only). `sid_size` and `domain_size` are
        // out-parameters filled with required sizes. Expected to fail with
        // ERROR_INSUFFICIENT_BUFFER.
        let _ = unsafe {
            LookupAccountNameW(
                None,
                windows::core::PCWSTR(account_name.as_ptr()),
                None,
                &mut sid_size,
                None,
                &mut domain_size,
                &mut sid_type,
            )
        };

        if sid_size == 0 {
            return Err(io::Error::other(format!("account '{name}' not found")));
        }

        // Second call: fill buffers
        // The global allocator guarantees alignment >= align_of::<usize>() (8 on
        // 64-bit, 4 on 32-bit), which satisfies PSID's DWORD alignment requirement.
        let mut sid_buf = vec![0u8; sid_size as usize];
        debug_assert_eq!(
            sid_buf.as_ptr() as usize % std::mem::align_of::<u32>(),
            0,
            "SID buffer must be DWORD-aligned"
        );
        let mut domain_buf = vec![0u16; domain_size as usize];
        let sid_ptr = windows::Win32::Security::PSID(sid_buf.as_mut_ptr() as *mut _);

        // SAFETY: Second call with correctly sized buffers. `sid_buf` is at least
        // `sid_size` bytes (allocated above). `domain_buf` is at least `domain_size`
        // u16 elements. `account_name` remains alive. `sid_ptr` wraps `sid_buf`'s
        // pointer. The result is checked with `?`.
        unsafe {
            LookupAccountNameW(
                None,
                windows::core::PCWSTR(account_name.as_ptr()),
                Some(sid_ptr),
                &mut sid_size,
                Some(PWSTR(domain_buf.as_mut_ptr())),
                &mut domain_size,
                &mut sid_type,
            )
        }
        .map_err(|e| io::Error::other(format!("LookupAccountNameW failed: {e}")))?;

        // Convert SID to string
        // SAFETY: `sid_ptr` contains a valid SID written by the successful
        // LookupAccountNameW call. `string_sid` is an out-parameter that Windows
        // allocates via LocalAlloc; we free it with LocalFree below.
        let mut string_sid = PWSTR::null();
        unsafe { ConvertSidToStringSidW(sid_ptr, &mut string_sid) }
            .map_err(|e| io::Error::other(format!("ConvertSidToStringSidW failed: {e}")))?;

        // SAFETY: `string_sid.0` is a valid null-terminated UTF-16 string allocated
        // by ConvertSidToStringSidW. The pointer walk terminates at the null
        // terminator. from_raw_parts reads exactly `len` elements.
        let sid_string = unsafe {
            let len = (0..).take_while(|&i| *string_sid.0.add(i) != 0).count();
            String::from_utf16_lossy(std::slice::from_raw_parts(string_sid.0, len))
        };

        // SAFETY: `string_sid.0` was allocated by ConvertSidToStringSidW via
        // LocalAlloc. Freed exactly once here after we have finished reading it.
        unsafe {
            windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(string_sid.0 as *mut _)));
        }

        Ok(sid_string)
    }
}

#[cfg(test)]
#[path = "group_tests.rs"]
mod group_tests;
