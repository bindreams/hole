// PATH management: add/remove hole to/from system PATH.

/// Get the directory containing the current executable.
#[cfg(target_os = "windows")]
use std::path::PathBuf;

#[cfg(target_os = "windows")]
fn exe_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let exe = std::env::current_exe()?;
    let dir = exe
        .parent()
        .ok_or("cannot determine executable directory")?
        .to_path_buf();
    Ok(dir)
}

// Platform implementations =====

#[cfg(target_os = "windows")]
pub fn add() -> Result<(), Box<dyn std::error::Error>> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE};
    use winreg::RegKey;

    let dir = exe_dir()?;
    let dir_str = dir.to_string_lossy();

    let env = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(
        r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        KEY_READ | KEY_WRITE,
    )?;

    let current_path: String = env.get_value("Path")?;

    // Check if already present
    let entries: Vec<&str> = current_path.split(';').collect();
    if entries.iter().any(|e| e.eq_ignore_ascii_case(&dir_str)) {
        eprintln!("PATH already contains {dir_str}");
        return Ok(());
    }

    // Append
    let new_path = if current_path.is_empty() {
        dir_str.to_string()
    } else {
        format!("{current_path};{dir_str}")
    };

    // Write as REG_EXPAND_SZ to preserve %SystemRoot% and similar variables
    let reg_value = winreg::RegValue {
        vtype: winreg::enums::RegType::REG_EXPAND_SZ,
        bytes: new_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(|w| w.to_le_bytes())
            .collect(),
    };
    env.set_raw_value("Path", &reg_value)?;
    broadcast_env_change();
    eprintln!("added {dir_str} to system PATH");
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn remove() -> Result<(), Box<dyn std::error::Error>> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE};
    use winreg::RegKey;

    let dir = exe_dir()?;
    let dir_str = dir.to_string_lossy();

    let env = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(
        r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        KEY_READ | KEY_WRITE,
    )?;

    let current_path: String = env.get_value("Path")?;

    // Filter out our directory
    let new_entries: Vec<&str> = current_path
        .split(';')
        .filter(|e| !e.eq_ignore_ascii_case(&dir_str))
        .collect();
    let new_path = new_entries.join(";");

    if new_path.len() == current_path.len() {
        eprintln!("PATH does not contain {dir_str}");
        return Ok(());
    }

    // Write as REG_EXPAND_SZ to preserve %SystemRoot% and similar variables
    let reg_value = winreg::RegValue {
        vtype: winreg::enums::RegType::REG_EXPAND_SZ,
        bytes: new_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(|w| w.to_le_bytes())
            .collect(),
    };
    env.set_raw_value("Path", &reg_value)?;
    broadcast_env_change();
    eprintln!("removed {dir_str} from system PATH");
    Ok(())
}

/// Broadcast WM_SETTINGCHANGE so running shells pick up the PATH change.
#[cfg(target_os = "windows")]
fn broadcast_env_change() {
    use windows::core::w;
    use windows::Win32::UI::WindowsAndMessaging::{
        SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE,
    };

    let env_str = w!("Environment");
    unsafe {
        let mut _result = 0usize;
        let _ = SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            windows::Win32::Foundation::WPARAM(0),
            windows::Win32::Foundation::LPARAM(env_str.as_ptr() as isize),
            SMTO_ABORTIFHUNG,
            1000,
            Some(&mut _result),
        );
    }
}

#[cfg(target_os = "macos")]
pub fn add() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    let exe = std::env::current_exe()?;
    let exe = std::fs::canonicalize(&exe)?;
    let link_path = std::path::Path::new("/usr/local/bin/hole");

    // Warn about App Translocation
    let exe_str = exe.to_string_lossy();
    if exe_str.contains("/private/var/folders/") {
        eprintln!("warning: binary appears to be in an App Translocation path");
        eprintln!("  move Hole.app to /Applications first, then retry");
        return Err("App Translocation detected".into());
    }

    if link_path.exists() || link_path.is_symlink() {
        // Check if it already points to us
        if let Ok(target) = std::fs::read_link(link_path) {
            if target == exe {
                eprintln!("symlink already exists and points to {exe_str}");
                return Ok(());
            }
        }
        // Remove stale symlink
        std::fs::remove_file(link_path)?;
    }

    symlink(&exe, link_path)?;
    eprintln!("created symlink /usr/local/bin/hole -> {exe_str}");
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn remove() -> Result<(), Box<dyn std::error::Error>> {
    let link_path = std::path::Path::new("/usr/local/bin/hole");

    if !link_path.is_symlink() {
        eprintln!("/usr/local/bin/hole does not exist or is not a symlink");
        return Ok(());
    }

    // Verify it's our symlink before removing (check the filename, not entire path)
    if let Ok(target) = std::fs::read_link(link_path) {
        let filename = target
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_default();
        if filename != "hole" && filename != "hole.exe" {
            return Err(format!(
                "/usr/local/bin/hole points to {}, not a hole binary — refusing to remove",
                target.display()
            )
            .into());
        }
    }

    std::fs::remove_file(link_path)?;
    eprintln!("removed /usr/local/bin/hole");
    Ok(())
}

#[cfg(test)]
#[path = "path_management_tests.rs"]
mod path_management_tests;
