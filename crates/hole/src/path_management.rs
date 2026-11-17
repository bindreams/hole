// PATH management: add/remove hole to/from system PATH.

use std::path::{Path, PathBuf};

#[cfg(target_os = "windows")]
/// Get the directory containing the current executable.
fn exe_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let exe = std::env::current_exe()?;
    let dir = exe
        .parent()
        .ok_or("cannot determine executable directory")?
        .to_path_buf();
    Ok(dir)
}

// Link ownership ======================================================================================================

/// What is at the `hole` link path, as observed.
#[cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))]
#[derive(Debug, PartialEq, Eq)]
enum Entry {
    Absent,
    Directory,
    /// Anything that is neither a directory nor a symlink.
    File,
    Link(PathBuf),
}

/// What `add` does about the entry at the link path.
#[cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))]
#[derive(Debug, PartialEq, Eq)]
enum AddPlan {
    Create,
    AlreadyDone,
    /// An earlier install's link: delete it, then create ours.
    Replace,
    /// Not Hole's. Holds the message to return; nothing is deleted.
    Refuse(String),
}

/// What `remove` does about the entry at the link path.
#[cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))]
#[derive(Debug, PartialEq, Eq)]
enum RemovePlan {
    NothingToRemove,
    Remove,
    /// Not Hole's. Holds the message to return; nothing is deleted.
    Refuse(String),
}

/// Whether the entry is a symlink to a Hole binary, which is the only thing Hole may delete there.
#[cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))]
fn is_hole_link(entry: &Entry) -> bool {
    let Entry::Link(target) = entry else {
        return false;
    };
    matches!(target.file_name().and_then(|f| f.to_str()), Some("hole" | "hole.exe"))
}

#[cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))]
fn describe(entry: &Entry) -> String {
    match entry {
        Entry::Absent => "nothing".to_owned(),
        Entry::Directory => "a directory".to_owned(),
        Entry::File => "a file that is not a symlink".to_owned(),
        Entry::Link(target) => format!("a link to {}", target.display()),
    }
}

#[cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))]
fn decide_add(link_path: &Path, entry: &Entry, exe: &Path) -> AddPlan {
    match entry {
        Entry::Absent => AddPlan::Create,
        Entry::Link(target) if target == exe => AddPlan::AlreadyDone,
        _ if is_hole_link(entry) => AddPlan::Replace,
        _ => AddPlan::Refuse(format!(
            "{} is {}, not a link to a hole binary: refusing to replace it",
            link_path.display(),
            describe(entry)
        )),
    }
}

#[cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))]
fn decide_remove(link_path: &Path, entry: &Entry) -> RemovePlan {
    match entry {
        Entry::Link(_) if is_hole_link(entry) => RemovePlan::Remove,
        Entry::Link(_) => RemovePlan::Refuse(format!(
            "{} is {}, not a link to a hole binary: refusing to remove it",
            link_path.display(),
            describe(entry)
        )),
        Entry::Absent | Entry::Directory | Entry::File => RemovePlan::NothingToRemove,
    }
}

// Platform implementations ============================================================================================

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
        cli_log!(warn, "PATH already contains {dir_str}");
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
    cli_log!(info, "added {dir_str} to system PATH");
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
        cli_log!(warn, "PATH does not contain {dir_str}");
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
    cli_log!(info, "removed {dir_str} from system PATH");
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
    // SAFETY: `env_str` is a compile-time wide string literal with static lifetime,
    // so the LPARAM pointer remains valid for the duration of the call.
    // HWND_BROADCAST + WM_SETTINGCHANGE is the documented way to notify running
    // processes of environment changes. SMTO_ABORTIFHUNG prevents hangs from
    // unresponsive windows.
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

/// Observe what is at `path` without following a link.
#[cfg(target_os = "macos")]
fn observe(path: &Path) -> std::io::Result<Entry> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Entry::Absent),
        Err(e) => return Err(e),
    };
    let file_type = meta.file_type();
    if file_type.is_symlink() {
        return Ok(Entry::Link(std::fs::read_link(path)?));
    }
    Ok(if file_type.is_dir() {
        Entry::Directory
    } else {
        Entry::File
    })
}

#[cfg(target_os = "macos")]
const MACOS_LINK_PATH: &str = "/usr/local/bin/hole";

#[cfg(target_os = "macos")]
pub fn add() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    let exe = std::env::current_exe()?;
    let exe = std::fs::canonicalize(&exe)?;
    let link_path = Path::new(MACOS_LINK_PATH);

    // Warn about App Translocation
    let exe_str = exe.to_string_lossy();
    if exe_str.contains("/private/var/folders/") {
        cli_log!(warn, "warning: binary appears to be in an App Translocation path");
        cli_log!(warn, "  move Hole.app to /Applications first, then retry");
        return Err("App Translocation detected".into());
    }

    match decide_add(link_path, &observe(link_path)?, &exe) {
        AddPlan::AlreadyDone => {
            cli_log!(info, "symlink already exists and points to {exe_str}");
            return Ok(());
        }
        AddPlan::Refuse(message) => return Err(message.into()),
        AddPlan::Replace => std::fs::remove_file(link_path)?,
        AddPlan::Create => {}
    }

    symlink(&exe, link_path)?;
    cli_log!(info, "created symlink {MACOS_LINK_PATH} -> {exe_str}");
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn remove() -> Result<(), Box<dyn std::error::Error>> {
    let link_path = Path::new(MACOS_LINK_PATH);

    match decide_remove(link_path, &observe(link_path)?) {
        RemovePlan::NothingToRemove => {
            cli_log!(warn, "{MACOS_LINK_PATH} does not exist or is not a symlink");
            Ok(())
        }
        RemovePlan::Refuse(message) => Err(message.into()),
        RemovePlan::Remove => {
            std::fs::remove_file(link_path)?;
            cli_log!(info, "removed {MACOS_LINK_PATH}");
            Ok(())
        }
    }
}

#[cfg(test)]
#[path = "path_management_tests.rs"]
mod path_management_tests;
