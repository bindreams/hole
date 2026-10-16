//! Absolute paths for the OS tools Hole spawns.
//!
//! The bridge runs as root/SYSTEM, so a program named without a directory is
//! resolved by something an unprivileged user can influence: `PATH` on macOS;
//! on Windows `CreateProcess` searches the application's directory and the
//! *current directory* before System32 (see
//! <https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw>,
//! "lpApplicationName"). [`SystemTool::command`] is the only way to build a
//! `Command` for these tools, and its program is always an absolute path.
//!
//! The Windows directory is read from the OS (`GetSystemDirectoryW`), never
//! assumed to be `C:\Windows`. Spawning anything else (Hole's own executable,
//! dev tooling) is not covered here; the workspace `clippy.toml` bans
//! `Command::new` so each such site must say why it is exempt.

use std::process::Command;

#[cfg(target_os = "macos")]
mod tools {
    /// An OS tool the macOS bridge spawns, at its fixed absolute path.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum SystemTool {
        /// `/sbin/route`
        Route,
        /// `/sbin/ifconfig`
        Ifconfig,
        /// `/sbin/pfctl`
        Pfctl,
        /// `/usr/sbin/networksetup`
        Networksetup,
        /// `/usr/bin/dscacheutil`
        Dscacheutil,
        /// `/usr/bin/killall`
        Killall,
        /// `/bin/launchctl`
        Launchctl,
        /// `/usr/sbin/dseditgroup`
        Dseditgroup,
        /// `/usr/bin/stat`
        Stat,
        /// `/usr/bin/logname`
        Logname,
    }

    impl SystemTool {
        /// Every variant, for tests that must cover the whole set.
        pub const ALL: &'static [SystemTool] = &[
            Self::Route,
            Self::Ifconfig,
            Self::Pfctl,
            Self::Networksetup,
            Self::Dscacheutil,
            Self::Killall,
            Self::Launchctl,
            Self::Dseditgroup,
            Self::Stat,
            Self::Logname,
        ];

        /// The tool's absolute path. These are SIP-protected locations that are
        /// stable across the macOS versions Hole supports.
        pub fn path(self) -> std::path::PathBuf {
            std::path::PathBuf::from(match self {
                Self::Route => "/sbin/route",
                Self::Ifconfig => "/sbin/ifconfig",
                Self::Pfctl => "/sbin/pfctl",
                Self::Networksetup => "/usr/sbin/networksetup",
                Self::Dscacheutil => "/usr/bin/dscacheutil",
                Self::Killall => "/usr/bin/killall",
                Self::Launchctl => "/bin/launchctl",
                Self::Dseditgroup => "/usr/sbin/dseditgroup",
                Self::Stat => "/usr/bin/stat",
                Self::Logname => "/usr/bin/logname",
            })
        }
    }
}

#[cfg(windows)]
mod tools {
    use std::path::PathBuf;
    use std::sync::OnceLock;

    /// An OS tool the Windows bridge spawns, under the system directory.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum SystemTool {
        /// `System32\route.exe`
        Route,
        /// `System32\netsh.exe`
        Netsh,
        /// `System32\net.exe`
        Net,
        /// `System32\WindowsPowerShell\v1.0\powershell.exe`
        Powershell,
    }

    impl SystemTool {
        /// Every variant, for tests that must cover the whole set.
        pub const ALL: &'static [SystemTool] = &[Self::Route, Self::Netsh, Self::Net, Self::Powershell];

        /// The tool's absolute path under the OS-reported system directory.
        ///
        /// # Panics
        ///
        /// If `GetSystemDirectoryW` fails, which leaves no directory to trust;
        /// falling back to a bare name would reintroduce the search-order hazard
        /// this type exists to remove.
        pub fn path(self) -> PathBuf {
            let system32 = system_directory();
            match self {
                Self::Route => system32.join("route.exe"),
                Self::Netsh => system32.join("netsh.exe"),
                Self::Net => system32.join("net.exe"),
                Self::Powershell => system32.join("WindowsPowerShell").join("v1.0").join("powershell.exe"),
            }
        }
    }

    fn system_directory() -> &'static PathBuf {
        static DIR: OnceLock<PathBuf> = OnceLock::new();
        DIR.get_or_init(|| {
            use std::ffi::OsString;
            use std::os::windows::ffi::OsStringExt;
            use windows::Win32::System::SystemInformation::GetSystemDirectoryW;

            // SAFETY: both calls write only into the slice they are given.
            let needed = unsafe { GetSystemDirectoryW(None) } as usize;
            assert!(needed != 0, "GetSystemDirectoryW failed to report a length");
            let mut buf = vec![0u16; needed];
            // Returns the length without the NUL on success, 0 on failure.
            let written = unsafe { GetSystemDirectoryW(Some(&mut buf)) } as usize;
            assert!(
                written != 0 && written < needed,
                "GetSystemDirectoryW failed to return the system directory"
            );
            PathBuf::from(OsString::from_wide(&buf[..written]))
        })
    }
}

pub use tools::SystemTool;

impl SystemTool {
    /// The only sanctioned constructor of a `Command` for a system tool. Its
    /// program is [`path`](Self::path), never a bare name.
    #[allow(clippy::disallowed_methods)] // this IS the sanctioned constructor; clippy.toml routes every other site here
    pub fn command(self) -> Command {
        Command::new(self.path())
    }

    /// The argv text for logging: the absolute path followed by `args`.
    pub fn display_with<S: AsRef<str>>(self, args: &[S]) -> String {
        let mut out = self.path().display().to_string();
        for a in args {
            out.push(' ');
            out.push_str(a.as_ref());
        }
        out
    }
}

#[cfg(test)]
#[path = "system_tool_tests.rs"]
mod system_tool_tests;
