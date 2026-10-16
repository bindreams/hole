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
//! assumed to be `C:\Windows`. If that call fails there is no directory to
//! trust, and falling back to a bare name would reintroduce the search-order
//! hazard, so [`SystemTool::path`] and [`SystemTool::command`] return the
//! error; callers carry it as their spawn error. Spawning anything else (Hole's
//! own executable, dev tooling) is not covered here; the workspace `clippy.toml`
//! bans every `Command` constructor so each such site must say why it is exempt.

use std::io;
use std::path::PathBuf;
use std::process::Command;

#[cfg(target_os = "macos")]
mod tools {
    use std::io;
    use std::path::PathBuf;
    use std::process::Command;

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
        /// stable across the macOS versions Hole supports, so this never fails
        /// here; the `Result` is the Windows signature.
        pub(super) fn resolve_path(self) -> io::Result<PathBuf> {
            Ok(PathBuf::from(match self {
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
            }))
        }

        /// The program's bare name, for text that must stay free of paths.
        pub fn name(self) -> &'static str {
            match self {
                Self::Route => "route",
                Self::Ifconfig => "ifconfig",
                Self::Pfctl => "pfctl",
                Self::Networksetup => "networksetup",
                Self::Dscacheutil => "dscacheutil",
                Self::Killall => "killall",
                Self::Launchctl => "launchctl",
                Self::Dseditgroup => "dseditgroup",
                Self::Stat => "stat",
                Self::Logname => "logname",
            }
        }

        /// Nothing to pin on macOS.
        pub(super) fn pin_environment(self, _command: &mut Command) -> io::Result<()> {
            Ok(())
        }
    }
}

#[cfg(windows)]
mod tools {
    use std::io;
    use std::path::PathBuf;
    use std::process::Command;
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
        /// `System32\pnputil.exe`
        Pnputil,
    }

    impl SystemTool {
        /// Every variant, for tests that must cover the whole set.
        pub const ALL: &'static [SystemTool] = &[Self::Route, Self::Netsh, Self::Net, Self::Powershell, Self::Pnputil];

        /// The tool's absolute path under the OS-reported system directory.
        pub(super) fn resolve_path(self) -> io::Result<PathBuf> {
            let system32 = system_directory()?;
            Ok(match self {
                Self::Route => system32.join("route.exe"),
                Self::Netsh => system32.join("netsh.exe"),
                Self::Net => system32.join("net.exe"),
                Self::Powershell => system32.join("WindowsPowerShell").join("v1.0").join("powershell.exe"),
                Self::Pnputil => system32.join("pnputil.exe"),
            })
        }

        /// The program's bare name, for text that must stay free of paths.
        pub fn name(self) -> &'static str {
            match self {
                Self::Route => "route",
                Self::Netsh => "netsh",
                Self::Net => "net",
                Self::Powershell => "powershell",
                Self::Pnputil => "pnputil",
            }
        }

        /// A root PowerShell autoloads cmdlets from `PSModulePath`, whose default
        /// begins with the invoking user's `Documents\WindowsPowerShell\Modules`
        /// (user-writable), so the child gets only the system module directory.
        /// The other tools resolve nothing by search order once launched by
        /// absolute path.
        pub(super) fn pin_environment(self, command: &mut Command) -> io::Result<()> {
            match self {
                Self::Powershell => {
                    command.env("PSModulePath", powershell_module_directory()?);
                }
                Self::Route | Self::Netsh | Self::Net | Self::Pnputil => {}
            }
            Ok(())
        }
    }

    fn powershell_module_directory() -> io::Result<PathBuf> {
        Ok(system_directory()?
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("Modules"))
    }

    /// The system directory, read once. A failure is not cached: the next call
    /// asks the OS again.
    fn system_directory() -> io::Result<&'static PathBuf> {
        static DIR: OnceLock<PathBuf> = OnceLock::new();
        if let Some(dir) = DIR.get() {
            return Ok(dir);
        }
        let dir = read_system_directory(|buf| {
            use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
            // SAFETY: `GetSystemDirectoryW` writes only into the slice it is given.
            unsafe { GetSystemDirectoryW(buf) }
        })?;
        Ok(DIR.get_or_init(|| dir))
    }

    /// `GetSystemDirectoryW`'s two-call protocol over an injectable `get`: with
    /// `None` it returns the buffer length needed (NUL included), with a buffer
    /// it returns the length written (NUL excluded). 0 is failure in both.
    pub(crate) fn read_system_directory(mut get: impl FnMut(Option<&mut [u16]>) -> u32) -> io::Result<PathBuf> {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;

        let needed = get(None) as usize;
        if needed == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buf = vec![0u16; needed];
        let written = get(Some(&mut buf)) as usize;
        if written == 0 {
            return Err(io::Error::last_os_error());
        }
        if written >= needed {
            // The directory grew between the two calls; `written` is then the
            // size needed, not a length written.
            return Err(io::Error::other(
                "GetSystemDirectoryW: the system directory changed between the length query and the read",
            ));
        }
        Ok(PathBuf::from(OsString::from_wide(&buf[..written])))
    }
}

pub use tools::SystemTool;

#[cfg(windows)]
#[cfg(test)]
pub(crate) use tools::read_system_directory;

impl SystemTool {
    /// The tool's absolute path.
    ///
    /// # Errors
    ///
    /// On Windows, when `GetSystemDirectoryW` fails. There is then no directory
    /// to trust, and the caller reports it as its spawn error.
    pub fn path(self) -> io::Result<PathBuf> {
        self.resolve_path()
    }

    /// The only sanctioned constructor of a `Command` for a system tool. Its
    /// program is [`path`](Self::path), never a bare name, and its environment is
    /// pinned where the tool would otherwise search a user-writable place.
    ///
    /// # Errors
    ///
    /// As [`path`](Self::path).
    #[allow(clippy::disallowed_methods)] // this IS the sanctioned constructor; clippy.toml routes every other site here
    pub fn command(self) -> io::Result<Command> {
        let mut command = Command::new(self.path()?);
        self.pin_environment(&mut command)?;
        Ok(command)
    }

    /// The argv text for logging: the absolute path followed by `args`. When the
    /// path is unavailable (see [`path`](Self::path)) it names the tool instead,
    /// since the text is only ever logged, never run.
    pub fn display_with<S: AsRef<str>>(self, args: &[S]) -> String {
        let mut out = match self.path() {
            Ok(path) => path.display().to_string(),
            Err(_) => self.name().to_string(),
        };
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
