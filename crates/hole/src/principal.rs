//! Who a command runs for. The answer decides where its files go: a person, even an elevated one, gets their own
//! directories. With no person behind it, the installed service (`bridge run --service`) gets the system's, and any
//! other process, a GUI or a foreground `bridge run`, its own profile: it is not the installed service and keeps out
//! of the service's folders.

use std::io;
use std::path::PathBuf;

use hole_bridge::group::RealUser;

/// The identity the OS reports for this process, before the question of whether it is the daemon.
#[derive(Debug)]
pub enum Identity {
    /// An ordinary account running as itself. On Windows an elevated administrator is this too: elevation keeps
    /// their SID.
    Person,
    /// An account nobody logs in as: LocalSystem, LocalService, NetworkService, a per-service virtual account.
    ServiceAccount,
    /// The OS would not name this process's account. Treated as a person: the process's own profile.
    Unreadable(io::Error),
    /// Unix root. `sudo` replaces the identity, so the person behind it is reconstructed; the error is why none
    /// could be.
    Root(Result<RealUser, io::Error>),
}

/// Who a command runs for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    /// A person running as themselves: the process's own profile is theirs.
    Person,
    /// A person behind an elevation: their profile and ownership, not the process's.
    Elevated(RealUser),
    /// No person: the system's directories.
    Service,
}

/// A [`Principal`], and what went wrong reading the account when that changed the answer. No subscriber is
/// installed while the principal is resolved (it picks the log directory), so the warning waits for
/// [`Self::log_warning`].
#[derive(Debug)]
pub struct Resolved {
    pub principal: Principal,
    warning: Option<Warning>,
}

#[derive(Debug)]
struct Warning {
    message: &'static str,
    cause: io::Error,
}

impl Resolved {
    /// A principal with nothing to warn about.
    pub fn new(principal: Principal) -> Self {
        Self {
            principal,
            warning: None,
        }
    }

    fn with_warning(principal: Principal, message: &'static str, cause: io::Error) -> Self {
        Self {
            principal,
            warning: Some(Warning { message, cause }),
        }
    }

    /// Logs the warning, if any. Call once a subscriber is installed.
    pub fn log_warning(&self) {
        if let Some(Warning { message, cause }) = &self.warning {
            tracing::warn!(error = cause as &dyn std::error::Error, "{message}");
        }
    }
}

impl Principal {
    /// The principal of this process. `daemon` is whether the command is the service entry point
    /// (`bridge run --service`), which no account can make a person.
    pub fn resolve(daemon: bool) -> Resolved {
        Self::from_identity(daemon, Identity::of_process)
    }

    /// `identity` is read only for a command that is not the daemon.
    pub fn from_identity(daemon: bool, identity: impl FnOnce() -> Identity) -> Resolved {
        if daemon {
            return Resolved::new(Self::Service);
        }
        match identity() {
            Identity::Person => Resolved::new(Self::Person),
            Identity::ServiceAccount => Resolved::new(Self::Service),
            Identity::Unreadable(cause) => Resolved::with_warning(
                Self::Person,
                "could not read this process's account; treating it as a person",
                cause,
            ),
            Identity::Root(Ok(user)) => Resolved::new(Self::Elevated(user)),
            Identity::Root(Err(cause)) => Resolved::with_warning(
                Self::Service,
                "no person behind this elevation; treating it as the system",
                cause,
            ),
        }
    }

    /// The person behind an elevation: whose files these are, though the process is root.
    pub fn elevated(&self) -> Option<&RealUser> {
        match self {
            Self::Person => None,
            Self::Elevated(user) => Some(user),
            Self::Service => None,
        }
    }

    /// The default log directory of the installed service and of the commands that act for the system: a person's
    /// own, or the system's when there is none. A process that is not the installed service uses
    /// [`Self::own_log_dir`].
    pub fn log_dir(&self) -> PathBuf {
        match self {
            Self::Person => hole_common::logging::default_log_dir(),
            Self::Elevated(user) => hole_common::paths::user_log_dir(&user.home),
            Self::Service => hole_common::update_marker::service_log_dir(),
        }
    }

    /// The default log directory of a process that is not the installed service: the GUI, and `bridge run` without
    /// `--service`. With no person behind it, that is the process's own profile: the system's directory belongs to
    /// the installed service, whose update marker and crash marker such a process would otherwise sweep.
    pub fn own_log_dir(&self) -> PathBuf {
        match self {
            Self::Person => self.log_dir(),
            Self::Elevated(_) => self.log_dir(),
            Self::Service => hole_common::logging::default_log_dir(),
        }
    }

    /// The `(uid, gid)` that files this command creates are handed to.
    pub fn owner(&self) -> Option<(u32, u32)> {
        self.elevated().map(|user| (user.uid, user.gid))
    }
}

impl Identity {
    /// Classify a Windows account by its SID. The well-known service SIDs are matched whole; `S-1-5-80-` is the
    /// NT SERVICE domain, whose accounts all carry sub-authorities after it.
    pub fn of_sid(sid: &str) -> Self {
        match sid {
            "S-1-5-18" | "S-1-5-19" | "S-1-5-20" => Self::ServiceAccount,
            _ if sid.starts_with("S-1-5-80-") => Self::ServiceAccount,
            _ => Self::Person,
        }
    }

    fn of_process() -> Self {
        #[cfg(windows)]
        {
            match hole_bridge::target::current_user_sid() {
                Ok(sid) => Self::of_sid(&sid),
                Err(e) => Self::Unreadable(e),
            }
        }
        #[cfg(target_os = "macos")]
        {
            if !stepstool::is_privileged() {
                return Self::Person;
            }
            Self::Root(hole_bridge::group::resolve_real_user())
        }
        #[cfg(not(any(windows, target_os = "macos")))]
        {
            Self::Person
        }
    }
}

#[cfg(test)]
#[path = "principal_tests.rs"]
mod principal_tests;
