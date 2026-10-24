//! configd's DNS-configuration-changed notification, the event the macOS DNS tests wait on instead of
//! elapsed time.

use std::ffi::CString;
use std::io;
use std::time::Instant;

use super::scutil_dns_checked;

const DNS_CONFIG_NOTIFY_KEY: &str = "com.apple.system.SystemConfiguration.dns_configuration";

extern "C" {
    fn notify_register_file_descriptor(
        name: *const libc::c_char,
        notify_fd: *mut libc::c_int,
        flags: libc::c_int,
        out_token: *mut libc::c_int,
    ) -> u32;
    fn notify_cancel(token: libc::c_int) -> u32;
}

/// A live registration for configd's DNS-configuration-changed notification. Every wait rendezvous on
/// this rather than on elapsed time; the `deadline` passed to `wait`/`settle` is the failure bound
/// surfaced to a human when configd never posts, not a sync sleep.
pub struct DnsConfigNotify {
    fd: libc::c_int,
    token: libc::c_int,
}

impl DnsConfigNotify {
    pub fn register() -> Option<Self> {
        let name = CString::new(DNS_CONFIG_NOTIFY_KEY).expect("notify key has no interior NUL");
        let mut fd: libc::c_int = -1;
        let mut token: libc::c_int = 0;
        // SAFETY: `name` is a valid NUL-terminated string that outlives the
        // call; `fd`/`token` are live out-params.
        let status = unsafe { notify_register_file_descriptor(name.as_ptr(), &mut fd, 0, &mut token) };
        (status == 0).then_some(Self { fd, token })
    }

    /// Block until configd posts a DNS-configuration change, or `deadline` passes.
    pub fn wait(&self, deadline: Instant) -> bool {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            let millis = libc::c_int::try_from(remaining.as_millis().max(1)).unwrap_or(libc::c_int::MAX);
            let mut pfd = libc::pollfd {
                fd: self.fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: single live pollfd, count matches.
            match unsafe { libc::poll(&mut pfd, 1, millis) } {
                -1 if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => continue,
                -1 => return false,
                0 => return false,
                _ => {
                    let mut token_be = [0u8; 4];
                    // SAFETY: reading 4 bytes into a 4-byte buffer.
                    let n = unsafe { libc::read(self.fd, token_be.as_mut_ptr().cast(), 4) };
                    return n == 4;
                }
            }
        }
    }

    /// Block until `scutil --dns` mentioning `needle` equals `want`, driven by configd's own change posts.
    /// Checks the predicate first, so an already-satisfied state (a registration made after the mutation
    /// landed) needs no event at all.
    pub fn settle(&self, deadline: Instant, needle: &str, want: bool) -> bool {
        let mentions = || scutil_dns_checked().unwrap_or_default().contains(needle);
        loop {
            if mentions() == want {
                return true;
            }
            if !self.wait(deadline) {
                return mentions() == want;
            }
        }
    }
}

impl Drop for DnsConfigNotify {
    fn drop(&mut self) {
        // SAFETY: token was produced by a successful registration.
        unsafe {
            notify_cancel(self.token);
        }
    }
}
