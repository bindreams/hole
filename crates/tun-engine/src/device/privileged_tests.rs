//! Privileged-lane oracle for [`super::config::TunName::KernelAssigned`]: it
//! creates a REAL `utun` device with no requested name and checks the kernel
//! actually assigned one, that [`resolve_identity`](super::identity::resolve_identity)
//! read it back correctly, and that the read-back name is the SAME device the
//! kernel opened — not merely a plausible-looking string.
//!
//! macOS only: `KernelAssigned` exists as a variant on every platform, but
//! only macOS's `utun` driver actually grants one — every other platform
//! rejects it with `InvalidConfig` before any OS call (see
//! [`super::config::TunName`]'s doc and `build_rejects_kernel_assigned_off_macos`
//! in `device_tests.rs`), so there is nothing to probe elsewhere.
//!
//! Needs no adapter-cleanup guard, unlike the Windows wintun privileged tests:
//! `crate::adapter_cleanup::remove_adapter` is a documented no-op on macOS —
//! the kernel tears the `utun` down when the owning FD closes, which
//! `AsyncDevice`'s own `Drop` does unconditionally, including on an unwind
//! from a failed assertion below.
//!
//! Runs on the elevated `tun` lane only (creating a `utun` device needs
//! elevation): the `TUN` label gates it out of the `SKULD_LABELS="!tun"` pass
//! and into the `SKULD_LABELS="tun"` one.
//!
//! Isolation is `serial = TUN` plus `.config/nextest.toml`'s `global_net_state`
//! group, which serializes it across test binaries — same treatment as every
//! other real-TUN-open privileged test, per that file's own instruction to
//! add new ones there.
//!
//! COUPLED NAMES: the test name below contains the substring
//! `opens_a_kernel_assigned`, which `.config/nextest.toml`'s `global_net_state`
//! filter matches. Renaming it without updating that filter silently drops it
//! from the group. NOT the bare `kernel_assigned` substring — that also
//! matches this crate's unlabelled unprivileged unit tests
//! (`identity_tests.rs`), which must stay out of the group.

use tun::AbstractDevice;

use super::{Device, MutDeviceConfig, TunName};
use crate::{GLOBAL_NET_STATE, TUN};

#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn device_opens_a_kernel_assigned_utun() {
    let device = Device::build(|c: &mut MutDeviceConfig| {
        c.tun_name = TunName::KernelAssigned;
        c.mtu = 1400;
        c.ipv4 = Some("10.255.242.1/24".parse().expect("literal"));
    })
    .expect("HARNESS: Device::build");

    // 1. The read-back name has the shape `man 4 utun` documents: `utun`
    //    followed by the unit number the kernel picked. Not `hole-tun` — a
    //    literal match there would mean the read-back seam silently fell
    //    back to the empty requested name instead of consulting the OS.
    let alias = device.identity().alias().to_string();
    assert_ne!(
        alias, "hole-tun",
        "KernelAssigned must read the real OS-assigned name, not a fallback"
    );
    let suffix = alias.strip_prefix("utun").unwrap_or_else(|| {
        panic!("expected a name of the form utunN (man 4 utun / UTUN_OPT_IFNAME read-back), got {alias:?}")
    });
    suffix
        .parse::<u32>()
        .unwrap_or_else(|e| panic!("the utun suffix must parse as u32, got {suffix:?} in {alias:?}: {e}"));

    // 2. The read-back name resolves, via the OS's own name table, to the
    //    SAME interface index this exact device opened. Compared against
    //    `tun.tun_index()` (the concrete opened device), never
    //    `Device::interface_index()` — that field is `None` unless an IPv6
    //    CIDR was configured (no IPv6 CIDR is set above), which would leave
    //    this coherence claim silently unchecked.
    let (tun, _config) = device.into_inner();
    let index_from_device: i32 = tun.tun_index().expect("HARNESS: tun_index() on the just-opened device");
    assert!(
        index_from_device > 0,
        "HARNESS: tun_index() returned a non-positive index: {index_from_device}"
    );

    let c_alias = std::ffi::CString::new(alias.as_str()).expect("HARNESS: alias has no interior NUL");
    // SAFETY: `c_alias` is a NUL-terminated C string valid for the call;
    // `if_nametoindex` performs a pure read via the OS's interface name
    // table and takes no ownership of the pointer.
    let index_from_name = unsafe { libc::if_nametoindex(c_alias.as_ptr()) };
    assert_ne!(
        index_from_name, 0,
        "if_nametoindex({alias:?}) reported no such interface — the read-back name does not resolve"
    );

    assert_eq!(
        index_from_name, index_from_device as u32,
        "the read-back name {alias:?} must resolve to the SAME interface this device opened \
         (if_nametoindex={index_from_name}, tun_index={index_from_device})"
    );
}
