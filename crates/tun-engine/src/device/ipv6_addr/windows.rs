//! Windows IPv6 address assignment, through IP Helper.
//!
//! Every step follows the `tun` crate's own `platform/windows/sys.rs`, because
//! that shape is exercised for the IPv4 address on every Full-mode start this
//! product makes.
//!
//! IP Helper, not `netsh`: `netsh interface ipv6 add address` defaults to
//! `store=persistent`, which writes the address to the registry keyed by the
//! adapter GUID — and wintun derives that GUID from the adapter name, so a
//! crash would leave the address waiting to be re-applied to the next
//! `hole-tun`. `CreateUnicastIpAddressEntry` has no persistence parameter, keys
//! on the interface identity, and returns a typed `WIN32_ERROR`. Nothing here
//! outlives the adapter, so `recover_routes` has nothing to sweep.
//!
//! Open question, recorded rather than assumed: Microsoft describes
//! `OnLinkPrefixLength` as the address's prefix length and documents no route
//! side effect, so whether the assignment also creates an on-link `/64` route
//! is unverified. Nothing here depends on it — the `/1` split routes carry the
//! flow either way.

use std::sync::mpsc::{sync_channel, RecvTimeoutError, SyncSender};
use std::sync::Mutex;
use std::time::Duration;

use smoltcp::wire::Ipv6Cidr;
use tracing::warn;
use windows::Win32::Foundation::{
    ERROR_NOT_FOUND, ERROR_NOT_SUPPORTED, ERROR_OBJECT_ALREADY_EXISTS, HANDLE, NO_ERROR, WIN32_ERROR,
};
use windows::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, ConvertInterfaceIndexToLuid, CreateUnicastIpAddressEntry, GetIpInterfaceEntry,
    InitializeUnicastIpAddressEntry, MibAddInstance, NotifyIpInterfaceChange, MIB_IPINTERFACE_ROW,
    MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW,
};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Networking::WinSock::{
    IpDadStatePreferred, IpPrefixOriginManual, IpSuffixOriginManual, AF_INET6, AF_UNSPEC,
};

use super::Assigned;
use crate::error::DeviceError;

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;

/// How long to wait for the interface's IPv6 half to appear.
///
/// This is a bound on an **external event that genuinely might never happen**,
/// not a synchronisation delay: when IPv6 is unbound on the host, the kernel
/// never publishes an AF_INET6 interface for this adapter, and the elapsed
/// budget *is* the answer. The wait blocks on an IP Helper notification rather
/// than polling. 5 s matches the `tun` crate's own
/// `wait_for_interface_timeout` default for the IPv4 half.
const IPV6_INTERFACE_BUDGET: Duration = Duration::from_secs(5);

/// Whether the interface's IPv6 half is there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Appearance {
    Appeared,
    NeverAppeared,
    /// IP Helper rejected the registration or the existence query. Distinct
    /// from `NeverAppeared`, which says the interface has no IPv6 half; this
    /// says nothing about the interface at all.
    Failed(WIN32_ERROR),
}

/// How `CreateUnicastIpAddressEntry`'s status reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CreateVerdict {
    Created,
    StackAbsent,
    Failed(WIN32_ERROR),
}

pub(super) fn assign(if_index: u32, cidr: Ipv6Cidr) -> Result<Assigned, DeviceError> {
    let luid = luid_for(if_index)?;
    let row = unicast_row(if_index, cidr);

    match wait_for_ipv6_interface(luid, IPV6_INTERFACE_BUDGET) {
        Appearance::NeverAppeared => return Ok(Assigned::Ipv6StackAbsent),
        Appearance::Failed(code) => {
            return Err(assign_error(if_index, "waiting for the IPv6 interface", code));
        }
        Appearance::Appeared => {}
    }

    // SAFETY: `row` is fully initialized by `unicast_row` and read-only here.
    match classify_create(unsafe { CreateUnicastIpAddressEntry(&row) }) {
        CreateVerdict::Created => Ok(Assigned::Address),
        CreateVerdict::StackAbsent => Ok(Assigned::Ipv6StackAbsent),
        CreateVerdict::Failed(code) => Err(assign_error(if_index, "CreateUnicastIpAddressEntry", code)),
    }
}

fn assign_error(index: u32, what: &str, code: WIN32_ERROR) -> DeviceError {
    DeviceError::Ipv6Assign {
        index,
        message: format!("{what} failed with Win32 error {}", code.0),
    }
}

fn luid_for(if_index: u32) -> Result<u64, DeviceError> {
    let mut luid = NET_LUID_LH::default();
    // SAFETY: `luid` is a live out-parameter for the duration of the call.
    let status = unsafe { ConvertInterfaceIndexToLuid(if_index, &mut luid) };
    if status != NO_ERROR {
        return Err(assign_error(if_index, "ConvertInterfaceIndexToLuid", status));
    }
    // SAFETY: `NET_LUID_LH` is a union of two same-sized POD views of one u64.
    Ok(unsafe { luid.Value })
}

/// The address row, created **non-tentative**: `DadState = IpDadStatePreferred`
/// makes the stack skip duplicate address detection for this address alone, so
/// there is no tentative window and no interface-wide state is touched. The
/// `tun` crate does the same for the IPv4 address (`sys.rs:82`), three lines
/// from the call this wraps.
fn unicast_row(if_index: u32, cidr: Ipv6Cidr) -> MIB_UNICASTIPADDRESS_ROW {
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    // SAFETY: `row` is a live, zeroed row of the right type.
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };

    row.InterfaceIndex = if_index;
    row.Address.si_family = AF_INET6;
    row.Address.Ipv6.sin6_family = AF_INET6;
    row.Address.Ipv6.sin6_addr.u.Byte = cidr.address().octets();
    row.OnLinkPrefixLength = cidr.prefix_len();
    row.ValidLifetime = u32::MAX;
    row.PreferredLifetime = u32::MAX;
    row.SkipAsSource = false;
    row.DadState = IpDadStatePreferred;
    // `InitializeUnicastIpAddressEntry` leaves both origins `Unchanged`; the
    // `tun` crate pins them to `Manual` for the IPv4 address.
    row.PrefixOrigin = IpPrefixOriginManual;
    row.SuffixOrigin = IpSuffixOriginManual;
    row
}

fn classify_create(status: WIN32_ERROR) -> CreateVerdict {
    match status {
        NO_ERROR | ERROR_OBJECT_ALREADY_EXISTS => CreateVerdict::Created,
        // Microsoft's code for "no IPv6 stack on the local computer and an
        // IPv6 address was specified".
        ERROR_NOT_SUPPORTED => CreateVerdict::StackAbsent,
        other => CreateVerdict::Failed(other),
    }
}

/// What the change callback needs: which interface to watch, and the one-shot
/// sender to fire.
struct WaitContext {
    luid: u64,
    sender: Mutex<Option<SyncSender<()>>>,
}

/// Owns the IP Helper registration and the boxed context behind it.
struct Registration {
    handle: HANDLE,
    context: *mut WaitContext,
}

impl Drop for Registration {
    fn drop(&mut self) {
        // Cancel while holding NO lock: `CancelMibChangeNotify2` blocks until
        // an in-flight callback returns, and Microsoft documents a deadlock if
        // the cancelling thread owns a resource that callback needs.
        // SAFETY: `handle` came from a successful `NotifyIpInterfaceChange`.
        let status = unsafe { CancelMibChangeNotify2(self.handle) };
        if status != NO_ERROR {
            // The callback can still fire and read the context, so leaking it
            // is the only sound option.
            warn!(
                code = status.0,
                "CancelMibChangeNotify2 failed; leaking the interface-change context"
            );
            return;
        }
        // SAFETY: the cancel above guarantees no callback can still read the
        // context, and it was created with `Box::into_raw`.
        drop(unsafe { Box::from_raw(self.context) });
    }
}

unsafe extern "system" fn on_interface_change(
    context: *const core::ffi::c_void,
    row: *const MIB_IPINTERFACE_ROW,
    notification_type: MIB_NOTIFICATION_TYPE,
) {
    if notification_type != MibAddInstance {
        return;
    }
    // An unwind across the FFI boundary is undefined behaviour.
    let _ = std::panic::catch_unwind(|| {
        // SAFETY: registered with a `Box::into_raw(WaitContext)` that
        // `Registration::drop` reclaims only after `CancelMibChangeNotify2`.
        let ctx = unsafe { &*context.cast::<WaitContext>() };
        // SAFETY: `Row` is NULL only for `MibInitialNotification`, filtered
        // above and never requested (`initialnotification = false`).
        let row = unsafe { &*row };
        // SAFETY: `NET_LUID_LH` is a union of two POD views of one u64.
        if unsafe { row.InterfaceLuid.Value } != ctx.luid || row.Family != AF_INET6 {
            return;
        }
        // `sync_channel(1)` + `take()`-once + `try_send`: the callback never
        // blocks. A parked callback would deadlock `CancelMibChangeNotify2`,
        // which waits for it.
        if let Some(tx) = ctx
            .sender
            .lock()
            .expect("interface-change sender mutex poisoned")
            .take()
        {
            let _ = tx.try_send(());
        }
    });
}

/// Block until the interface's IPv6 half exists, or the budget elapses.
///
/// Register **first**, check existence **second**. `MibInitialNotification`
/// confirms registration and carries a NULL row — it enumerates nothing — so
/// the explicit `GetIpInterfaceEntry` is what closes the race. An interface the
/// kernel published while `tun::Device::new` was waiting on its own AF_INET
/// half emits no later `MibAddInstance`, so a register-and-block with no
/// existence check would burn the whole budget and report a live IPv6 half as
/// absent.
fn wait_for_ipv6_interface(luid: u64, budget: Duration) -> Appearance {
    let (tx, rx) = sync_channel(1);
    let context = Box::into_raw(Box::new(WaitContext {
        luid,
        sender: Mutex::new(Some(tx)),
    }));
    let mut handle = HANDLE::default();
    // SAFETY: `context` is a live `Box::into_raw`, and `handle` is a live
    // out-parameter. `initialnotification = false` — see this fn's doc.
    let status = unsafe {
        NotifyIpInterfaceChange(
            AF_UNSPEC,
            Some(on_interface_change),
            Some(context.cast()),
            false,
            &mut handle,
        )
    };
    if status != NO_ERROR {
        // SAFETY: registration failed, so no callback exists to read it.
        drop(unsafe { Box::from_raw(context) });
        return Appearance::Failed(status);
    }
    let _registration = Registration { handle, context };

    match ip_interface_exists(luid) {
        Ok(true) => return Appearance::Appeared,
        Ok(false) => {}
        Err(code) => return Appearance::Failed(code),
    }

    match rx.recv_timeout(budget) {
        Ok(()) => Appearance::Appeared,
        Err(RecvTimeoutError::Timeout) => Appearance::NeverAppeared,
        // The sender lives inside `_registration`'s context, which outlives
        // this receive, and the callback drops it only after a successful
        // `try_send` — whose value is already queued.
        Err(RecvTimeoutError::Disconnected) => {
            unreachable!("the interface-change sender outlives this receive")
        }
    }
}

fn ip_interface_exists(luid: u64) -> Result<bool, WIN32_ERROR> {
    let mut row = MIB_IPINTERFACE_ROW {
        InterfaceLuid: NET_LUID_LH { Value: luid },
        Family: AF_INET6,
        ..Default::default()
    };
    // SAFETY: `row` is a live out-parameter with its lookup keys set.
    match unsafe { GetIpInterfaceEntry(&mut row) } {
        NO_ERROR => Ok(true),
        ERROR_NOT_FOUND => Ok(false),
        other => Err(other),
    }
}
