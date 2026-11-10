//! The rendezvous on an address's duplicate-address-detection (DAD) end: the OS announces it through
//! `NotifyUnicastIpAddressChange`, so a test waits on the announcement and never polls or sleeps.
//!
//! The callback's row carries only the address and interface; the authoritative state is read back
//! with [`dad_verdict`] after every notification.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;

use windows::Win32::Foundation::{ERROR_NOT_FOUND, HANDLE, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, GetUnicastIpAddressEntry, NotifyUnicastIpAddressChange, MIB_NOTIFICATION_TYPE,
    MIB_UNICASTIPADDRESS_ROW,
};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Networking::WinSock::{
    IpDadStateDeprecated, IpDadStateDuplicate, IpDadStateInvalid, IpDadStatePreferred, ADDRESS_FAMILY, AF_INET,
    AF_INET6, SOCKADDR_INET,
};

/// What the address's DAD state means for a waiter, read from the authoritative entry rather than from
/// the notification.
pub enum DadVerdict {
    /// Usable as a source address.
    Usable,
    /// DAD found another host holding the address.
    Duplicate,
    /// The stack rejected the address outright.
    Invalid,
    /// `GetUnicastIpAddressEntry` itself failed.
    QueryFailed(u32),
    /// DAD is still running, or the address is not registered yet. The only state worth waiting
    /// through: wait for the next notification.
    Pending,
}

/// Owns both the registration handle and the boxed [`Sender`] its context pointer targets, so one
/// `Drop` cancels the registration before the box releases, regardless of which order the two were
/// constructed in. Declaration order alone does not give this: a panic unwinding past both would drop
/// the sender (and free the box) FIRST, while the kernel-held registration still points into it, a
/// leak turned into a use-after-free. Bundling them means there is no order left to get wrong.
pub struct AddressChangeRegistration {
    notify: HANDLE,
    /// Never read after registration: kept alive only because `notify` holds a raw pointer into it
    /// until cancelled.
    _tx: Box<Sender<u32>>,
    /// Test-only observability: set once `Drop` confirms the cancel succeeded. A second real
    /// `CancelMibChangeNotify2` on an already-cancelled handle corrupts the heap, so `Drop`'s own
    /// confirmation is the only sound signal that the cancel ran.
    cancel_confirmed: Option<Arc<AtomicBool>>,
}

impl AddressChangeRegistration {
    /// Registers `tx` boxed, so its address is stable for the registration's context pointer, for
    /// changes to addresses of `family` (`AF_UNSPEC` for both).
    pub fn register(family: ADDRESS_FAMILY, tx: Sender<u32>) -> Self {
        Self::register_with(family, tx, None)
    }

    pub fn register_with(family: ADDRESS_FAMILY, tx: Sender<u32>, cancel_confirmed: Option<Arc<AtomicBool>>) -> Self {
        let tx = Box::new(tx);
        let mut notify = HANDLE::default();
        // SAFETY: the boxed `tx` outlives the registration (`Drop` cancels it before the box
        // releases), so the callback's context pointer stays valid throughout.
        let status = unsafe {
            NotifyUnicastIpAddressChange(
                family,
                Some(on_address_change),
                Some(&*tx as *const Sender<u32> as *const core::ffi::c_void),
                false,
                &mut notify,
            )
        };
        assert_eq!(status, NO_ERROR, "NotifyUnicastIpAddressChange failed: {status:?}");
        Self {
            notify,
            _tx: tx,
            cancel_confirmed,
        }
    }
}

impl Drop for AddressChangeRegistration {
    fn drop(&mut self) {
        // SAFETY: `self.notify` is the live handle `register_with`'s successful call produced.
        let cancelled = unsafe { CancelMibChangeNotify2(self.notify) };
        // Gated on `!panicking()`: a failed cancel during unwind must not itself panic, since a second
        // panic during unwind aborts the process and destroys the ORIGINAL failure message.
        if cancelled != NO_ERROR && !std::thread::panicking() {
            panic!("CancelMibChangeNotify2 failed: {cancelled:?}");
        }
        if cancelled == NO_ERROR {
            if let Some(flag) = &self.cancel_confirmed {
                flag.store(true, Ordering::SeqCst);
            }
        }
        // `_tx` (and the box `notify`'s context pointer named) drops only after this line.
    }
}

/// The notification callback.
///
/// **It must not read `DadState`.** The row handed to the callback "contains incomplete data ... only
/// enough information that an application can call `GetUnicastIpAddressEntry`": exactly `Address`,
/// `InterfaceLuid` and `InterfaceIndex`. Every other member is zero, and `IpDadStateInvalid` IS zero,
/// so reading it here reports a rejection on every notification.
///
/// So the callback forwards only the interface index and the waiter does the authoritative query.
/// Keeping it to a channel send also respects the rule that `CancelMibChangeNotify2` must never be
/// reached from the callback thread.
unsafe extern "system" fn on_address_change(
    context: *const core::ffi::c_void,
    row: *const MIB_UNICASTIPADDRESS_ROW,
    _kind: MIB_NOTIFICATION_TYPE,
) {
    if context.is_null() || row.is_null() {
        return;
    }
    // SAFETY: `context` is the boxed `Sender` passed to `NotifyUnicastIpAddressChange`, kept alive
    // until after `CancelMibChangeNotify2`. `row` is kernel-owned and valid for the duration of the
    // callback; `InterfaceIndex` is one of the three members the API documents as populated.
    let tx = unsafe { &*(context as *const Sender<u32>) };
    let index = unsafe { (*row).InterfaceIndex };
    let _ = tx.send(index);
}

/// Ask for the COMPLETE entry for `addr` on the interface, which is the only place `DadState` is real.
pub fn dad_verdict(luid: NET_LUID_LH, index: u32, addr: IpAddr) -> DadVerdict {
    let mut row = MIB_UNICASTIPADDRESS_ROW {
        Address: sockaddr_inet(addr),
        InterfaceLuid: luid,
        InterfaceIndex: index,
        ..Default::default()
    };
    // SAFETY: `row` is an owned local seeded with the three members `GetUnicastIpAddressEntry`
    // requires as input.
    let status = unsafe { GetUnicastIpAddressEntry(&mut row) };
    if status == ERROR_NOT_FOUND {
        // The address has not been registered yet: the creation notification can arrive first.
        return DadVerdict::Pending;
    }
    if status != NO_ERROR {
        return DadVerdict::QueryFailed(status.0);
    }
    match row.DadState {
        s if s == IpDadStatePreferred || s == IpDadStateDeprecated => DadVerdict::Usable,
        s if s == IpDadStateDuplicate => DadVerdict::Duplicate,
        s if s == IpDadStateInvalid => DadVerdict::Invalid,
        // Tentative: the documented transient.
        _ => DadVerdict::Pending,
    }
}

fn sockaddr_inet(addr: IpAddr) -> SOCKADDR_INET {
    let mut sa = SOCKADDR_INET::default();
    match addr {
        IpAddr::V4(v4) => {
            sa.Ipv4.sin_family = AF_INET;
            sa.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.octets());
        }
        IpAddr::V6(v6) => {
            sa.Ipv6.sin6_family = AF_INET6;
            sa.Ipv6.sin6_addr.u.Byte = v6.octets();
        }
    }
    sa
}
