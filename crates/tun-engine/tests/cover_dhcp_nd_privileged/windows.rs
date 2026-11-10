//! Windows apparatus for the #1075 measurement: `ipconfig /renew` for DHCP, a `pktmon` capture of
//! the NIC for the neighbor solicitation DAD sends.

use std::net::{Ipv6Addr, UdpSocket};
use std::process::Command;
use std::sync::mpsc::channel;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tun_engine::test_utils::dad::{dad_verdict, AddressChangeRegistration, DadVerdict};
use tun_engine::test_utils::{
    capture_contains_nonce, classify_send, describe_output, nonce, pktmon_checked, ps_capture,
    stop_reports_no_events_lost, PktmonGuard, SendFate,
};
use windows::Win32::Foundation::NO_ERROR;
use windows::Win32::NetworkManagement::IpHelper::ConvertInterfaceIndexToLuid;
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Networking::WinSock::AF_INET6;

use crate::trial::{fresh_address, Reading};

/// The egress NIC: what the default route leaves by.
pub struct Nic {
    index: u32,
    luid: NET_LUID_LH,
    name: String,
}

pub fn default_nic() -> Result<Nic, String> {
    let gw = tun_engine::gateway::get_default_gateway_info().map_err(|e| format!("{e}"))?;
    let mut luid = NET_LUID_LH::default();
    // SAFETY: writes an owned local.
    let status = unsafe { ConvertInterfaceIndexToLuid(gw.interface_index, &mut luid) };
    if status != NO_ERROR {
        return Err(format!(
            "ConvertInterfaceIndexToLuid({}) failed: {status:?}",
            gw.interface_index
        ));
    }
    Ok(Nic {
        index: gw.interface_index,
        luid,
        name: gw.interface_name,
    })
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs()
}

/// Send a datagram carrying a fresh nonce to a destination neither cover permits. Returns the nonce.
/// A WFP block at `ALE_AUTH_CONNECT` shows up as `Rejected` (`WSAEACCES`) or as an accepted send that
/// goes nowhere; both are a dropped datagram, anything else is a fault of the send.
fn calibration_send() -> Result<[u8; 16], String> {
    let marker = nonce();
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("bind: {e}"))?;
    let sent = socket.send_to(&marker, "8.8.8.8:40053");
    match classify_send(&sent) {
        SendFate::Accepted | SendFate::Rejected(_) => Ok(marker),
        fate @ SendFate::NeverLeft(_) => Err(format!("{fate:?}: {sent:?}")),
    }
}

impl Nic {
    /// The lease's start in Unix seconds, as the adapter configuration reports it (it has one-second
    /// resolution). `None` when the NIC holds no lease.
    fn lease_obtained(&self) -> Result<Option<u64>, String> {
        let text = ps_capture(&format!(
            "$c = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'InterfaceIndex={}'; \
             if ($c.DHCPLeaseObtained) {{ ([DateTimeOffset]$c.DHCPLeaseObtained).ToUnixTimeSeconds() }}",
            self.index
        ))?;
        if text.is_empty() {
            return Ok(None);
        }
        text.parse().map(Some).map_err(|e| format!("lease time {text:?}: {e}"))
    }

    /// Force a renewal and read whether the lease moved. `ipconfig /renew` returns when the DHCP
    /// client has its own answer, so there is nothing to wait on after it. Its exit status says nothing:
    /// measured on the runner, a renewal that timed out ("unable to contact your DHCP server") exits 0. So
    /// the lease alone decides, and a renewal that left it unmoved is read as the cover's only because the
    /// control run, with the same adapter and command, just moved it: a cause that is not the network
    /// would have failed it too.
    ///
    /// The lease time has one-second resolution, so it can show a renewal only if the renewal starts
    /// in a later second than the lease it replaces: the reading waits for the clock to pass the
    /// current lease's second, then asks whether the lease now dates from the renewal's second on.
    pub fn dhcp_renewal(&self) -> Reading {
        let before = match self.lease_obtained() {
            Ok(Some(s)) => s,
            Ok(None) => return Reading::Unmeasurable(format!("{:?} holds no DHCP lease", self.name)),
            Err(e) => return Reading::Unmeasurable(format!("reading the lease before the renewal: {e}")),
        };
        // The wait re-checks the clock itself, the one fact it needs.
        let started = loop {
            let now = unix_seconds();
            if now > before {
                break now;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let renew = match Command::new("ipconfig").args(["/renew", &self.name]).output() {
            Ok(out) => describe_output(&out),
            Err(e) => return Reading::Unmeasurable(format!("spawn ipconfig: {e}")),
        };
        let after = match self.lease_obtained() {
            Ok(Some(s)) => s,
            Ok(None) => {
                return Reading::Unmeasurable(format!("the lease vanished after the renewal; ipconfig: {renew}"))
            }
            Err(e) => return Reading::Unmeasurable(format!("reading the lease after the renewal: {e}")),
        };
        if after >= started {
            Reading::Worked(format!("lease obtained at {after}, the renewal began at {started}"))
        } else if after == before {
            Reading::Failed(format!("lease obtained stayed {before}; ipconfig: {renew}"))
        } else {
            Reading::Unmeasurable(format!(
                "the lease moved from {before} to {after}, before the renewal began at {started}; ipconfig: {renew}"
            ))
        }
    }

    /// Add a throwaway ULA address to the NIC, wait for DAD to end, and read a capture of every NIC
    /// component for the solicitation DAD sends for it. Under a cover, the same capture also gets a
    /// datagram WFP drops: if the capture shows it, it records packets WFP dropped and cannot tell a
    /// dropped solicitation from a sent one.
    pub fn neighbor_discovery(&self, covered: bool) -> Reading {
        let dir = match tempfile::tempdir() {
            Ok(d) => d,
            Err(e) => return Reading::Unmeasurable(format!("temp dir: {e}")),
        };
        let etl = dir.path().join("nd.etl");
        let pcap = dir.path().join("nd.pcapng");
        let addr = fresh_address();

        // Registered before the address exists, so the end of its DAD cannot be missed.
        let (tx, rx) = channel::<u32>();
        let _registration = AddressChangeRegistration::register(AF_INET6, tx);

        // No filter: the 16 octets of the address, unique to this call, are the match.
        let started = pktmon_checked(&["filter", "remove"]).and_then(|_| {
            pktmon_checked(&[
                "start",
                "--capture",
                "--comp",
                "nics",
                "--pkt-size",
                "0",
                "--file-name",
                &etl.to_string_lossy(),
            ])
        });
        let _guard = PktmonGuard;
        if let Err(e) = started {
            return Reading::Unmeasurable(format!("starting the capture: {e}"));
        }

        let calibration = covered.then(calibration_send);
        let added = self.add_address(addr).and_then(|()| self.wait_for_dad(addr, &rx));
        let removed = self.remove_address(addr);
        let stopped = pktmon_checked(&["stop"]).and_then(|out| {
            if !stop_reports_no_events_lost(&out) {
                return Err(format!(
                    "the capture lost events: {}",
                    String::from_utf8_lossy(&out.stdout)
                ));
            }
            pktmon_checked(&["etl2pcap", &etl.to_string_lossy(), "--out", &pcap.to_string_lossy()])
        });
        if let Err(e) = added {
            return Reading::Unmeasurable(format!("DAD for {addr} did not run to an end: {e}"));
        }
        if let Err(e) = stopped {
            return Reading::Unmeasurable(format!("stopping the capture: {e}"));
        }
        if let Some(calibration) = calibration {
            match calibration {
                Err(e) => return Reading::Unmeasurable(format!("the calibration datagram was not sent: {e}")),
                Ok(marker) if capture_contains_nonce(&pcap, marker) => return Reading::Unmeasurable(
                    "the capture shows a datagram WFP drops, so it cannot tell a dropped solicitation from a sent one"
                        .into(),
                ),
                Ok(_) => {}
            }
        }
        // A leftover address is harmless (each call uses its own), so a failed removal is reported, not fatal.
        let note = removed
            .err()
            .map(|e| format!("; removing {addr}: {e}"))
            .unwrap_or_default();

        if capture_contains_nonce(&pcap, addr.octets()) {
            Reading::Worked(format!("the solicitation for {addr} reached the NIC{note}"))
        } else {
            Reading::Failed(format!(
                "no solicitation for {addr} in a capture that lost no events, though DAD ran to its end{note}"
            ))
        }
    }

    fn add_address(&self, addr: Ipv6Addr) -> Result<(), String> {
        ps_capture(&format!(
            "New-NetIPAddress -InterfaceIndex {} -AddressFamily IPv6 -IPAddress '{addr}' -PrefixLength 64 \
             -PolicyStore ActiveStore -ErrorAction Stop | Out-Null",
            self.index
        ))
        .map(drop)
    }

    fn remove_address(&self, addr: Ipv6Addr) -> Result<(), String> {
        ps_capture(&format!(
            "Remove-NetIPAddress -InterfaceIndex {} -IPAddress '{addr}' -Confirm:$false -ErrorAction Stop",
            self.index
        ))
        .map(drop)
    }

    /// Wait for the OS to announce an end of DAD for `addr`: `Preferred` is the normal end; every other
    /// terminal state (a duplicate, an invalid address) is an error. DAD always ends, so there is no cap.
    fn wait_for_dad(&self, addr: Ipv6Addr, announcements: &std::sync::mpsc::Receiver<u32>) -> Result<(), String> {
        loop {
            match dad_verdict(self.luid, self.index, addr.into()) {
                DadVerdict::Usable => return Ok(()),
                DadVerdict::Duplicate => return Err("DAD reported a duplicate".into()),
                DadVerdict::Invalid => return Err("the stack rejected the address".into()),
                DadVerdict::QueryFailed(code) => return Err(format!("GetUnicastIpAddressEntry failed: {code}")),
                DadVerdict::Pending => {}
            }
            announcements
                .recv()
                .map_err(|_| "the address-change registration closed".to_string())?;
        }
    }
}
