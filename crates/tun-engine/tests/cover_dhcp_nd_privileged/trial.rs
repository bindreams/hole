//! One measurement: the event with no cover, then the same event under a real cover, then the verdict.

use std::net::IpAddr;
use std::path::Path;

use tun_engine::routing::failclosed::{self, Cover, CoverLock, SystemLuidResolver};
use tun_engine::test_utils::{EscapeGuard, RecordSpec};

use crate::platform;

/// Routable: the covers permit one server address and this is it. The macOS DHCP reading makes one TCP
/// connection to its port 443, the one flow both covers let out, and closes it.
pub const SERVER_IP: &str = "1.1.1.1";

/// The interface the standing cover's tunnel permit names. It need not exist: the permit only has to
/// resolve (Windows: any live alias) or never match (macOS), and neither is under test.
const TUN_NAME: &str = if cfg!(target_os = "windows") {
    "Loopback Pseudo-Interface 1"
} else {
    "utun-absent"
};

const ESCAPE: RecordSpec = RecordSpec {
    file_name: "hole-1075-cover-dhcp-nd-recovery.txt",
    what: "#1075 DHCP / neighbor-discovery measurement",
};

#[derive(Debug, Clone, Copy)]
pub enum CoverKind {
    Transient,
    Standing,
}

#[derive(Debug, Clone, Copy)]
pub enum Probe {
    DhcpRenewal,
    NeighborDiscovery,
}

/// What one forced event did, as the platform observed it.
pub enum Reading {
    /// The event happened, and this is the evidence.
    Worked(String),
    /// The apparatus watched and the event did not happen.
    Failed(String),
    /// The apparatus could not tell.
    Unmeasurable(String),
}

impl std::fmt::Display for Reading {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Reading::Worked(why) => write!(f, "worked ({why})"),
            Reading::Failed(why) => write!(f, "did not happen ({why})"),
            Reading::Unmeasurable(why) => write!(f, "unmeasurable ({why})"),
        }
    }
}

/// Engage `kind` for real into `state_dir`. The only place this file names the cover API.
fn engage(kind: CoverKind, state_dir: &Path) -> Cover {
    let server: IpAddr = SERVER_IP.parse().unwrap();
    // The lock is held for the engage only; the returned guard takes it again when it drops.
    let lock = CoverLock::acquire(state_dir);
    match kind {
        CoverKind::Transient => failclosed::engage(&lock, server, None, None),
        CoverKind::Standing => failclosed::engage_lockdown(&lock, server, TUN_NAME, &SystemLuidResolver, &[], None),
    }
    .unwrap_or_else(|e| panic!("HARNESS: engage the {kind:?} cover: {e}"))
}

pub fn run(kind: CoverKind, probe: Probe) {
    // The escape (record + release on every unwind) exists before the first engage.
    let escape = EscapeGuard::with_temp_dir(&ESCAPE);
    let nic = platform::default_nic().unwrap_or_else(|e| panic!("COULD NOT MEASURE: no egress NIC to measure on: {e}"));
    let measure = |covered: bool| match probe {
        #[cfg(target_os = "windows")]
        Probe::DhcpRenewal => nic.dhcp_renewal(),
        #[cfg(target_os = "macos")]
        Probe::DhcpRenewal => nic.dhcp_renewal(covered),
        Probe::NeighborDiscovery => nic.neighbor_discovery(covered),
    };

    let control = measure(false);
    // The covered reading is taken inside the window and judged after the cover is gone, so a failed
    // reading can never skip the release.
    let covered = match control {
        Reading::Worked(_) => {
            let cover = engage(kind, escape.state_dir());
            let reading = measure(true);
            drop(cover);
            Some(reading)
        }
        Reading::Failed(_) | Reading::Unmeasurable(_) => None,
    };

    eprintln!(
        "MEASUREMENT #1075 | {} | cover={kind:?} | event={probe:?} | control: {control} | covered: {}",
        std::env::consts::OS,
        covered.as_ref().map_or("not run".to_string(), |r| r.to_string()),
    );
    match (control, covered) {
        (Reading::Worked(_), Some(Reading::Worked(_))) => {}
        (Reading::Worked(_), Some(Reading::Failed(why))) => panic!(
            "DEFECT (#1075): the {kind:?} cover drops {probe:?}. It worked with no cover and not under it: {why}. \
             Add the wireguard-windows permits (DHCPv4 68 to 67, DHCPv6, ICMPv6 RS/RA/NS/NA) and fix the windows.rs doc."
        ),
        (Reading::Worked(_), Some(Reading::Unmeasurable(why))) => {
            panic!("COULD NOT MEASURE (#1075): {kind:?} cover, {probe:?}, under the cover: {why}")
        }
        (Reading::Worked(_), None) => unreachable!("a working control always runs the covered half"),
        (Reading::Failed(why) | Reading::Unmeasurable(why), _) => panic!(
            "COULD NOT MEASURE (#1075): {kind:?} cover, {probe:?}: the event did not work or could not be observed with \
             no cover, so a covered reading would mean nothing: {why}"
        ),
    }
}

/// An address no earlier call used: this process's id and a counter under a fixed ULA global ID.
pub fn fresh_address() -> std::net::Ipv6Addr {
    use std::sync::atomic::{AtomicU16, Ordering};
    static COUNTER: AtomicU16 = AtomicU16::new(1);
    let pid = (std::process::id() & 0xffff) as u16;
    std::net::Ipv6Addr::new(
        0xfd48,
        0x6f6c,
        0x6531,
        pid,
        0,
        0,
        0,
        COUNTER.fetch_add(1, Ordering::Relaxed),
    )
}
