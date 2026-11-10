//! macOS apparatus for the #1075 measurement: a `tcpdump` of the NIC for both events. DHCP: the T1 unicast
//! renewal the test sends itself, read off the wire (outbound only, see [`Nic::dhcp_renewal`]). ND: the neighbor
//! solicitation DAD sends. Plus a record of the IPv6 neighbor and router tables around the ND measurement.

use std::ffi::CString;
use std::io::{BufRead, BufReader, ErrorKind, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, TcpStream, UdpSocket};
use std::process::{Child, ChildStderr, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::thread::JoinHandle;
use std::time::Duration;

use socket2::{Domain, Socket, Type};
use tun_engine::test_utils::{classify_send, describe_output, SendFate};

use crate::trial::{fresh_address, Reading, SERVER_IP};

/// Destinations pf drops under either cover (`block out all`); their only use is to learn whether the NIC
/// capture sees packets pf drops. One per address family, since pf hooks each family separately.
const CALIBRATION_PORT: u16 = 40053;
const CALIBRATION_IP_V4: &str = "8.8.8.8";
/// Link-scoped all-nodes: it needs no neighbor resolution, so nothing but pf can stop it before the tap.
const CALIBRATION_IP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

const DHCP_CLIENT_PORT: u16 = 68;
const DHCP_SERVER_PORT: u16 = 67;
/// Both covers permit TCP to the server address on this port.
const ORDERING_PROBE_PORT: u16 = 443;

/// The egress NIC: what the default route leaves by.
pub struct Nic {
    name: String,
}

pub fn default_nic() -> Result<Nic, String> {
    let gw = tun_engine::gateway::get_default_gateway_info().map_err(|e| format!("{e}"))?;
    Ok(Nic {
        name: gw.interface_name,
    })
}

fn run(program: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("spawn {program}: {e}"))?;
    if !out.status.success() {
        return Err(format!("{program} {args:?}: {}", describe_output(&out)));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

// The NIC capture =====================================================================================================

/// A `tcpdump` of one NIC whose text lines are read as they arrive.
struct Tap {
    child: Child,
    stderr: BufReader<ChildStderr>,
    lines: Receiver<String>,
    reader: Option<JoinHandle<()>>,
    /// Every line received so far.
    seen: Vec<String>,
}

/// What a stopped capture holds.
struct Capture {
    text: String,
    /// `tcpdump`'s packet counts, printed to stderr when it exits.
    summary: String,
}

impl Tap {
    /// Start capturing `filter` on `nic`; returns once `tcpdump` reports its tap open, since a packet
    /// sent before that could be missed.
    fn start(nic: &str, filter: &str) -> Result<Tap, String> {
        let mut child = Command::new("tcpdump")
            .args(["-n", "-l", "--immediate-mode", "-i", nic, filter])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn tcpdump: {e}"))?;
        let stderr = BufReader::new(child.stderr.take().expect("piped"));
        let stdout = child.stdout.take().expect("piped");
        let (tx, lines) = channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let mut tap = Tap {
            child,
            stderr,
            lines,
            reader: Some(reader),
            seen: Vec::new(),
        };
        let mut announced = String::new();
        loop {
            let mut line = String::new();
            match tap.stderr.read_line(&mut line) {
                Ok(0) | Err(_) => {
                    let capture = tap.finish();
                    return Err(format!(
                        "tcpdump never reported listening: {announced:?} {:?}",
                        capture.summary
                    ));
                }
                Ok(_) => {
                    announced.push_str(&line);
                    if line.contains("listening on") {
                        return Ok(tap);
                    }
                }
            }
        }
    }

    /// The first captured line `matches` accepts.
    fn find(&self, matches: impl Fn(&str) -> bool) -> Option<&str> {
        self.seen.iter().map(String::as_str).find(|l| matches(l))
    }

    /// Wait until a captured line satisfies `matches`. The caller guarantees such a packet is on its way (it
    /// has seen the host receive it), so there is no bound; an error means the capture ended first.
    fn wait_for(&mut self, matches: impl Fn(&str) -> bool) -> Result<(), String> {
        if self.find(&matches).is_some() {
            return Ok(());
        }
        loop {
            let line = self
                .lines
                .recv()
                .map_err(|_| "tcpdump ended before the packet was seen".to_string())?;
            let hit = matches(&line);
            self.seen.push(line);
            if hit {
                return Ok(());
            }
        }
    }

    /// Take in every line already delivered.
    fn drain(&mut self) {
        self.seen.extend(self.lines.try_iter());
    }

    /// Stop the capture and collect what it saw and counted. Safe to call again and from `Drop`.
    fn finish(&mut self) -> Capture {
        // SIGINT makes tcpdump print its packet counts and exit.
        let _ = Command::new("kill")
            .args(["-INT", &self.child.id().to_string()])
            .status();
        let _ = self.child.wait();
        self.seen.extend(self.lines.try_iter());
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        self.seen.extend(self.lines.try_iter());
        let mut summary = String::new();
        let _ = self.stderr.read_to_string(&mut summary);
        Capture {
            text: self.seen.join("\n"),
            summary,
        }
    }
}

impl Drop for Tap {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Why `capture` cannot be trusted, if it cannot.
///
/// A packet the kernel buffer overflowed on is one the capture never saw. "Received by filter"
/// counts every packet the tap saw, matching or not, so it is not comparable to the packets captured.
/// And on a covered run the capture must not show the calibration datagram pf is known to drop: if it
/// does, the tap sits upstream of pf, so a captured packet may be one pf then dropped and an absent one
/// proves nothing.
fn untrusted(capture: &Capture, calibration: Option<Result<Calibration, String>>) -> Option<String> {
    if count_before(&capture.summary, "packets dropped by kernel") != Some(0) {
        return Some(format!(
            "tcpdump did not report zero kernel drops: {:?}",
            capture.summary
        ));
    }
    match calibration? {
        Err(e) => Some(format!("the calibration datagram was not sent: {e}")),
        Ok(calibration) if capture.text.contains(&calibration.on_the_wire) => Some(
            "the capture shows a datagram pf drops, so it taps upstream of pf and cannot tell a dropped packet from a \
             sent one"
                .into(),
        ),
        Ok(_) => None,
    }
}

/// The address family of the event under measurement, and so of its calibration datagram: pf hooks each
/// family separately.
#[derive(Clone, Copy)]
enum Family {
    V4,
    V6,
}

/// A calibration datagram that was sent.
struct Calibration {
    /// How `tcpdump -n` prints its destination.
    on_the_wire: String,
}

/// Send a datagram both covers' pf rulesets drop (`block out all`, no permit for this address), in `family`.
///
/// pf's drop of an outbound datagram is silent to the sender: the send is `Accepted`. Measured on the
/// runner: both covers' ND runs sent the IPv4 datagram, got `Accepted`, and the capture did not show it.
/// Any other fate is a fault of the send, so the reading is unmeasurable, never a verdict.
fn calibration_send(family: Family, nic: &str) -> Result<Calibration, String> {
    let payload = b"hole-1075-calibration";
    let (sent, on_the_wire) = match family {
        Family::V4 => {
            let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("bind: {e}"))?;
            (
                socket.send_to(payload, (CALIBRATION_IP_V4, CALIBRATION_PORT)),
                format!("{CALIBRATION_IP_V4}.{CALIBRATION_PORT}"),
            )
        }
        Family::V6 => {
            let name = CString::new(nic).map_err(|e| format!("NIC name {nic:?}: {e}"))?;
            // SAFETY: `name` is a NUL-terminated string that outlives the call.
            let scope = unsafe { libc::if_nametoindex(name.as_ptr()) };
            if scope == 0 {
                return Err(format!("if_nametoindex({nic:?}): {}", std::io::Error::last_os_error()));
            }
            let socket = UdpSocket::bind("[::]:0").map_err(|e| format!("bind: {e}"))?;
            (
                socket.send_to(
                    payload,
                    SocketAddrV6::new(CALIBRATION_IP_V6, CALIBRATION_PORT, 0, scope),
                ),
                format!("{CALIBRATION_IP_V6}.{CALIBRATION_PORT}"),
            )
        }
    };
    match classify_send(&sent) {
        SendFate::Accepted => Ok(Calibration { on_the_wire }),
        fate => Err(format!("{fate:?}: {sent:?}")),
    }
}

/// The number on the line of `tcpdump`'s summary that ends in `suffix`.
fn count_before(summary: &str, suffix: &str) -> Option<u64> {
    summary
        .lines()
        .find_map(|l| l.trim().strip_suffix(suffix)?.trim().parse().ok())
}

// DHCP renewal ========================================================================================================

/// What the NIC's DHCP client holds, which a renewal request has to name.
struct Lease {
    client: Ipv4Addr,
    server: Ipv4Addr,
    mac: [u8; 6],
}

/// What the wire showed of one renewal request whose send was accepted.
enum Renewal {
    /// The request was captured leaving the NIC.
    Left(String),
    /// The ordering probe was captured and the request was not.
    NeverLeft,
}

impl Nic {
    fn lease(&self) -> Result<Lease, String> {
        let client = run("ipconfig", &["getifaddr", &self.name])?;
        let server = run("ipconfig", &["getoption", &self.name, "server_identifier"])?;
        let link = run("ifconfig", &[&self.name])?;
        let mac = link
            .lines()
            .find_map(|l| l.trim().strip_prefix("ether "))
            .ok_or_else(|| format!("no ether line in `ifconfig {}`: {link:?}", self.name))?;
        Ok(Lease {
            client: client
                .trim()
                .parse()
                .map_err(|e| format!("lease address {client:?}: {e}"))?,
            server: server
                .trim()
                .parse()
                .map_err(|e| format!("DHCP server {server:?}: {e}"))?,
            mac: parse_mac(mac.trim())?,
        })
    }

    /// The T1 renewal the DHCP client sends in its BOUND state: a unicast DHCPREQUEST from the leased
    /// address, port 68, to the server that granted it. `ipconfig set <nic> DHCP` is not that: it
    /// restarts the client (INIT-REBOOT, sent through BPF, which pf does not see) and drops the lease
    /// while it runs.
    ///
    /// The reading is outbound only: does the request leave the NIC under the cover. The reply is not
    /// waited for. The runner's DHCP server draws no reply to a crafted renewal (measured: none in 60 s
    /// with no cover engaged), and neither cover's ruleset has a `block in`, so no cover can drop a reply.
    ///
    /// The wire decides, through a `tcpdump` filtered to this request's transaction id (pf's outbound drop
    /// is silent to the sender, see [`calibration_send`]):
    /// - the request captured is "worked";
    /// - the request not captured although the ordering probe was is "did not happen".
    ///
    /// The ordering probe is a TCP connection to the address both covers permit. One NIC's output is FIFO,
    /// so once the probe's SYN is captured the request, sent first, had its chance, provided the request
    /// was not held behind a neighbor lookup the SYN skipped: on a covered run the reading first requires
    /// the server's link-layer address to be resolved already.
    pub fn dhcp_renewal(&self, covered: bool) -> Reading {
        let lease = match self.lease() {
            Ok(l) => l,
            Err(e) => return Reading::Unmeasurable(format!("{:?} has no DHCP lease to renew: {e}", self.name)),
        };
        if covered {
            if let Err(e) = self.server_resolved(&lease) {
                return Reading::Unmeasurable(e);
            }
        }
        let xid = random_u32();
        let filter = format!(
            "(udp and udp[12:4] = {xid:#010x}) or (tcp and host {SERVER_IP} and port {ORDERING_PROBE_PORT}) \
             or udp port {CALIBRATION_PORT}"
        );
        let mut tap = match Tap::start(&self.name, &filter) {
            Ok(t) => t,
            Err(e) => return Reading::Unmeasurable(e),
        };
        let calibration = covered.then(|| calibration_send(Family::V4, &self.name));
        let renewal = renew(&mut tap, &lease, xid);
        let capture = tap.finish();
        match (renewal, untrusted(&capture, calibration)) {
            (Err(e), _) => Reading::Unmeasurable(e),
            (Ok(_), Some(why)) => Reading::Unmeasurable(why),
            (Ok(Renewal::Left(line)), None) => Reading::Worked(format!("the DHCPREQUEST left the NIC: {line}")),
            (Ok(Renewal::NeverLeft), None) => Reading::Failed(format!(
                "the send was accepted and the ordering probe was captured, but no DHCPREQUEST with xid {xid:#x} left \
                 the NIC; capture: {:?}",
                capture.text
            )),
        }
    }

    /// Whether the neighbor table already holds a resolved entry for the DHCP server, so a request to it
    /// is not held behind a lookup. `arp -n` prints `? (ip) at aa:bb:... on enN ...`, or `(incomplete)`.
    fn server_resolved(&self, lease: &Lease) -> Result<(), String> {
        let entry = run("arp", &["-n", &lease.server.to_string()])?;
        if entry.contains(" at ") && !entry.contains("incomplete") {
            return Ok(());
        }
        Err(format!(
            "the DHCP server's link-layer address is not resolved, so the request could be held behind a lookup the \
             ordering probe skips: {entry:?}"
        ))
    }

    /// Every NIC's IPv6 neighbor cache and default-router list. Record-only: a read that fails is
    /// text, not an error.
    pub fn nd_state(&self) -> String {
        let read = |args: &[&str]| run("ndp", args).unwrap_or_else(|e| format!("<unreadable: {e}>"));
        format!(
            "-- neighbors (ndp -an)
{}
-- routers (ndp -rn)
{}",
            read(&["-an"]),
            read(&["-rn"])
        )
    }

    /// Add a throwaway ULA address to the NIC while `tcpdump` watches it, wait for DAD to end, and
    /// read the capture for the solicitation DAD sends for it. Under a cover, also learn whether the
    /// capture sees a datagram pf drops: if it does, the capture cannot tell a sent solicitation
    /// from a dropped one.
    pub fn neighbor_discovery(&self, covered: bool) -> Reading {
        let addr = fresh_address();
        let mut tap = match Tap::start(&self.name, &format!("icmp6 or udp port {CALIBRATION_PORT}")) {
            Ok(t) => t,
            Err(e) => return Reading::Unmeasurable(e),
        };
        let calibration = covered.then(|| calibration_send(Family::V6, &self.name));
        let dad = self.add_address(addr).and_then(|()| self.wait_for_dad(addr));
        let removed = self.remove_address(addr);
        let capture = tap.finish();

        if let Err(e) = dad {
            return Reading::Unmeasurable(format!("DAD for {addr} did not run to an end: {e}"));
        }
        let note = removed
            .err()
            .map(|e| format!("; removing {addr}: {e}"))
            .unwrap_or_default();
        if let Some(why) = untrusted(&capture, calibration) {
            return Reading::Unmeasurable(why);
        }
        let target = addr.to_string();
        if capture
            .text
            .lines()
            .any(|l| l.contains("neighbor sol") && l.contains(&target))
        {
            Reading::Worked(format!("the solicitation for {addr} reached the NIC{note}"))
        } else {
            Reading::Failed(format!(
                "no solicitation for {addr} in the capture, though DAD ran to its end{note}; capture: {:?}",
                capture.text
            ))
        }
    }

    fn add_address(&self, addr: Ipv6Addr) -> Result<(), String> {
        run(
            "ifconfig",
            &[&self.name, "inet6", &addr.to_string(), "prefixlen", "64", "alias"],
        )
        .map(drop)
    }

    fn remove_address(&self, addr: Ipv6Addr) -> Result<(), String> {
        run("ifconfig", &[&self.name, "inet6", &addr.to_string(), "-alias"]).map(drop)
    }

    /// Wait until DAD for `addr` has run to an end: the address is listed without `tentative`.
    /// A duplicate is an error, an absent address is an error. DAD always ends, so there is no cap.
    fn wait_for_dad(&self, addr: Ipv6Addr) -> Result<(), String> {
        let target = addr.to_string();
        loop {
            let listing = run("ifconfig", &[&self.name, "inet6"])?;
            let Some(line) = listing
                .lines()
                .find(|l| l.split_whitespace().nth(1) == Some(target.as_str()))
            else {
                return Err(format!("{target} is not listed on {}: {listing:?}", self.name));
            };
            if line.contains("duplicated") {
                return Err(format!("duplicate address: {line:?}"));
            }
            if !line.contains("tentative") {
                return Ok(());
            }
            // Paced re-check: the OS announces no end of DAD to a script, and every return re-reads the state.
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

/// Send the renewal request, then connect to the permitted server address as the ordering probe, and read
/// what the capture shows. An `Err` is a fault of the apparatus, not a reading.
fn renew(tap: &mut Tap, lease: &Lease, xid: u32) -> Result<Renewal, String> {
    // The DHCP client's own socket holds port 68; a request from any other port would not be the
    // client's renewal (a cover may permit exactly 68 to 67). Both reuse options, so the bind can share.
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, None).map_err(|e| format!("create the request socket: {e}"))?;
    socket
        .set_reuse_address(true)
        .and_then(|()| socket.set_reuse_port(true))
        .map_err(|e| format!("set the request socket's reuse options: {e}"))?;
    let client = SocketAddr::new(IpAddr::V4(lease.client), DHCP_CLIENT_PORT);
    socket
        .bind(&client.into())
        .map_err(|e| format!("bind {client} beside the DHCP client's own socket: {e}"))?;

    let server = SocketAddr::new(IpAddr::V4(lease.server), DHCP_SERVER_PORT);
    let sent = socket.send_to(&renewal_request(lease, xid), &server.into());
    match (classify_send(&sent), &sent) {
        (SendFate::Accepted, _) => {}
        (fate, sent) => {
            return Err(format!(
                "the DHCPREQUEST send to {server} was not accepted ({fate:?}): {sent:?}"
            ))
        }
    }

    // The probe's own outcome ends the wait. An answer (the server's SYN-ACK or RST) was received by the
    // host, so the tap has it and prints it after the SYN: waiting for that line needs no bound. Any
    // other outcome means no answer is coming; the SYN is then either already printed or never left.
    let probe = ordering_probe();
    match &probe {
        ProbeOutcome::Answered => tap.wait_for(is_probe_answer)?,
        ProbeOutcome::Unanswered(_) => tap.drain(),
    }
    if tap.find(is_probe_syn).is_none() {
        return Err(match probe {
            ProbeOutcome::Answered => "the ordering probe was answered but its SYN was not captured".into(),
            ProbeOutcome::Unanswered(why) => format!("{why}; its SYN was not captured, so nothing orders the request"),
        });
    }
    Ok(match tap.find(is_dhcp_request) {
        Some(line) => Renewal::Left(line.to_owned()),
        None => Renewal::NeverLeft,
    })
}

/// How the ordering probe's connection ended.
enum ProbeOutcome {
    /// The server answered: a connection, or a refusal.
    Answered,
    /// Neither; the error says why.
    Unanswered(String),
}

/// One TCP connection to the server address, which both covers permit. The kernel decides when it ends
/// (connected, refused, or its own connect timeout), so no bound is chosen here.
fn ordering_probe() -> ProbeOutcome {
    match TcpStream::connect((SERVER_IP, ORDERING_PROBE_PORT)) {
        Ok(_) => ProbeOutcome::Answered,
        Err(e) if e.kind() == ErrorKind::ConnectionRefused => ProbeOutcome::Answered,
        Err(e) => ProbeOutcome::Unanswered(format!("the ordering probe to {SERVER_IP}:{ORDERING_PROBE_PORT}: {e}")),
    }
}

/// The probe's SYN: from us to the server's port.
fn is_probe_syn(line: &str) -> bool {
    line.contains(&format!("> {SERVER_IP}.{ORDERING_PROBE_PORT}:"))
}

/// The server's answer to the probe: from the server's port to us.
fn is_probe_answer(line: &str) -> bool {
    line.contains(&format!("{SERVER_IP}.{ORDERING_PROBE_PORT} >"))
}

/// The source and destination ports of a `tcpdump -n` line (`... IP a.b.c.d.68 > e.f.g.h.67: ...`).
fn udp_ports(line: &str) -> Option<(u16, u16)> {
    let (source, rest) = line.split_once(" IP ")?.1.split_once(" > ")?;
    let port = |addr: &str| -> Option<u16> { addr.rsplit('.').next()?.parse().ok() };
    Some((port(source.trim())?, port(rest.split(':').next()?)?))
}

/// A DHCP message (the filter keeps only UDP with our transaction id) sent to the port the server owns.
fn is_dhcp_request(line: &str) -> bool {
    line.contains("BOOTP/DHCP") && udp_ports(line).is_some_and(|(_, to)| to == DHCP_SERVER_PORT)
}

fn parse_mac(text: &str) -> Result<[u8; 6], String> {
    let octets: Vec<u8> = text
        .split(':')
        .map(|o| u8::from_str_radix(o, 16))
        .collect::<Result<_, _>>()
        .map_err(|e| format!("hardware address {text:?}: {e}"))?;
    octets
        .try_into()
        .map_err(|_| format!("hardware address {text:?} is not six octets"))
}

fn random_u32() -> u32 {
    use std::hash::BuildHasher;
    std::hash::RandomState::new().hash_one(std::process::id()) as u32
}

/// A BOOTP header carries 236 bytes, then the magic cookie. RFC 2131 4.3.2 RENEWING: the leased
/// address in `ciaddr`, no requested-address and no server-identifier option, sent unicast.
const BOOTP_FIXED_LEN: usize = 236;
const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];
/// Servers and relays expect at least a 300-byte BOOTP message.
const MIN_BOOTP_LEN: usize = 300;

fn renewal_request(lease: &Lease, xid: u32) -> Vec<u8> {
    let mut p = vec![0u8; BOOTP_FIXED_LEN];
    p[0] = 1; // BOOTREQUEST
    p[1] = 1; // Ethernet
    p[2] = 6; // hardware address length
    p[4..8].copy_from_slice(&xid.to_be_bytes());
    p[12..16].copy_from_slice(&lease.client.octets()); // ciaddr
    p[28..34].copy_from_slice(&lease.mac); // chaddr
    p.extend_from_slice(&MAGIC_COOKIE);
    p.extend_from_slice(&[53, 1, 3]); // DHCPREQUEST
    p.extend_from_slice(&[61, 7, 1]); // client identifier: hardware type, then the address
    p.extend_from_slice(&lease.mac);
    p.push(255);
    p.resize(p.len().max(MIN_BOOTP_LEN), 0);
    p
}
