//! `Socks5DnsUpstream` — a fixture that accepts a SOCKS5 CONNECT on
//! loopback and answers exactly one DNS-over-TCP query with a canned
//! NOERROR reply. Lets a unit-test `start_inner` clear the Phase-4
//! forwarder self-test gate (which dials the configured SOCKS5 listener)
//! and reach Phase 7 (`Dns::apply`) without a real shadowsocks listener or
//! a real upstream resolver.
//!
//! No sleep or timeout sequences the accept: `bind_ephemeral`'s bind+listen
//! has already queued the kernel accept backlog before this returns, so any
//! connect attempt against the returned port succeeds immediately — the
//! same reasoning `start_inner`'s own in-bridge self-test connect uses.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use util::port_alloc::{bind_ephemeral, Protocols};

const SOCKS5_VER: u8 = 0x05;
const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_IPV6: u8 = 0x04;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;

pub(crate) struct Socks5DnsUpstream {
    port: u16,
    task: tokio::task::JoinHandle<()>,
}

impl Socks5DnsUpstream {
    pub(crate) async fn bind() -> std::io::Result<Self> {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let (port, listener) = bind_ephemeral(
            ip,
            Protocols::TCP,
            |port| async move { TcpListener::bind((ip, port)).await },
        )
        .await?;

        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(serve_one(stream));
            }
        });

        Ok(Self { port, task })
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for Socks5DnsUpstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A well-formed NOERROR DNS-over-TCP reply with no records.
/// `crate::dns::self_test::is_dns_reply_ok` only requires 12+ bytes and a
/// non-SERVFAIL RCODE, so an empty answer section is sufficient.
fn canned_dns_reply() -> Vec<u8> {
    vec![
        0x00, 0x01, // ID (matches the self-test's fixed query ID)
        0x81, 0x80, // flags: QR=1, RD=1, RA=1, RCODE=0 (NOERROR)
        0x00, 0x00, // QDCOUNT
        0x00, 0x00, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
    ]
}

/// Serve one connection: SOCKS5 no-auth greeting, a CONNECT ack (to any
/// target — this fixture never dials out, it just plays the far end of the
/// tunnel), then one length-prefixed DNS query/reply exchange. Best-effort:
/// any I/O error just ends the task, mirroring a real peer closing early.
async fn serve_one(mut stream: TcpStream) {
    let mut greeting = [0u8; 2];
    if stream.read_exact(&mut greeting).await.is_err() {
        return;
    }
    let nmethods = greeting[1] as usize;
    let mut methods = vec![0u8; nmethods];
    if stream.read_exact(&mut methods).await.is_err() {
        return;
    }
    if stream.write_all(&[SOCKS5_VER, 0x00]).await.is_err() {
        return; // METHOD=NoAuth
    }

    // CONNECT request: VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
    let mut head = [0u8; 4];
    if stream.read_exact(&mut head).await.is_err() {
        return;
    }
    let addr_len = match head[3] {
        SOCKS5_ATYP_IPV4 => 4,
        SOCKS5_ATYP_IPV6 => 16,
        SOCKS5_ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            if stream.read_exact(&mut len).await.is_err() {
                return;
            }
            len[0] as usize
        }
        _ => return,
    };
    let mut addr_buf = vec![0u8; addr_len + 2]; // + DST.PORT
    if stream.read_exact(&mut addr_buf).await.is_err() {
        return;
    }

    // Reply: VER | REP=0 (succeeded) | RSV | ATYP=IPv4 | BND.ADDR=0.0.0.0 | BND.PORT=0
    let reply = [SOCKS5_VER, 0x00, 0x00, SOCKS5_ATYP_IPV4, 0, 0, 0, 0, 0, 0];
    if stream.write_all(&reply).await.is_err() {
        return;
    }

    let mut len_buf = [0u8; 2];
    if stream.read_exact(&mut len_buf).await.is_err() {
        return;
    }
    let qlen = u16::from_be_bytes(len_buf) as usize;
    let mut query = vec![0u8; qlen];
    if stream.read_exact(&mut query).await.is_err() {
        return;
    }

    let answer = canned_dns_reply();
    let mut framed = Vec::with_capacity(2 + answer.len());
    framed.extend_from_slice(&(answer.len() as u16).to_be_bytes());
    framed.extend_from_slice(&answer);
    let _ = stream.write_all(&framed).await;
}
