//! Fake DNS — handles A/AAAA queries by returning synthetic IPs from a
//! pool, then lets the dispatcher reverse-map those fake IPs back to
//! the original domain at connection time.
//!
//! This is a *function*, not a server: there is no socket bound
//! anywhere. The dispatcher's port-53 fast path (added in Plan 2)
//! invokes [`FakeDns::handle_udp`] directly with bytes pulled from
//! smoltcp; the response is written back through smoltcp.
//!
//! Allocation is sequential with collision skip. Eviction is LRU on
//! the unpinned set; pinned entries (refcounted by active flows) are
//! never evicted. Pool exhaustion (every entry pinned) is reported as
//! `AllocateError::Exhausted` and the DNS query is answered with
//! SERVFAIL — degenerate case requiring tens of thousands of
//! concurrent distinct domain connections.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use ipnet::{Ipv4Net, Ipv6Net};
use lru::LruCache;

use super::matcher::canonicalize_ip;

// Default pools =======================================================================================================

/// IPv4 pool (RFC 2544 benchmark testing range). De-facto standard
/// shared with Clash, V2Ray, sing-box. Unroutable on the public
/// internet — leaked fake IPs cannot collide with real destinations.
pub const DEFAULT_POOL_V4: &str = "198.18.0.0/15";

/// IPv6 pool (ULA prefix per RFC 4193). Plenty of room and unroutable.
pub const DEFAULT_POOL_V6: &str = "fd00:0:0:ff00::/64";

/// TTL written into fake DNS responses. Short, so apps re-query
/// frequently and the bimap stays warm.
pub const FAKE_DNS_TTL: u32 = 60;

// Errors ==============================================================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllocateError {
    /// Every IP in the pool is pinned by an active flow; no more
    /// allocations possible until something un-pins.
    Exhausted,
}

impl std::fmt::Display for AllocateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exhausted => f.write_str("fake DNS pool exhausted"),
        }
    }
}

impl std::error::Error for AllocateError {}

// State ===============================================================================================================

/// Internal mutable state, guarded by a single mutex on `FakeDns`.
struct State {
    /// Forward maps: domain → fake IP, separate per family. Domains
    /// are interned as `Arc<str>` so the bimap shares storage.
    domain_to_v4: HashMap<Arc<str>, Ipv4Addr>,
    domain_to_v6: HashMap<Arc<str>, Ipv6Addr>,
    /// LRU buckets for unpinned entries (eligible for eviction). Keys
    /// are the fake IPs; values are the interned domain.
    unpinned_v4: LruCache<Ipv4Addr, Arc<str>>,
    unpinned_v6: LruCache<Ipv6Addr, Arc<str>>,
    /// Pinned entries — never evicted. Refcount tracks active flows
    /// using each fake IP. When the refcount drops to 0, the entry
    /// moves back into the corresponding LRU bucket.
    pinned_v4: HashMap<Ipv4Addr, (Arc<str>, u32)>,
    pinned_v6: HashMap<Ipv6Addr, (Arc<str>, u32)>,
    /// Sequential allocation cursors (offset within the pool). On
    /// collision, the allocator advances and tries again.
    next_v4_offset: u64,
    next_v6_offset: u128,
}

// Public API ==========================================================================================================

/// Fake DNS function. Construct once at proxy start with a fixed pair
/// of pools, then call [`Self::handle_udp`] for each port-53 datagram
/// received from smoltcp.
pub struct FakeDns {
    pool_v4: Ipv4Net,
    pool_v6: Ipv6Net,
    pool_v4_size: u64,
    state: Mutex<State>,
}

impl FakeDns {
    /// Construct a `FakeDns` with the default pools (`198.18.0.0/15`
    /// for v4, `fd00:0:0:ff00::/64` for v6).
    pub fn with_defaults() -> Self {
        let v4 = DEFAULT_POOL_V4
            .parse::<Ipv4Net>()
            .expect("default v4 pool literal is valid");
        let v6 = DEFAULT_POOL_V6
            .parse::<Ipv6Net>()
            .expect("default v6 pool literal is valid");
        Self::new(v4, v6)
    }

    /// Construct a `FakeDns` with custom pools.
    pub fn new(pool_v4: Ipv4Net, pool_v6: Ipv6Net) -> Self {
        // Pool size for v4 is at most 2^32 (less than u64::MAX), so the
        // u64 cast is lossless. For v6 we cap the eviction-bucket
        // capacity at a reasonable upper bound — eviction logic only
        // matters when the working set actually approaches the pool
        // size, which never happens for /64.
        let pool_v4_size = network_size_v4(&pool_v4);
        let v4_capacity = clamp_capacity(pool_v4_size);
        let v6_capacity = NonZeroUsize::new(1 << 16).expect("constant is non-zero");

        Self {
            pool_v4,
            pool_v6,
            pool_v4_size,
            state: Mutex::new(State {
                domain_to_v4: HashMap::new(),
                domain_to_v6: HashMap::new(),
                unpinned_v4: LruCache::new(v4_capacity),
                unpinned_v6: LruCache::new(v6_capacity),
                pinned_v4: HashMap::new(),
                pinned_v6: HashMap::new(),
                next_v4_offset: 0,
                next_v6_offset: 0,
            }),
        }
    }

    /// Look up the domain that was previously mapped to a fake IP.
    /// Returns `None` if the IP is not in the bimap. IPv4-mapped IPv6
    /// addresses (`::ffff:1.2.3.4`) are unwrapped before lookup so the
    /// dispatcher's connection-level address (which may arrive in
    /// either form) finds the same entry.
    pub fn reverse_lookup(&self, ip: IpAddr) -> Option<Arc<str>> {
        let ip = canonicalize_ip(ip);
        let state = self.state.lock().unwrap();
        match ip {
            IpAddr::V4(v4) => {
                if let Some((domain, _)) = state.pinned_v4.get(&v4) {
                    return Some(Arc::clone(domain));
                }
                state.unpinned_v4.peek(&v4).map(Arc::clone)
            }
            IpAddr::V6(v6) => {
                if let Some((domain, _)) = state.pinned_v6.get(&v6) {
                    return Some(Arc::clone(domain));
                }
                state.unpinned_v6.peek(&v6).map(Arc::clone)
            }
        }
    }

    /// Look up the fake IP currently allocated to a domain. Returns
    /// `None` if no allocation exists in the requested family.
    pub fn forward_lookup_v4(&self, domain: &str) -> Option<Ipv4Addr> {
        let state = self.state.lock().unwrap();
        state.domain_to_v4.get(domain).copied()
    }

    /// Look up the fake IPv6 currently allocated to a domain.
    pub fn forward_lookup_v6(&self, domain: &str) -> Option<Ipv6Addr> {
        let state = self.state.lock().unwrap();
        state.domain_to_v6.get(domain).copied()
    }

    /// Pin an entry by its fake IP, preventing LRU eviction. Pinning
    /// is refcounted: each call must be paired with a `unpin` call.
    /// Pinning a non-existent IP is a no-op (the dispatcher should
    /// never do this, but we don't panic to keep the API permissive).
    pub fn pin(&self, ip: IpAddr) {
        let ip = canonicalize_ip(ip);
        let mut state = self.state.lock().unwrap();
        match ip {
            IpAddr::V4(v4) => {
                if let Some(domain) = state.unpinned_v4.pop(&v4) {
                    state.pinned_v4.insert(v4, (domain, 1));
                } else if let Some((_, count)) = state.pinned_v4.get_mut(&v4) {
                    *count += 1;
                }
            }
            IpAddr::V6(v6) => {
                if let Some(domain) = state.unpinned_v6.pop(&v6) {
                    state.pinned_v6.insert(v6, (domain, 1));
                } else if let Some((_, count)) = state.pinned_v6.get_mut(&v6) {
                    *count += 1;
                }
            }
        }
    }

    /// Decrement the refcount for an entry; if it reaches zero, move
    /// it back into the LRU set so it becomes evictable. Unpinning a
    /// non-pinned IP is a no-op.
    pub fn unpin(&self, ip: IpAddr) {
        let ip = canonicalize_ip(ip);
        let mut state = self.state.lock().unwrap();
        match ip {
            IpAddr::V4(v4) => {
                if let Some((_, count)) = state.pinned_v4.get_mut(&v4) {
                    *count -= 1;
                    if *count == 0 {
                        let (domain, _) = state.pinned_v4.remove(&v4).unwrap();
                        state.unpinned_v4.put(v4, domain);
                    }
                }
            }
            IpAddr::V6(v6) => {
                if let Some((_, count)) = state.pinned_v6.get_mut(&v6) {
                    *count -= 1;
                    if *count == 0 {
                        let (domain, _) = state.pinned_v6.remove(&v6).unwrap();
                        state.unpinned_v6.put(v6, domain);
                    }
                }
            }
        }
    }

    /// Handle one DNS query message and produce a response.
    ///
    /// - Parses the request via `hickory-proto`.
    /// - On parse failure, returns a `FORMERR` response if possible
    ///   (using the original query ID), else an empty Vec (the caller
    ///   should drop the datagram).
    /// - For A queries: allocate (or reuse) a fake IPv4 from the pool
    ///   and answer with the fake IP. TTL is `FAKE_DNS_TTL`.
    /// - For AAAA queries: same with IPv6.
    /// - For other query types: NOERROR with empty answer section.
    /// - On allocation exhaustion: SERVFAIL.
    pub fn handle_udp(&self, payload: &[u8]) -> Vec<u8> {
        let request = match Message::from_vec(payload) {
            Ok(m) => m,
            Err(_) => {
                // Best-effort: try to extract the ID from the first
                // two bytes of the payload to make the FORMERR
                // matchable. If the payload is shorter than 2 bytes,
                // give up entirely.
                if payload.len() < 2 {
                    return Vec::new();
                }
                let id = u16::from_be_bytes([payload[0], payload[1]]);
                let err = Message::error_msg(id, OpCode::Query, ResponseCode::FormErr);
                return err.to_vec().unwrap_or_default();
            }
        };

        self.build_response(&request).to_vec().unwrap_or_default()
    }

    /// Build a response `Message` for a parsed query. Pure-ish — only
    /// touches the bimap state, no I/O.
    fn build_response(&self, request: &Message) -> Message {
        let mut response = Message::new();
        response
            .set_id(request.id())
            .set_message_type(MessageType::Response)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(request.recursion_desired())
            .set_recursion_available(true)
            .set_authoritative(true);

        for q in request.queries() {
            response.add_query(q.clone());
        }

        let Some(query) = request.queries().first() else {
            response.set_response_code(ResponseCode::FormErr);
            return response;
        };

        match query.query_type() {
            RecordType::A => match self.allocate_v4(query.name()) {
                Ok(ip) => {
                    let record = Record::from_rdata(query.name().clone(), FAKE_DNS_TTL, RData::A(A(ip)));
                    response.add_answer(record);
                    response.set_response_code(ResponseCode::NoError);
                }
                Err(AllocateError::Exhausted) => {
                    response.set_response_code(ResponseCode::ServFail);
                }
            },
            RecordType::AAAA => match self.allocate_v6(query.name()) {
                Ok(ip) => {
                    let record = Record::from_rdata(query.name().clone(), FAKE_DNS_TTL, RData::AAAA(AAAA(ip)));
                    response.add_answer(record);
                    response.set_response_code(ResponseCode::NoError);
                }
                Err(AllocateError::Exhausted) => {
                    response.set_response_code(ResponseCode::ServFail);
                }
            },
            // For non-A/AAAA queries we return NOERROR with an empty
            // answer section. NXDOMAIN is intentionally avoided
            // because it's negatively cached and can break apps that
            // legitimately query MX/TXT/SRV.
            _ => {
                response.set_response_code(ResponseCode::NoError);
            }
        }

        response
    }

    /// Allocate a fake IPv4 for `name`. Reuses any existing
    /// allocation. Pure of I/O.
    fn allocate_v4(&self, name: &Name) -> Result<Ipv4Addr, AllocateError> {
        let domain = name_to_domain_key(name);
        let mut state = self.state.lock().unwrap();

        if let Some(&existing) = state.domain_to_v4.get(&domain) {
            // Touch LRU position if unpinned.
            let _ = state.unpinned_v4.get(&existing);
            return Ok(existing);
        }

        // Sequential allocation with collision skip. Bound the loop
        // by the pool size so we never spin forever.
        for _ in 0..self.pool_v4_size {
            let offset = state.next_v4_offset;
            state.next_v4_offset = (state.next_v4_offset + 1) % self.pool_v4_size;
            let candidate = ipv4_at_offset(&self.pool_v4, offset);
            if state.pinned_v4.contains_key(&candidate) || state.unpinned_v4.contains(&candidate) {
                continue;
            }
            state.unpinned_v4.put(candidate, Arc::clone(&domain));
            state.domain_to_v4.insert(domain, candidate);
            return Ok(candidate);
        }

        // Pool fully populated. Try LRU eviction (unpinned only).
        if let Some((victim_ip, victim_domain)) = state.unpinned_v4.pop_lru() {
            state.domain_to_v4.remove(&victim_domain);
            state.unpinned_v4.put(victim_ip, Arc::clone(&domain));
            state.domain_to_v4.insert(domain, victim_ip);
            return Ok(victim_ip);
        }

        Err(AllocateError::Exhausted)
    }

    /// Allocate a fake IPv6 for `name`.
    fn allocate_v6(&self, name: &Name) -> Result<Ipv6Addr, AllocateError> {
        let domain = name_to_domain_key(name);
        let mut state = self.state.lock().unwrap();

        if let Some(&existing) = state.domain_to_v6.get(&domain) {
            let _ = state.unpinned_v6.get(&existing);
            return Ok(existing);
        }

        // For v6 the pool is effectively infinite (/64 = 2^64), so the
        // sequential cursor never wraps in practice; we still cap the
        // loop at the cache capacity to keep the worst case bounded.
        let max_attempts = state.unpinned_v6.cap().get() as u128 + state.pinned_v6.len() as u128 + 1;
        for _ in 0..max_attempts {
            let offset = state.next_v6_offset;
            state.next_v6_offset = state.next_v6_offset.wrapping_add(1);
            let candidate = ipv6_at_offset(&self.pool_v6, offset);
            if state.pinned_v6.contains_key(&candidate) || state.unpinned_v6.contains(&candidate) {
                continue;
            }
            state.unpinned_v6.put(candidate, Arc::clone(&domain));
            state.domain_to_v6.insert(domain, candidate);
            return Ok(candidate);
        }

        if let Some((victim_ip, victim_domain)) = state.unpinned_v6.pop_lru() {
            state.domain_to_v6.remove(&victim_domain);
            state.unpinned_v6.put(victim_ip, Arc::clone(&domain));
            state.domain_to_v6.insert(domain, victim_ip);
            return Ok(victim_ip);
        }

        Err(AllocateError::Exhausted)
    }
}

// Helpers =============================================================================================================

/// Convert a hickory `Name` (which carries trailing-dot semantics)
/// into a lowercased `Arc<str>` suitable for use as a bimap key.
fn name_to_domain_key(name: &Name) -> Arc<str> {
    let mut s = name.to_ascii();
    if s.ends_with('.') {
        s.pop();
    }
    s.make_ascii_lowercase();
    Arc::from(s)
}

/// Compute the number of host addresses in an IPv4 network. For `/0`
/// this is 2^32; we cap to `u64::MAX` to avoid overflow on systems
/// that store the size as `u64`.
fn network_size_v4(net: &Ipv4Net) -> u64 {
    if net.prefix_len() == 0 {
        // 2^32 (just over u32::MAX)
        1u64 << 32
    } else {
        1u64 << (32 - net.prefix_len())
    }
}

/// Compute the IPv4 address at the given offset within a network.
/// Wraps via modulo on the caller's side.
fn ipv4_at_offset(net: &Ipv4Net, offset: u64) -> Ipv4Addr {
    let base = u32::from(net.network());
    let max_offset = network_size_v4(net);
    let normalized = (offset % max_offset) as u32;
    Ipv4Addr::from(base.wrapping_add(normalized))
}

/// Compute the IPv6 address at the given offset within a network.
fn ipv6_at_offset(net: &Ipv6Net, offset: u128) -> Ipv6Addr {
    let base = u128::from(net.network());
    Ipv6Addr::from(base.wrapping_add(offset))
}

/// Clamp a pool size to a sensible LRU capacity. The lru crate
/// requires a `NonZeroUsize`, and we don't want to allocate a
/// data structure with billions of slots even if the pool is huge.
fn clamp_capacity(size: u64) -> NonZeroUsize {
    let capped = std::cmp::min(size, 1u64 << 20) as usize;
    NonZeroUsize::new(capped.max(1)).expect("clamped to >= 1")
}

#[cfg(test)]
#[path = "fake_dns_tests.rs"]
mod fake_dns_tests;
