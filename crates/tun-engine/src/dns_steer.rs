//! macOS DNS steering — publish a supplemental resolver at a synthetic,
//! session-scoped `SCDynamicStore` key so Hole becomes (one of) the
//! machine's DNS resolvers, without writing to any of the user's real
//! network services.
//!
//! The mechanism (validated by PR #877's spike, on both darwin arches): a
//! dictionary `{ ServerAddresses: [...], SupplementalMatchDomains: [""],
//! SearchOrder: 100000 }` published at `State:/Network/Service/<uuid>/DNS`
//! — a service that does not exist — is merged by configd as a supplemental
//! resolver for every query (the empty match-domain matches everything),
//! ranked above its own 200000 default. Nothing of the user's is ever read
//! or captured, so there is nothing to restore on withdraw beyond removing
//! that one key.
//!
//! **Session-scoped, not persistent (D3).** The store is built with
//! `SCDynamicStoreBuilder::session_keys(true)`: the key is scoped to this
//! process's dynamic-store session and configd discards it when the session
//! closes, including on an abrupt process exit — the exact analogue of
//! `dns_confine`'s process-scoped dynamic FWPM session on Windows. There is
//! therefore no persistent state and nothing for a startup sweep to
//! reconcile; two live bridges publish two distinct keys and configd merges
//! both rather than either unsteering the other.
//!
//! `SCDynamicStore` is not `Send` (it wraps a raw CF pointer type), so the
//! open session lives on a dedicated OS thread for its whole lifetime;
//! [`Steering`] itself holds only a channel handle to that thread, so it
//! *is* `Send`. [`Steering::withdraw`] is confirmable — it blocks for the
//! thread's acknowledgement of the removal — with `Drop` as the best-effort
//! crash/unwind fallback, mirroring the discipline
//! `ProxyManager::stop_with` already applies to the lockdown cover: `Drop`
//! can only warn on a genuine OS failure, never propagate one.
//!
//! `#[cfg]`-free facade, mirroring `dns_confine`'s shape.

#[cfg(target_os = "macos")]
#[path = "dns_steer/macos.rs"]
mod platform;

#[cfg(target_os = "macos")]
pub use platform::{engage, DnsSteerError, Steering};
