//! macOS DNS steering: publish a supplemental resolver at a synthetic,
//! session-scoped `SCDynamicStore` key so Hole becomes (one of) the
//! machine's DNS resolvers, without writing to any of the user's real
//! network services.
//!
//! The mechanism: a dictionary `{ ServerAddresses, SupplementalMatchDomains:
//! [""], SearchOrder }` published at `State:/Network/Service/<uuid>/DNS`, a
//! service that does not exist, is merged by configd as a supplemental
//! resolver for every query (the empty match domain matches everything) and
//! ranked above configd's default search order. Nothing of the user's is ever
//! read or captured, so withdrawing only removes that one key.
//!
//! **Session-scoped, not persistent.** The store is built with
//! `SCDynamicStoreBuilder::session_keys(true)`: the key is scoped to this
//! process's dynamic-store session and configd discards it when the session
//! closes, including on an abrupt process exit, like `dns_confine`'s
//! process-scoped dynamic FWPM session on Windows. There is therefore no
//! persistent state and nothing for a startup sweep to reconcile; two live
//! bridges publish two distinct keys and configd merges both rather than
//! either unsteering the other. The key is logged at `info` when published,
//! the only way to find a stranded one by hand.
//!
//! `SCDynamicStore` is not `Send` (it wraps a raw CF pointer type), so the
//! open session lives on a dedicated OS thread for its whole lifetime;
//! `Steering` itself holds only a channel handle to that thread, so it
//! *is* `Send`. `Steering::withdraw` is confirmable: it blocks for the
//! thread's acknowledgement of the removal. `Drop` is the best-effort
//! crash/unwind fallback and can only warn on a genuine OS failure, never
//! propagate one.

#[cfg(target_os = "macos")]
#[path = "dns_steer/macos.rs"]
mod platform;

#[cfg(target_os = "macos")]
pub use platform::{engage, DnsSteerError, Steering};
