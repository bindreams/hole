# TCP accept refusal and socket retirement

The packet loop of the {term}`TUN` device answers every application's TCP connection itself, with a TCP/IP stack
([smoltcp](https://github.com/smoltcp-rs/smoltcp)) that plays the remote server, and only then hands the connection to
[the router](datapath.md). That puts three problems in the loop's hands: refusing a connection cleanly when Hole is at
its limit, freeing sockets without confusing a peer that is still talking, and not holding a slot for ever for a client
that has gone. This page is for a developer changing `SocketStack` or `Driver`
({src}`crates/tun-engine/src/engine/socket_stack.rs`, {src}`crates/tun-engine/src/engine/driver.rs`).

## The verdict comes before the handshake

A listener socket is created with its SYN-ACK paused (`pause_synack(true)`, enabled by smoltcp's
`socket-tcp-pause-synack` feature in {src}`crates/tun-engine/Cargo.toml`). When a SYN arrives the socket moves to
`SynReceived`, but nothing has left the interface. The driver reads the verdict there:

- `SocketStack::admit` releases the SYN-ACK, so the handshake proceeds.
- `SocketStack::refuse` aborts the socket, so the client gets a reset in answer to its SYN. A client sees a connection
  refused, and never a connection that was opened and then reset.

The verdict is `decide_admission` ({src}`crates/tun-engine/src/engine/admission.rs`), a pure function over a `Handshake`
and a closure that tries to take a connection permit. It has three outcomes, and `Driver::accept_tcp_connections` only
dispatches on them:

| Handshake   | Outcome                              | What the driver does                                                |
| ----------- | ------------------------------------ | ------------------------------------------------------------------- |
| `Pending`   | `Admit(permit)` if a permit was free | spawn the router task holding the permit, then `admit`              |
| `Pending`   | `Refuse` if the limit is reached     | `refuse`, and log the destination                                   |
| `Duplicate` | `Duplicate`                          | drop the socket without a segment ([below](#one-owner-per-4-tuple)) |

The permit is an `OwnedSemaphorePermit` from a semaphore sized by `EngineConfig::max_connections`. The closure keeps the
permit out of `decide_admission`'s types, and a duplicate never calls it, so it never costs a permit. The router task
drops the permit when it ends.

## Retiring and reaping

A socket with a packet still to send cannot simply be removed: the packet would never leave. So the driver *retires* it
(`SocketStack::retire`), which parks the handle, and `SocketStack::poll` *reaps* it, the `SocketSet::remove` that frees the
slot, once `remote_endpoint()` is `None`. That is smoltcp's signal that it has emitted the socket's last packet; a retired
socket whose peer is still live stays in the set.

`decide_disposal` picks the path for a connection socket by its state:

| State             | Disposal | Why                                                                                                                                 |
| ----------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `Closed`          | retire   | its 4-tuple is clear, or clears once the last packet is out                                                                         |
| `Listen`          | retire   | a connection socket reaches it by one route: the client answered the SYN-ACK with a reset, and smoltcp flipped it back to listening |
| `TimeWait`        | remove   | retiring would hold the socket and both buffers for smoltcp's `CLOSE_DELAY`, for nothing                                            |
| every other state | none     | still live                                                                                                                          |

`TimeWait` can be removed at once because every socket the stack creates has its delayed ACK disabled
(`set_ack_delay(None)`, in `ensure_listener`). smoltcp therefore sends any ACK it owes on the poll that ingests the
segment, and a socket removed at `TimeWait` owes nothing. With a delayed ACK, the peer's last data and FIN would go
unacknowledged and its retransmission would be answered with a reset. `SocketStack::remove` asserts the property in debug
builds. The `Listen` case matters because a reverted socket keeps its listen endpoint and would take every later SYN on
its port (`a_reverted_socket_would_hijack_a_later_syn`).

### One call per packet

Retiring only marks a socket; the reap happens in the next `poll`. In between, the socket is still live and still bound to
its port, so a SYN arriving before that poll can be handed to it, with no accept path watching it. `Driver::settle_packet`
closes the gap by construction: enqueue, both polls, admission, relay and retirement all happen inside one call per
packet, so two packets' verdicts can never straddle a poll however the loop's read cadence changes. It is the only
production entry point for a TUN packet.

## One owner per 4-tuple

Re-arming a port gives the new listener the lowest free socket slot, which can sit *below* the connection it was just
re-armed for. smoltcp hands a packet to the first socket that accepts it, and a `Listen` socket accepts a bare SYN on the
local port alone. A SYN can therefore land on the replacement listener when it belongs to its own connection. Tuple
equality does not say whether it is that connection's retransmission or a new connection reusing the tuple: a client
that lost its own TCP state while the stack kept its own (a reboot, a resume from sleep, a recycled ephemeral port).

`SocketStack::take_handshakes` tells them apart by the initial sequence number (ISN). smoltcp exposes none, so
`enqueue_rx` reads it off the wire with `parse_syn`, for a bare SYN over IPv4, or over IPv6 after at most one Hop-by-Hop
header, and it keeps the ISN each admitted connection was admitted with (`owner_isn`).

| Same-tuple SYN                            | Reported as                     | What happens                                                              |
| ----------------------------------------- | ------------------------------- | ------------------------------------------------------------------------- |
| same ISN as the owner's                   | `Handshake::Duplicate`          | the new socket is dropped without a segment                               |
| different ISN                             | `Pending` with `supersedes` set | the driver tears the stale owner down, then admits or refuses the new SYN |
| either ISN could not be read off the wire | `Duplicate`                     | a parsing gap never creates a connection or tears down a live one         |

A duplicate gets no reset, because the reset would acknowledge the client's SYN, which a client in `SYN-SENT` must accept,
and would kill the very connection it is retransmitting for. Superseding follows RFC 9293 section 3.10.7.4.

## A client that never speaks again

An admitted connection gets a keep-alive and a timeout (`EngineConfig::tcp_keep_alive_interval` and `tcp_peer_timeout`,
set in `admit`). They bound an external event, a client process that may never speak again, and not anything inside the
engine. Without them a connection stalled in `SynReceived`, `FinWait2` or `CloseWait` reaches no state `decide_disposal`
has a verdict for, and holds its entry, both buffers and its connection permit for the life of the process; enough of
them wedge the tunnel for all new TCP. The keep-alive probe is what keeps the bound off a client that is merely quiet:
only silence in answer to the probes resets the socket to `Closed`, where the disposal path already runs. The defaults
are in {src}`crates/tun-engine/src/engine/config.rs`; the timeout default is the floor RFC 5382 REQ-5 sets for a
transitory connection, and the interval is a quarter of it.

## Read next

- [The datapath](datapath.md): what happens to an admitted connection.
- [The TUN device](tun-device.md): the device the packet loop reads.
