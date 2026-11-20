# The reachability check

A network that blocks the TLS handshake to a server and a server that rejects the password look the same from the
client: the tunnel does not come up. Hole tells them apart with the {term}`reachability check`, a connection the
{term}`bridge` makes straight to the server's address, outside the tunnel.

## When the check runs

On connect, the bridge runs the check beside its start-time {term}`self-test`. If the self-test fails, the result of the
check decides the message:

| Result of the check                                           | Message                                                  |
| ------------------------------------------------------------- | -------------------------------------------------------- |
| TCP connected, then no byte came back                         | "The network is blocking the connection to this server…" |
| The server refused the TCP connection                         | "The server refused the connection."                     |
| Nothing answered the TCP connect, or it failed some other way | "The server did not respond (connection timed out)."     |
| The server answered, or the check could not tell              | The self-test's own message                              |

On **Test**, the bridge runs the check when the test ends as "Server rejected the connection" or "Server cannot reach
the public internet". If the check found the handshake blocked, Test reports the network block and not the rejection.

## What the check sends

The check goes to the server's address as the bridge resolved it, never to its domain name. It speaks the plugin's
transport: a bare TCP connect with no plugin, a TLS {term}`ClientHello` for a plugin with `tls`, a WebSocket upgrade request for a
WebSocket plugin without it, a QUIC handshake for a QUIC server. For TLS it accepts any byte in reply and does not verify the certificate, because the question is
whether the network lets a handshake through, not whose certificate comes back.

## Limitations of the reachability check

- On connect, the bridge skips the check when {term}`Lockdown <lockdown>` is on, because Hole's own block would fail
  it. A failed connect then shows the self-test's own message.
- On connect, the check runs only with the {term}`DNS forwarder` on, because the self-test it accompanies is the
  forwarder's.
- Its ClientHello carries neither {term}`ECH` nor the {term}`SNI` extension. Hole therefore reports a server that
  ignores a ClientHello without the SNI extension as blocked. And a result of "reachable" means that a plain
  ClientHello was answered, not that the one {term}`ex-ray` sends would be.
- Hole reports a reply that arrives after the check's deadline as blocked.
- Hole reports a TCP connect that fails for any reason other than a refusal as "did not respond", whether the cause is
  the network, a firewall on the machine or a reset.

A network that blocked handshakes this way is described in
[a field report from June 2026](../knowledge-base/field-reports/2026-06-tls-handshake-block.md).

```{dropdown} Where in the code
The check is {src}`crates/bridge/src/reachability.rs`. The messages are in {src}`crates/common/src/protocol.rs` and
{src}`ui/servers.ts`.
```
