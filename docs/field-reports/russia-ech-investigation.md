# A CDN-fronted server that does not answer

A client in Russia could not get a working tunnel, and a second test box in Russia failed the same way. Both used a
server behind a CDN, and the {term}`ECH` lookup for it succeeded every time, so the first suspicion was that a censor was
reacting to ECH. That suspicion was written down as a hypothesis, and the test that would check it was never run.

The sources are the investigator's working notes, which are not published, and the logs they quote, which are not part of
this documentation. Every observation below is therefore second-hand.

```{admonition} This case is open
---
class: warning
---
The observations below are what the notes report. The reading that a censor targeted ECH is a hypothesis, and the
evidence neither confirms nor excludes it. [Reading the evidence](#reading-the-evidence) says why, and [the control that
was never run](#the-control-that-was-never-run) says what would settle it.
```

## The setting

- A client in Russia, on Hole 0.5.0.
- A server entry whose plugin options name {term}`galoshes` as the plugin, with TLS on, and a domain name as the TLS server
  name (`host`). The domain is served from a CDN, so it resolves to an address in the CDN's space.
- No `ech` option in the plugin options, so the default, `auto` (see [the three ways ECH can
  fail](ech-in-practice.md#three-ways-it-can-fail-and-which-way-each-one-fails)).
- A `fast-open` option, which the notes record for this config. {term}`ex-ray` reads the option as `fastOpen`, so whether TCP
  Fast Open was on is unknown.

## Observed

**On the client's screen:**

1. Chrome, with no VPN, got a timeout opening the server's site, even after the system DNS was switched to a public
   resolver over {term}`DoH`. The notes do not say whether Chrome's attempt went to the same address and port as Hole's.
1. The first connect attempt in Hole failed. After closing and reopening Hole, a later attempt went green.
1. While green, Hole's dashboard (its main window) showed outbound bytes in the traffic graph and no inbound ones, and no
   site loaded.

**In the log of the {term}`bridge`** (Hole's privileged background service), which the notes quote:

- ex-ray's own error on each attempt began `wsarecv: A connection attempt failed because the connected party did not properly respond...`. The notes elide the rest of the message.
- The ECH config lookup, to the default {term}`DoH` resolver, succeeded on every attempt: a real config and a real
  lifetime.
- One attempt of the start-time DNS {term}`self-test` passed, which is how the connect went green at all.
- After that, the notes say ex-ray kept retrying the outer connection about every 19 seconds for the rest of the capture,
  every retry failing the same way. They say this matches the reconnect cadence of galoshes' transport. They do not say
  which log line the cadence was read from.

**In the bridge's connection trace**, a Windows network event trace (ETW) the bridge records: connect attempts to the
server's address were logged, and none was followed by a "connect complete" event. This is the weakest line here; the
next section says why.

**On a second test box in Russia**, the same day and the same release, with the same config: six connect attempts, none
succeeded, with the same pattern in the connection trace. The ECH lookup succeeded on all eight that were logged. The
notes do not say why there are more lookups than connect attempts.

## What the code does with ECH here

With no `ech` option the mode is `auto`. When the lookup succeeds, `auto` and `always` act alike: the ECH extension is
applied. `auto` differs only when the lookup itself fails, and then it sends the name in the clear.

The release in question already dialed the WebSocket transport as Chrome would: ex-ray's default fingerprint for a
client WebSocket dial is `chrome_auto`, and that fingerprint carries ECH. So the lookups that succeeded produced
ClientHellos with ECH, and the real server name was not sent in the clear on any attempt that got as far as a
ClientHello. Whether any attempt got that far is what the next section is about.

## Reading the evidence

**The connection trace says little.** The bridge's trace is limited to the bridge's own process, and ex-ray is a child
process. The connects it recorded are therefore, most likely, the bridge's own: the out-of-band reachability probe that
runs beside the start-time self-test (see [Range-blocked hosts](range-blocked-hosts.md#how-hole-reports-it)), not ex-ray's
dials. The missing "connect complete" event is also weak evidence on its own: in a later triage of two other logs it was
missing for external connections that had evidently worked.

**ex-ray's own error does not say the connect failed.** `wsarecv` names a receive on a socket that already exists; Go on
Windows reports a failed connect as `connectex`. Read as written, the error is a timeout on an established TCP connection:
the TCP handshake completed and then nothing came back. The notes' working hypothesis read the failure as SYNs sent and
never answered. The error text does not show that, and the only SYN-level evidence is the connection trace above.

That reading holds only if TCP Fast Open was off. With it, the client's first data can ride the SYN, so a handshake that
fails can show up first on a read, and the same error would then not say that the connection was established. Whether the
option took effect is not known ([the setting](#the-setting)).

That leaves several readings. The error text fits each, none is established, and all are hypotheses:

- **A censor acting on the hello.** The hypothesis recorded at the time: deep packet inspection (DPI), or the
  {term}`TSPU` equipment Russian operators run, interferes with the ECH extension or with its shared outer server name,
  for instance by dropping the ClientHello or the server's reply. An established connection that then goes silent is what
  that would look like. It stays open. The control below is the test.
- **A block on the destination.** The CDN address, or its port, is blocked in a way that lets TCP complete and then
  drops what follows. ECH is then beside the point, and so is the real server name.
- **A penalty after an earlier hello.** A device that saw an earlier ClientHello from that client to that address, and
  then dropped the client's later traffic. No test for it is on record.
- **A fault on that path** that has nothing to do with censorship.

Whatever the reading, one self-test attempt passed, so traffic got through end to end at least once. A block that never
lets anything through does not fit that; the readings above all have to allow for it.

**Two boxes failing against one address do not separate them.** Two machines in Russia failing against the same address
is consistent with a network block, and just as consistent with something about that address or path that breaks for any
reason. The plain-Chrome timeout does not separate them either: if Chrome also sent ECH, it failed the same way for the
same unknown reason.

An earlier case is a caution; it has no page here, and this is the notes' summary of it. An earlier "unusable from Russia"
report, from a test box, looked the same: the start-time check failed, and no traffic came back after the tunnel came up.
A packet capture showed the handshake with the CDN completing cleanly, so the censorship reading was ruled out. The cause
was a fault in Hole's own tunnel transport that a lossy path exposed. The symptom a user sees does not say which of the
two they have.

## The control that was never run

The test the investigator wrote down: from the same box, in the same time window, dial something that is not ECH-bearing
and not this address, such as a plain HTTPS connection to a different CDN-fronted host.

- If it works, the variable is isolated to this address or this ClientHello, and not to the CDN's whole address space.
- If it fails too, the network is dropping connections to that CDN broadly, and nothing specific to this server or to ECH
  explains the failure.

By the same logic, a bare TCP connect to port 443 of the address, with no TLS at all, separates a block on the
destination from anything that depends on the ClientHello. If that also gets no reply, the ClientHello cannot be what the
network reacted to. Neither test has been run.

## What Hole showed

The dashboard stayed green while no data came in. "Connected" is decided once, by the start-time self-test; nothing after
it re-checks that traffic flows. That is a known gap, tracked in
[bindreams/hole#772](https://github.com/bindreams/hole/issues/772).

## What to take from it

- Before blaming the network, run a control dial from the same box. The [recommendations](hostile-networks.md) put it
  first.
- Tell the layer apart: no reply to the SYN, a reset ClientHello and a tunnel that dies after it are three different
  failures ([telling them apart](hostile-networks.md#telling-the-failures-apart)). This case's own error fits the second
  or the third, not the first. The evidence does not separate those two; the leading hypothesis, a censor acting on the
  hello, is the second.
- ECH conceals the server's name, not its address. If the address is what is blocked, ECH cannot help; see [ECH in
  practice](ech-in-practice.md#what-ech-does-not-do).
