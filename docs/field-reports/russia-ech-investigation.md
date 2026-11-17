# A CDN address that never answers

A client in Russia could not get a working tunnel, and a second test box in Russia failed the same way. Both used a
server behind a CDN, and the {term}`ECH` lookup for it succeeded every time, so the first suspicion was that a censor was
reacting to ECH. That suspicion was written down as a hypothesis, and the test that would check it was never run.

```{admonition} This case is open
---
class: warning
---
The observations below are solid. The reading that a censor targeted ECH is a hypothesis, and the evidence fits it worse
than it first looked. [Reading the evidence](#reading-the-evidence) says why, and [the control that was never
run](#the-control-that-was-never-run) says what would settle it.
```

## The setting

- A client in Russia, on Hole 0.5.0, the release of the time.
- A server config that names {term}`galoshes` as the plugin, with TLS on, and a domain name as the TLS server name
  (`host`). The domain is served from a CDN, so it resolves to an address in the CDN's space.
- No `ech` option in the config, so the default, `auto`.

## Observed

**On the client's screen:**

1. Chrome, with no VPN, got a timeout opening the server's site, even after the system DNS was switched to a public
   resolver over {term}`DoH`.
1. The first connect attempt in Hole failed. After closing and reopening Hole, a later attempt went green.
1. While green, the dashboard's traffic graph showed outbound bytes and no inbound ones, and no site loaded.

**In the bridge log:**

- Every connection attempt to the server's address that the log recorded started and none was reported complete.
- ex-ray's own error on each attempt was that the other side did not respond.
- The ECH config lookup, to the default {term}`DoH` resolver, succeeded on every attempt: a real config and a real
  lifetime.
- One start-time DNS self-test attempt passed, which is how the connect went green at all. After that ex-ray retried the
  outer connection about every 19 seconds for the rest of the capture, and every retry failed the same way.

**On a second test box in Russia**, the same day and the same release, with the same config: six connect attempts, none
succeeded, and the same pattern of connection attempts that never completed. The ECH lookup succeeded on all eight that
were logged.

## What the code does with ECH here

With no `ech` option the mode is `auto`. When the lookup succeeds, `auto` and `always` act alike: the ECH extension is
applied. `auto` differs only when the lookup itself fails, and then it sends the name in the clear.

The release in question already dialed the WebSocket transport as Chrome would: ex-ray's default fingerprint for a
client WebSocket dial is `chrome_auto`, and that fingerprint carries ECH. So the lookups that succeeded produced
ClientHellos with ECH, and the real server name was not sent in the clear on any attempt that got as far as a
ClientHello.

That last clause matters, and the next section is about it.

## Reading the evidence

**The recorded connects are the bridge's own.** The bridge's connection trace is limited to the bridge's own process, and
ex-ray is a child process. The connects it recorded are therefore, most likely, the bridge's own: the out-of-band
reachability probe that runs beside the start-time self-test (see [Range-blocked
hosts](range-blocked-hosts.md#how-hole-reports-it)), not ex-ray's dials. The trace's missing "connect complete" event is
also weak evidence on its own: in a later triage of two other logs it was missing for external connections that had
evidently worked. ex-ray's own error is the stronger signal.

**A dropped SYN has no ClientHello in it.** The hypothesis recorded at the time was that DPI, or the {term}`TSPU`
equipment Russian operators run, interferes with the ECH extension or with its shared outer server name. But the observed
failure is that the connection attempt itself got no reply, and in an ordinary TCP handshake the ClientHello follows the
server's reply. Whatever dropped the attempt was reacting to something other than the ECH extension. These readings fit:

- **A block on the destination.** The CDN address, or its port, is unreachable from that network. ECH is then beside the
  point, and so is the real server name.
- **A penalty after an earlier hello.** A device that saw an earlier ClientHello from that client to that address, and
  then dropped the client's later connection attempts. It is the only reading here in which ECH matters, and nothing
  observed supports it over the first.
- **A fault on that path** that has nothing to do with censorship.

None of the three is established. They are hypotheses.

```{dropdown} The exception: TCP Fast Open
TCP Fast Open can put the ClientHello into the SYN, once the client holds a cookie from an earlier connection to the same
address. The config in this case named a `fast-open` option, and the notes do not say whether it took effect: ex-ray reads
the option under the spelling `fastOpen`. For the first attempts there was no earlier connection to give a cookie, so the
argument holds. After the attempt that went green it is weaker.
```

**Two boxes failing against one address do not separate them.** Two machines in Russia failing against the same address
is consistent with a network block, and just as consistent with something about that address or path that breaks for any
reason. The plain-Chrome timeout does not separate them either: if Chrome also sent ECH, it failed the same way for the
same unknown reason.

The case before this one is the warning. An earlier "unusable from Russia" report, from a test box, looked the same:
the start-time check failed, and no traffic came back after the tunnel came up. A packet capture showed the handshake with
the CDN completing cleanly, so the censorship reading was ruled out. The cause was a fault in Hole's own tunnel
transport that a lossy path exposed. The symptom a user sees does not say which of the two they have.

## The control that was never run

The test the notes name: from the same box, in the same time window, dial something that is not ECH-bearing and not this
address, such as a plain HTTPS connection to a different CDN-fronted host.

- If it works, the variable is isolated to this address or this ClientHello, and not to the CDN's whole address space.
- If it fails too, the network is dropping connections to that CDN broadly, and nothing specific to this server or to ECH
  explains the failure.

By the same logic, a bare TCP connect to port 443 of the address, with no TLS at all, separates a block on the
destination from anything that depends on the ClientHello. If that also gets no reply, the ClientHello cannot be what the
network reacted to. Neither test has been run.

## What Hole showed

The dashboard stayed green while no data came in. "Connected" is decided once, by the start-time gate; nothing after it
re-checks that traffic flows. That is a known gap, tracked in
[bindreams/hole#772](https://github.com/bindreams/hole/issues/772).

## What to take from it

- Before blaming the network, run a control dial from the same box. The [recommendations](hostile-networks.md) put it
  first.
- Tell the layer apart: no reply to the SYN, a reset ClientHello and a tunnel that dies after it are three different
  failures with three different remedies ([telling them apart](hostile-networks.md#telling-the-failures-apart)).
- ECH conceals the server's name, not its address. If the address is what is blocked, ECH cannot help; see [ECH in
  practice](ech-in-practice.md#what-ech-does-not-do).
