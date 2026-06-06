# sitrep 1.0.0 — SIP003u plugin → host situation-report protocol

- **Version:** 1.0 (document); wire `protocol` string `sitrep-1.0.0`
- **Status:** Draft
- **License:** Apache-2.0 (this document ships with the [`garter`](https://crates.io/crates/garter) reference implementation)

The document version tracks `MAJOR.MINOR`; the on-the-wire `protocol`
field carries a full three-component semver (`sitrep-MAJOR.MINOR.PATCH`).
The two move together: a `MAJOR.MINOR` revision of this document
corresponds to a wire `protocol` whose `MAJOR.MINOR` match.

## Abstract

sitrep is a one-way, line-delimited JSON control stream that a SIP003 /
SIP003u shadowsocks plugin emits on its standard output so the process
that spawned it (the "host") learns the plugin's readiness, its actual
bound listen address, the transports it serves, and any typed start
failure. It replaces the brittle older approach of TCP-connect-probing
the plugin's port and scraping the plugin's human-readable log output.

## Motivation

A host that supervises a SIP003 plugin needs to know three things before
it can route traffic: did the plugin come up, where did it actually
bind, and — if it did not come up — why. The pre-sitrep approach
answered these by connect-probing a presumed port and reading the
plugin's logs. Both fail in ways that sitrep is designed to remove:

- **Single-address probing cannot see inner-hop readiness in a
  multi-plugin chain.** When several plugins are composed end to end,
  a successful TCP connect to the chain's public-facing port does not
  prove that an *inner* hop finished binding; the connect can succeed
  against a half-initialized chain, or fail spuriously against one that
  is merely slow.

- **A connect probe cannot distinguish "starting" from "exited."** A
  refused connection looks the same whether the plugin is still binding
  its listener or has already crashed. The host is forced to guess with
  a timer, which is both racy and slow.

- **Bind-failure causes are lost to localized OS log text.** When a
  bind fails, the only signal in the old model is free-form text in the
  plugin's log, whose wording and language vary by platform and locale.
  A host cannot reliably parse it to recover the structured fact
  ("address already in use") that it needs to drive a retry decision.

sitrep gives the host these facts directly, as typed events, on a
dedicated control channel.

## Conventions

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL
NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and
**OPTIONAL** in this document are to be interpreted as described in
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

Throughout this document:

- **host** — the process that spawned the plugin and supervises its
  startup (e.g. a shadowsocks client, a chain runner).
- **plugin** — the SIP003 child process the host spawned.

## Transport

sitrep travels on the plugin's **standard output**. It is a control
channel, not the data plane: it carries no proxied traffic and never
the bytes of any tunneled connection.

Conformance is specified separately for producers (plugins) and
consumers (hosts) so an implementer of either side knows exactly what
it owes.

### Producer (plugin) conformance

- A plugin that speaks sitrep **MUST** emit, on standard output,
  newline-delimited UTF-8 JSON objects and nothing else.
- The **first** stdout line **MUST** be the `hello` handshake event.
- After `hello`, the plugin **MUST NOT** emit any non-JSON line on
  stdout.
- Standard error is unconstrained: it carries the plugin's
  human-readable logs and is not part of the sitrep stream.

### Consumer (host) conformance

- A host **SHOULD** tolerate a non-JSON stdout line by treating it as a
  log line rather than a protocol error. This is Postel's law: it keeps
  the host robust against a noncompliant or pre-sitrep producer.
- A host **MUST** ignore unknown `event` values and unknown object
  fields, so that a future minor revision that adds events or fields
  does not break an older consumer (forward compatibility — see
  [Versioning](#versioning) and [Unknown-event
  handling](#unknown-event-handling)).
- The wire carries no "I exited" event. A host **MUST** therefore
  detect plugin process exit and stdout end-of-file out of band (by
  observing the child process and its stdout pipe), and apply the
  [absence backstop](#event-ordering-and-the-absence-backstop).

## Framing

The stream is one JSON object per line, separated by a single `\n`
(`U+000A`). Each object has a string field named `event` that is the
discriminant identifying the event type; the remaining fields depend on
the event. Lines are independent: there is no enclosing array and no
inter-line state beyond the ordering rules in this document.

## Versioning

The wire `protocol` field is the string `"sitrep-<semver>"`, where
`<semver>` is a full three-component semantic version
(`MAJOR.MINOR.PATCH`). This document's own version tracks `MAJOR.MINOR`.

Compatibility is gated on **MAJOR**:

- **MAJOR** — incompatible wire change. A consumer that does not
  recognize a producer's MAJOR cannot assume any event shape.
- **MINOR** — additive only: new events or new fields. Older consumers
  ignore what they do not recognize and keep working
  ([forward compatibility](#unknown-event-handling)).
- **PATCH** — no wire-visible change (clarifications, implementation
  fixes). It does not affect interoperability.

### Scope of the unknown-MAJOR fallback rule

There are two host models, and the "unrecognized MAJOR" rule binds only
one of them. An implementer must know which model their host uses.

- **Detection host (capability auto-detection).** A host that decides
  *whether* a plugin speaks sitrep — by inspecting `hello` — is
  performing capability auto-detection. Such a host, on encountering a
  MAJOR it does not recognize, **MUST** fall back to its non-sitrep
  readiness behavior (e.g. its prior connect-probe), and **MUST NOT**
  hard-fail. The plugin might be speaking a newer protocol the host
  genuinely cannot interpret; refusing to start it would be a regression
  against the pre-sitrep baseline.

  Detection can be done two ways. *First-line sniffing* reads the first
  stdout line and classifies on it — but a non-sitrep plugin that is
  **silent on stdout** never produces a line to classify, so a pure
  sniffing host would hang waiting for one. The robust alternative is to
  run the non-sitrep readiness probe **concurrently** with the sitrep
  reader from the start (sharing a single send-once readiness slot) and
  let a recognized `hello` *stand the probe down*; a plugin that emits no
  `hello` (silent or not) is then readied by the probe with no timeout.
  Because a `bind_conflict` plugin never binds its listener, the
  concurrent connect-probe can never win that race — `bind_conflict`
  remains the deterministic outcome.

- **Preselection host (out-of-band configuration).** A host that was
  told by configuration that a specific plugin speaks sitrep is *not*
  performing detection; the unrecognized-MAJOR fallback clause does not
  bind it. Such a host **MAY** treat an unknown MAJOR from a plugin it
  was configured to expect as sitrep-speaking as a `fatal`-class start
  error, because the mismatch indicates a misconfiguration or a plugin
  upgrade the operator has not accounted for.

## Event catalog

This is the normative core. Each event below specifies when it MUST or
MAY be emitted, the type of each field, and a pinned illustrative
example line. The example lines are illustrative of *shape*; a value
shown as platform-specific (notably `errno`) is **not** normative.

### The `errno` field

Several failure events carry `errno`: a **signed integer** holding the
platform-native OS error code for the failure (for example, the
"address already in use" condition is `48` on macOS, `98` on Linux, and
`10048` on Windows). Because the same condition has different numeric
codes on different platforms:

- A host **SHOULD** classify the failure by its own platform's
  semantics.
- A host **MUST NOT** compare the number across platforms (a Linux host
  must not assume `48` means the same thing it does on macOS).
- A host treats `0` — or an absent `errno` where the field is optional
  — as "unknown."

### `hello`

The handshake. **MUST** be the first line a sitrep producer emits.

| Field      | Type   | Required | Meaning                          |
| ---------- | ------ | -------- | -------------------------------- |
| `event`    | string | yes      | Literal `"hello"`.               |
| `protocol` | string | yes      | `"sitrep-<semver>"` (see above). |

Example (illustrative):

```json
{"event":"hello","protocol":"sitrep-1.0.0"}
```

### `ready`

Emitted **once** the plugin's listener is bound and accepting
connections. It reports the authoritative bound address and the
transports actually served.

| Field        | Type     | Required | Meaning                                                       |
| ------------ | -------- | -------- | ------------------------------------------------------------- |
| `event`      | string   | yes      | Literal `"ready"`.                                            |
| `listen`     | string   | yes      | The authoritative bound address as `"ip:port"`.               |
| `transports` | [string] | yes      | Non-empty array of lowercase transport names actually served. |

`listen` is the address the plugin actually bound, not the address it
was asked to bind. This enables the OS-assigned-port pattern: a plugin
told to bind port `0` lets the kernel choose a free port and reports
the chosen `ip:port` back in `listen`, and the host learns where to
connect without a side channel.

`transports` lists lowercase transport names — currently `"tcp"` and
`"udp"`. A consumer **MUST** ignore transport names it does not
recognize (forward compatibility, the same rule as for unknown events
and fields).

**Empty `transports` is illegal.** A plugin **MUST** list at least one
transport in `ready`. A host **MUST** treat a `ready` whose
`transports` is empty — or whose every entry is an unrecognized name,
leaving nothing the host can use — as a `fatal`-class failure, **not**
as "the plugin came up but serves nothing." A listener that serves no
usable transport is not ready in any sense the host can act on.

Example (illustrative):

```json
{"event":"ready","listen":"127.0.0.1:1984","transports":["tcp"]}
```

### `bind_conflict`

Emitted when the plugin's listener failed to bind. This is a terminal
start failure.

| Field   | Type   | Required | Meaning                                        |
| ------- | ------ | -------- | ---------------------------------------------- |
| `event` | string | yes      | Literal `"bind_conflict"`.                     |
| `errno` | int    | yes      | Platform-native OS error code; `0` if unknown. |
| `addr`  | string | yes      | The `"ip:port"` the plugin attempted to bind.  |

`errno` is **always present** on `bind_conflict`; a producer that
cannot determine the OS error code **MUST** emit `0` rather than omit
the field.

Example (illustrative — the `errno` shown is the macOS code for
address-in-use):

```json
{"event":"bind_conflict","errno":48,"addr":"127.0.0.1:1984"}
```

### `fatal`

A terminal start failure that is not specifically a bind conflict
(invalid configuration, a failed upstream dial during startup, an
internal error, and so on).

| Field    | Type   | Required | Meaning                                          |
| -------- | ------ | -------- | ------------------------------------------------ |
| `event`  | string | yes      | Literal `"fatal"`.                               |
| `detail` | string | yes      | Human-readable description of the failure.       |
| `errno`  | int    | no       | Platform-native OS error code, when one applies. |

Unlike `bind_conflict`, the `errno` key on `fatal` is **omitted** when
no OS error code applies or it is unknown (rather than emitted as `0`).

Example (illustrative):

```json
{"event":"fatal","detail":"config invalid"}
```

### Event ordering and the absence backstop

Before entering its long-lived serving phase, a plugin **MUST** emit
exactly one of:

- a `ready` event (startup succeeded), **or**
- a failure event — `bind_conflict` or `fatal` (startup failed).

A plugin **MAY** exit without emitting any event at all (for example,
it crashed before it could report). The wire carries no "I exited"
event by design. The host therefore detects this case out of band, via
stdout end-of-file / process exit, and **MUST** treat it as a terminal
start failure. This is the **absence backstop**: the absence of both
`ready` and a failure event, observed as the stream ending, is itself
the terminal signal.

## Unknown-event handling

Two rules appear to pull in opposite directions; they do not, and this
section reconciles them explicitly.

1. **Unknown `event` values are ignored** (non-terminal). This is what
   makes MINOR revisions additive: an older host skips an event type it
   was not written to understand and keeps waiting.

1. **The host defaults to terminal on an unexpected startup failure**
   (via the absence backstop above).

These do not conflict, because a host **never** derives a terminal
decision by *inferring meaning* from an ignored unknown event. A future
protocol version that needs to signal a new unrecoverable state
**MUST** do so by *also* ceasing to emit `ready` and then exiting —
which triggers the absence backstop. The host's terminal decision
always comes from the absence backstop (`ready`/failure absent + stream
ended), and never from guessing at the semantics of an event it does
not recognize. An unknown event, on its own, is silence as far as the
terminal decision is concerned.

## Host obligations

A host supervising a sitrep plugin's startup **MUST** await exactly one
of three mutually exclusive outcomes:

- a `ready` event,
- a failure event (`bind_conflict` or `fatal`), or
- stdout end-of-file / process exit (the absence backstop).

The host then maps the outcome onto **its own** retry policy. sitrep
deliberately carries facts, not directives: there is no `retryable`
field. The protocol tells the host *what happened* (the listener bound
at this address; the bind failed with this OS error code; the plugin
exited without reporting); the host alone decides whether and how to
retry, using its own platform knowledge and configuration. Two hosts
observing the same `bind_conflict` may legitimately choose different
responses, and the protocol does not constrain that choice.

## Security considerations

- **stdout is a local IPC side-channel, never the wire.** sitrep is
  exchanged between a parent process and its child over an inherited
  pipe; it is not transmitted over any network and is not part of the
  proxied data plane.
- **sitrep MUST NOT alter the plugin's network or data-plane
  behavior.** Speaking sitrep is purely a reporting concern; it changes
  what the plugin says on stdout, never what bytes it puts on the wire
  or how it handles tunneled traffic.
- **A host MUST NOT trust `listen` to point outside the
  loopback/host-controlled range it expects.** The `listen` value comes
  from the (possibly buggy or hostile) child. A host that intends to
  connect to a loopback listener **MUST** validate that the reported
  address falls within the range it controls before connecting, so a
  malformed or malicious `listen` cannot redirect the host's
  connections to an unintended destination.

## Reference implementation

[`garter`](https://crates.io/crates/garter) is the reference
implementation of sitrep. Its sitrep module (`src/sitrep.rs`) defines
the wire types and the `SITREP_PROTOCOL` constant (`"sitrep-1.0.0"`).

Conforming emitters in the Hole workspace: the `mock-plugin` test
plugin, the `galoshes` SIP003u plugin, and the `ex-ray` plugin. The
protocol is independently adoptable: any
SIP003 / SIP003u plugin or host may implement it without depending on
`garter`.

## Appendix A — JSON schema (per-event field tables)

Every event object has a string `event` field that discriminates the
type. Consumers ignore unknown `event` values and unknown fields.

**`hello`**

| Field      | Type               | Required |
| ---------- | ------------------ | -------- |
| `event`    | string (`"hello"`) | yes      |
| `protocol` | string             | yes      |

**`ready`**

| Field        | Type                                   | Required |
| ------------ | -------------------------------------- | -------- |
| `event`      | string (`"ready"`)                     | yes      |
| `listen`     | string (`"ip:port"`)                   | yes      |
| `transports` | array of string (non-empty, lowercase) | yes      |

**`bind_conflict`**

| Field   | Type                        | Required |
| ------- | --------------------------- | -------- |
| `event` | string (`"bind_conflict"`)  | yes      |
| `errno` | int (signed; `0` = unknown) | yes      |
| `addr`  | string (`"ip:port"`)        | yes      |

**`fatal`**

| Field    | Type               | Required                  |
| -------- | ------------------ | ------------------------- |
| `event`  | string (`"fatal"`) | yes                       |
| `detail` | string             | yes                       |
| `errno`  | int (signed)       | no — omitted when unknown |

## Appendix B — Worked transcripts

The lines below are byte-identical to the pinned examples in the
[Event catalog](#event-catalog).

**Successful startup** — `hello`, then `ready`:

```json
{"event":"hello","protocol":"sitrep-1.0.0"}
{"event":"ready","listen":"127.0.0.1:1984","transports":["tcp"]}
```

The host reads `hello`, recognizes the MAJOR, awaits readiness, reads
`ready`, and connects to `127.0.0.1:1984`.

**Failing startup** — `hello`, then `bind_conflict`, then the plugin
exits:

```json
{"event":"hello","protocol":"sitrep-1.0.0"}
{"event":"bind_conflict","errno":48,"addr":"127.0.0.1:1984"}
```

After `bind_conflict` the plugin exits; the host observed a terminal
failure event and maps the (platform-native) `errno` onto its own
retry policy. Had the plugin instead crashed silently after `hello`,
the host would observe stdout end-of-file with neither `ready` nor a
failure event and apply the absence backstop — also a terminal
failure.

## Changelog

- **1.0** (Draft) — initial protocol: `hello`, `ready`, `bind_conflict`,
  `fatal` events; absence backstop; MAJOR-gated compatibility.

## Acknowledgements

sitrep was developed for the [Hole](https://github.com/bindreams/hole)
shadowsocks client to replace connect-probe + log-scrape plugin
readiness detection, and is published with `garter` as an independently
adoptable standard.
