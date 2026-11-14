# Server-address redaction

Hole is used where the address of the server is the most sensitive value on the machine, so no log file, console, toast
or support bundle may hold it. The mechanism has two halves that work at opposite ends: a **sink** that replaces the
address in every byte written to a log, and **types** that make it hard to write the address or the password into a
format string in the first place. This page is for a developer who logs, serializes or parses anything that can hold a
server entry. It ends with the limits, which are part of the contract.

The address is the configured host, a hostname or an IP literal, in every textual form, plus the IP address the bridge
resolved for it over {term}`DoH`. The password is protected by the types alone (see [the password](#the-password)).

## Why the sink carries the weight

The default log filter is a global `info`, so every crate in the process can write a line, third-party ones included, and
so can a plugin whose stderr is relayed and an operating-system command whose argv is logged. The set of code that can
write an address is not enumerable. Redacting at each call site covers the sites someone thought of; a sink covers bytes.

## The registry

{src}`crates/util/src/redact.rs` holds a process-global registry of armed literals. Reads are lock-free (an `ArcSwap` over
an immutable snapshot), so no logging call can block behind a concurrent arm. Matching is an `aho-corasick` automaton,
leftmost-longest and ASCII-case-insensitive: with `10.0.0.1` and `10.0.0.12` both armed, the longer one wins, so no
trailing byte leaks and the line is not attributed to the wrong entry.

`RedactingWriter` wraps a writer so that everything written through it is redacted. `init_dual` wraps four non-blocking
writers, and **exactly one of them is a log file**: the `DirRotate` appender ([logging](logging.md#where-the-logs-go)).
Wrapping it closes the file leak. The other three (the stderr layer and the two stdio relay tees) feed a developer's
terminal, which the redaction cannot reopen either way. `RedactingWriter::write` returns the count of *input* bytes: a
count of output bytes would panic `write_all`'s loop on the logging worker thread, since redaction changes the length.

## What is armed

`arm_server` ({src}`crates/common/src/logging/redact_arm.rs`) derives, from the entry's `server`:

- the value as configured, and the same without a trailing dot;
- its IDNA A-label (`idna::domain_to_ascii`);
- when it parses as an IP address, that address's canonical text.

`arm_resolved_ip` arms the address the DoH bootstrap resolved, bare and in the bracketed `[…]` form that `handoff_host`
writes for IPv6.

**Each candidate is filtered on its own**, not the configured value as a whole. A candidate is armed unless it is empty,
equals `localhost` ignoring case, or (after removing one pair of brackets) parses to a loopback or unspecified address.
The per-candidate rule matters: `server = "127.0.0.1."` does not parse as an IP address, so a filter on the whole value
passes it, and stripping the dot then arms the bare loopback address, which would turn every mention of loopback in the
process into a token.

An empty literal is never armed. An empty pattern matches at every position, which would replace every character of every
line.

## Tokens

An address becomes `<server:XXXXXXXX>`: the first eight hex characters of the entry's random UUID, never derived from the
address. For an id that is not a UUID the hex characters are used in order and padded, so the shape is constant.

Arming is keyed by literal, and **the last arm wins**. Re-arming a literal re-points it in place and logs one `info!`
that names both tokens and neither address, which is what joins the lines of one endpoint across two entries or two
sessions in a collected bundle. Entries are replaced, never appended, so the automaton stays bounded however many times
a long-running service arms.

### When a literal collides with Hole's own words

Nothing validates a configured host, so `server: "hole"` is reachable, and arming it would rewrite `hole-tun`,
`hole_bridge::proxy_manager` and the log directory path throughout the file. There is no principled threshold between
too short and fine, so `arm` does not guess. It checks the literal against `COLLISION_CORPUS` (a list of Hole's own
vocabulary: tracing targets, the TUN name, plugin binary names, the service log directories), **arms it anyway**, because
privacy does not yield to legibility, and logs one `warn!` that names the token and the collision. The corpus exists only
for that warning, so an incomplete corpus can weaken a diagnostic message and can never weaken redaction.

## Where the registry is armed

The registry starts empty, and these are the places that arm it:

| Where                                                                 | What it arms                             |
| --------------------------------------------------------------------- | ---------------------------------------- |
| The app, when it loads or saves the config (`arm_config`)             | Every entry, not only the selected one   |
| The bridge's `handle_start`, `handle_reload` and test-server handlers | The entry's configured address           |
| The command line, on a request it is about to send (`cli.rs`)         | The entry's configured address           |
| The DoH bootstrap, on every start including a held-cover retry        | The resolved IP, under the entry's token |

The bridge arms the configured address in its IPC handlers because a start itself arms only the resolved IP. The
support bundle is scrubbed with the app's registry.

## Prevention by type

`ServerAddress` and `Password` ({src}`crates/common/src/config.rs`, generated by `secret_newtype!` in
{src}`crates/common/src/secret_newtype.rs`) implement neither `Display` nor `Deref`. `server_host = %config.server.server`
is therefore a compile error, and `format!("{}", *addr)` cannot reopen it. `expose()` is the single named exit, so
`rg '\.expose\(\)'` lists every site that reads a real value. Both carry a hand-written `Debug` that prints
`<redacted>`, so a derived `Debug` on a container is not a hole, and a `Dump` impl tagged `dump::tag::SECRET`, which
renders as `[REDACTED]`.

That `Display` and `Deref` are **absent** is pinned by compile-fail probes
({src}`crates/common/tests/secret_shape/`, driven by `trybuild` from `the_secret_newtypes_have_no_second_exit`): adding
either impl compiles cleanly and fails no other test, so the shape needs a test of its own and not only a test of its
consequences.

### The password

Nothing arms the password into the registry. That is deliberate: a short password, or one that is a dictionary word,
armed into the global automaton would rewrite unrelated log text, with no bounded corpus to make it diagnosable. So for
the password prevention is the *whole* mechanism, and the two type rules above are load-bearing for it in a way they are
only a second line for the address.

### Where a secret enters

`UiServerEntry` ({src}`crates/hole/src/ui_settings.rs`) is where a password comes in from outside, as the payload of the
webview's `save_config`. It carries both newtypes from the deserializer inward, instead of wrapping them at the far end of
`apply`, because it derives `Debug` and every field between those two points would otherwise be renderable. The newtypes
are `#[serde(transparent)]`, so the payload's JSON shape is unchanged.

### `dump!` and a container that holds a secret

`dump!` ({src}`crates/dump/`) picks, per top-level expression, a `Dump` impl first, then `Serialize`, then `Debug`. It
does not pick per field. A `Serialize` type that transitively holds a `ServerAddress` or a `Password` and has no `Dump`
of its own is rendered through the serde tree, which shows the inner string, and the newtype's `Dump` is never reached.
So **every such type needs its own `Dump` impl.** They are `ServerEntry`, `AppConfig`, `ProxyConfig`,
`TestServerRequest`, `BridgeRequest`, and the bridge's persisted `Target`, `TargetFile`, `PersistedTarget` and
`StartupPreferenceFile`. The impls of `BridgeRequest` and `AppConfig` are exhaustive with no `_` arm, so a new field or
variant must say whether it carries a secret.

One type the rule reads as covering is deliberately not covered: `ImportOutcome`. `crates/hole` has no `dump` dependency,
so nothing there can call `dump!`, and adding the impl would mean adding the capability. All of this is convention backed
by a test per container. It is not a compiler guarantee, the sink is the backstop for the address, and nothing is behind
it for the password.

## Errors that quote their input

**Key material.** The 2022-blake3 ciphers take the password as base64 key material, so `ServerConfig::new` can reject it,
and the upstream `ServerConfigError`'s `Display` names the offending byte and its offset: one character of the user's key
and where to find it. `classify_key_material` ({src}`crates/bridge/src/proxy/config.rs`) is the one exhaustive match on
that type. It yields a `KeyMaterialFault`, a closed set of causes with no decode detail, carried by
`ProxyError::InvalidKeyMaterial`. `build_ss_config` and `server_test` both route through it. The variant is separate from
`InvalidMethod`: a cipher name Hole does not know and a good cipher with a bad key are different faults in different
fields.

**A parse error.** `serde_json::Error`'s `Display` quotes the input back, either the offending value or an arbitrary
string from an unknown variant or field, and nearly every JSON the workspace parses can hold a protected value: the
config, an imported profile, the elevation payload (a whole `BridgeRequest` in transit), and the bridge's state files.
Of those, `bridge-target.json` and `bridge-startup.json` hold a password, `bridge-routes.json` holds the server IP, and
`bridge-lockdown-pf.json` holds a captured pf ruleset that can contain the address. `ParseFailure` and
`describe_parse_error` ({src}`crates/util/src/parse_error.rs`) are the one door: a category plus a line and column, never a
fragment. They live in `util` because `tun-engine` parses two of those files and does not depend on `hole-common`;
`hole_common::config` re-exports them. `ConfigError::Parse` and `ImportError::Parse` go further and drop the
`serde_json::Error`, carrying the same scalars as fields, so neither their `Display` nor their derived `Debug` can echo
the input.

The state-file and elevation sites are the sharp ones, because nothing may be armed when they run: the elevation arms only
after a successful parse, and the crash-recovery sweep runs before any session exists. On those paths the address has no
sink-level backstop either.

## What a Hole-written line says instead

A line Hole authors names the server by `server` (the token), `server_kind` (`domain`, `ipv4` or `ipv6`), `server_family`,
`server_scope` (`global`, `private`, `loopback` or `link_local`) and the unchanged `server_port`. The diagnoses this
project has needed turned on those fields, not on the address. Output the project does not author, such as the joined
`route` and `netsh` argv, the ETW `remote` field and the plugin relay, is deliberately given no per-site edit: the sink
covers it, and hand-redaction there would rot. Text that leaves the bridge through the IPC (an error body, a death
reason) passes through `redact_str` explicitly.

## Limits

This is not a total guarantee.

1. **Nothing is armed before the first arm.** The sink redacts what the registry holds, and the registry starts empty. A
   line written before any arm is not redacted. [Crash recovery](crash-recovery.md) runs before any session exists and logs the recovered
   routes' server IP (`recovering routes from crashed run`), and a bridge that reconnects at boot from its persisted
   target arms the resolved IP only, not the configured host, until the app sends a request that arms it.
1. **`dump!` is convention, not a compiler guarantee**, as above.
1. **An address in a form no armed literal is a byte-substring of is not redacted**: a percent- or punycode-escaped form
   from a third-party process, or a non-canonical IPv6 text form from a peer that is not Rust's `std`.
1. **`shadowsocks_service=trace` writes the password to `bridge.log` in clear.** `shadowsocks::ServerConfig` derives
   `Debug` over a cleartext `password: String`, and `shadowsocks_service` renders it: `local/mod.rs` logs
   `{:?}` of the whole config at `trace` when the local server is constructed, and two `trace!` calls in
   `local/dns/server.rs` render a server config. `expose()` hands upstream a `String` it is entitled to keep, no newtype
   on Hole's side can reach that, and the password has no sink-level cure. The directive is not obscure:
   `init_multi`'s own example in {src}`crates/common/src/logging.rs` is
   `HOLE_BRIDGE_LOG=hole_bridge=debug,shadowsocks_service=trace`, and `bridge.log` is collected into the support bundle.

```{admonition} Do not enable shadowsocks_service=trace against a real server
---
class: warning
---
Do not turn the directive on against a real server, and do not ship a bundle collected while it was on. Flooring the
third-party directive in `build_filter` would close the leak at the cost of the diagnostic, and that trade has not been
made.
```

## Files that already exist, and the support bundle

Files already on disk are not rewritten: a privileged bridge rewriting files in a directory the user can write is an
attack surface. The support bundle ({src}`crates/hole/src/log_collector.rs`) is scrubbed **when it is collected**, line by
line as bytes (a relayed plugin line can carry any byte), with the app's registry, and it contains a `REDACTION.txt`
that states its own residuals: lines written before redaction existed may hold a resolved IP, which the app never holds
because the bridge resolved it; a server deleted since is not in the registry; and files taken from the service log
directory were scrubbed with that same hostname-only registry.
