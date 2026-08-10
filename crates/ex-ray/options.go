package main

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// parseIntOption reads a SIP003 option value from opts and applies it to
// dest, sharing one implementation across mux/tcp-keepalive/fwmark so the
// three can never silently drift apart.
//
// The rule: an absent key is a no-op, leaving dest at whatever it already
// held (dest holds whatever flag.Parse left there -- main() calls
// flag.Parse() before parseOptsIntoFlags runs -- the registered default
// when no CLI flag was passed, or the CLI-supplied value when one was).
// Any PRESENT value, empty included, must parse as an integer or the
// option is fatal: an explicitly empty value ("mux=") is not a documented
// "leave it alone" spelling, and treating it as one is actively dangerous
// for mux specifically -- galoshes' ex_ray_options appends `mux=0` and
// ex-ray is first-wins, so an operator's earlier bare `mux=` would win
// over galoshes' append and silently leave Mux.Cool at whatever default
// it already held (often ON), defeating the exact mechanism `mux=0` exists
// to guarantee. A BARE key (no `=` at all) is different: args.go's parser
// maps it to the literal string "1" for every option uniformly, so it
// goes through the same Atoi path as an explicit `=1` and sets dest to 1
// -- not "the default" for tcp-keepalive/fwmark, whose defaults are 15/0
// (see TestParseOptsIntoFlagsBareKeyResolvesToLiteralOne; fixing this
// needs args.go's Args type to distinguish a bare key from an explicit
// "=1", a grammar change not attempted here). A non-empty, non-numeric
// value is fatal and never echoes the rejected value: the escaping
// grammar lets a backslash absorb a later segment into a value, so an
// unparseable mux=abc\;certRaw=SECRET could otherwise leak certRaw's
// value through the mux error.
func parseIntOption(opts Args, key string, dest *int) error {
	c, ok := opts.Get(key)
	if !ok {
		return nil
	}
	i, err := strconv.Atoi(c)
	if err != nil {
		return newError(fmt.Sprintf("invalid %s: value is not an integer", key))
	}
	*dest = i
	return nil
}

// parseBoolOption reads a SIP003 presence option value from opts and
// applies it to dest. An explicitly empty value ("key=") is not a no-op
// here either -- only an absent key is. A bare
// key (no `=` at all) or an explicit "key=1" (args.go maps a bare key to
// the literal "1") is the only spelling that enables the flag; any other
// present value, empty included, is unrecognized and fatal. Inventing a
// wider vocabulary ("true"/"yes"/"on" as a heuristic) is exactly the kind
// of threshold that has no principled stopping point.
//
// The empty-value carve-out matters here specifically because these are
// presence-only options: garter's Mode::from_plugin_options treats
// presence of the `server` key, regardless of value, as server mode
// (crates/garter/src/chain_tests.rs). Treating `server=` as a no-op would
// leave *server false while garter still swapped the chain's SS_LOCAL/
// SS_REMOTE env vars for server mode, producing a silently-broken-but-
// reports-ready config: garter believes it is in server mode while ex-ray
// does not -- and fixing that properly needs a garter-side change, out of
// scope here. Rejecting `key=` outright avoids the disagreement without
// touching garter: ex-ray simply refuses to start.
//
// Never echoes the rejected value for the same reason parseIntOption
// doesn't.
func parseBoolOption(opts Args, key string, dest *bool) error {
	c, ok := opts.Get(key)
	if !ok {
		return nil
	}
	if c != "1" {
		return newError(fmt.Sprintf("invalid %s: value is not recognized", key))
	}
	*dest = true
	return nil
}

// parseEnumOption reads a SIP003 option value from opts and applies it to
// dest if it matches one of allowed, mirroring parseIntOption/
// parseBoolOption's structural rule: an absent key is a no-op; any
// PRESENT value, empty included, must be in allowed or the option is
// fatal. An empty value has no more claim to "not specified" here than an
// empty mux or tls value does. The allowed list is safe to name in the
// error (it's a small
// static vocabulary, not operator input) but the rejected value itself
// never is, for the same reason as every other option in this file.
func parseEnumOption(opts Args, key string, allowed []string, dest *string) error {
	c, ok := opts.Get(key)
	if !ok {
		return nil
	}
	for _, a := range allowed {
		if c == a {
			*dest = c
			return nil
		}
	}
	return newError(fmt.Sprintf("invalid %s: expected one of %s", key, strings.Join(allowed, ", ")))
}

// parseURLOption reads a SIP003 option value from opts and applies it to
// dest if it is a well-formed https:// URL. Unlike the other parse*Option
// helpers, an explicitly empty value is a legitimate, documented spelling
// here, not rejected: ech-doh's own flag description says "Empty disables
// ECH", so an empty value is applied (clearing dest) rather than treated
// as unrecognized. A malformed non-empty value is fatal: left unvalidated,
// a typo'd ech-doh silently disables ECH entirely (ech=auto) or leaves
// RequireEch armed with no way to ever satisfy it (ech=always), in both
// cases with ex-ray still reporting ready and no diagnostic reaching the
// sitrep. Never echoes the rejected value for the same reason the other
// parse*Option helpers don't.
func parseURLOption(opts Args, key string, dest *string) error {
	c, ok := opts.Get(key)
	if !ok {
		return nil
	}
	if c == "" {
		*dest = ""
		return nil
	}
	u, err := url.Parse(c)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return newError(fmt.Sprintf("invalid %s: value is not an https URL", key))
	}
	*dest = c
	return nil
}

// parseStringOption reads a SIP003 option value from opts and applies it
// to dest. An absent key is always a no-op, leaving dest untouched.
// Whether an explicitly empty value ("key=") is instead APPLIED (clearing
// dest to "") or fatal depends on emptyOK: pass true for options where
// the empty string is itself a meaningful, documented value -- cert/
// certRaw/key, where empty means "use the ~/.acme.sh default" (config.go's
// own fallback logic depends on this, the same way ech-doh's "empty
// disables ECH" does), so an explicit "cert=" deliberately clears a
// CLI-supplied -cert=/path -- and false for options with no legitimate
// "explicitly nothing" spelling (host, path, loglevel), where an empty
// value is exactly as unrecognized as an empty mux/tls value and must be
// fatal instead of silently clearing whatever was there.
//
// A BARE key (no `=` at all) is a separate, narrower gap this does NOT
// close: args.go's parser maps a bare key to the literal string "1" for
// every option uniformly (same as parseIntOption's doc comment
// documents for mux/tcp-keepalive/fwmark), so a fat-fingered bare `host`
// silently sets *host to "1" rather than failing loud. Fixing that needs
// the same args.go Args grammar change already tracked (not attempted
// here) to distinguish a bare key from an explicit "=1" -- this function
// only closes the explicitly-empty-value gap.
func parseStringOption(opts Args, key string, dest *string, emptyOK bool) error {
	c, ok := opts.Get(key)
	if !ok {
		return nil
	}
	if c == "" && !emptyOK {
		return newError(fmt.Sprintf("invalid %s: value must not be empty", key))
	}
	*dest = c
	return nil
}

// An unrecognized key (a typo, or a stale/removed option name) is
// deliberately NOT rejected here, unlike every other malformed shape in
// this file: ex-ray's SS_PLUGIN_OPTIONS string is shared with other
// first-party tools in the same process chain -- galoshes reads its own
// `udp_timeout` out of the operator-supplied options string (crates/
// galoshes/src/yamux.rs's parse_udp_timeout) but forwards the string to
// its embedded ex-ray verbatim otherwise, appending only `mux=0` (crates/
// galoshes/src/exray_options.rs), so `udp_timeout` itself still reaches
// ex-ray unstripped; the bridge likewise preserves arbitrary unrecognized
// keys when composing plugin options (crates/bridge/src/proxy/plugin.rs)
// -- and both rely on ex-ray's documented tolerance for keys it doesn't
// own. Rejecting unknown keys here would break that established, working
// contract for every caller that shares the string this way; closing the
// "typo silently ignored" gap instead needs coordination with those
// callers (an ex-ray-side allowlist that also names every externally-owned
// key, or a change on their side to strip their own keys before
// forwarding) rather than a unilateral ex-ray-only change.
