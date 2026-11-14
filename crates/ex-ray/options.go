package main

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Rules shared by the parse*Option helpers below, each of which applies one
// option from the parsed SS_PLUGIN_OPTIONS (Args) to a flag:
//   - An absent key leaves dest as it was: the flag's default, or the value
//     flag.Parse set from the command line.
//   - An invalid value is an error that never contains the value. The escaping
//     grammar lets a backslash absorb the following segments into one value
//     (`mux=abc\;certRaw=SECRET`), so a rejected value may hold a secret that
//     reaches the `fatal` sitrep.
//   - A bare key (no `=`) reads as "1" for every option alike (see
//     parsePluginOptions), so a bare `host` sets "1" and a bare `tcp-keepalive`
//     sets 1 rather than its default.
//   - An unrecognized key is deliberately not an error, unlike every malformed
//     shape here. SS_PLUGIN_OPTIONS is shared with other programs in the chain,
//     which read their own keys from it (galoshes' `udp_timeout`), so rejecting
//     unknown keys would break them.

// parseIntOption applies an integer option to dest, shared by mux,
// tcp-keepalive and fwmark. A present value, empty included, must parse as an
// integer or the option is fatal.
//
// An empty value (`mux=`) is rejected rather than treated as "leave it alone"
// because ex-ray is first-wins: galoshes appends `mux=0` to the options it
// hands ex-ray, so an operator's earlier empty `mux=` that was a no-op would
// win and leave Mux.Cool at its default of on, defeating that append.
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

// parseBoolOption applies a presence option to dest. Only a bare key or
// `key=1` enables it; any other present value, empty included, is fatal, and
// no other spelling ("true", "yes") is accepted.
//
// An empty value is rejected rather than ignored because garter's
// Mode::from_plugin_options (crates/garter/src/chain.rs) takes the mere
// presence of the `server` key as server mode, whatever its value. Ignoring
// `server=` would leave ex-ray in client mode while garter swapped the chain's
// SS_LOCAL and SS_REMOTE variables for server mode.
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

// parseEnumOption applies an option to dest if its value is one of allowed. A
// present value, empty included, outside allowed is fatal. The error names the
// allowed values (a fixed vocabulary), never the rejected one.
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

// parseURLOption applies an option to dest if its value is a well-formed https
// URL. Unlike the other helpers an empty value is valid and clears dest: the
// ech-doh flag's help says "Empty disables ECH.". A malformed non-empty value is
// fatal, because v2ray-core only logs a failed ECH config fetch: a typo'd ech-doh
// would silently disable ECH with ech=auto, or leave RequireEch armed and
// unsatisfiable with ech=always, in both cases with ex-ray reporting ready.
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

// parseStringOption applies a string option to dest. An empty value is
// applied (clearing dest) if emptyOK and fatal otherwise.
//
// emptyOK is for options where empty is a meaningful value: cert, certRaw and
// key, where it means "use the ~/.acme.sh default" and so can clear a
// command-line -cert. host, path and loglevel have no such spelling, and an
// empty value there would silently clear what was set.
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
