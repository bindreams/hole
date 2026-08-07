package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
)

// Args maps a string key to a list of values. It is similar to url.Values.
type Args map[string][]string

// Get returns the first value for key, or ("", false) if absent. Use the map
// directly for multiple values.
func (args Args) Get(key string) (value string, ok bool) {
	if args == nil {
		return "", false
	}
	vals, ok := args[key]
	if !ok || len(vals) == 0 {
		return "", false
	}
	return vals[0], true
}

// Append value to the list of values for key.
func (args Args) Add(key, value string) {
	args[key] = append(args[key], value)
}

// Return the index of the next unescaped byte in s that is in the term set, or
// else the length of the string if no terminators appear. Additionally return
// the unescaped string up to the returned index.
func indexUnescaped(s string, term []byte) (int, string, error) {
	var i int
	unesc := make([]byte, 0)
	for i = 0; i < len(s); i++ {
		b := s[i]
		// A terminator byte?
		if bytes.IndexByte(term, b) != -1 {
			break
		}
		if b == '\\' {
			i++
			if i >= len(s) {
				return 0, "", errors.New("plugin options end in an unpaired backslash")
			}
			b = s[i]
		}
		unesc = append(unesc, b)
	}
	return i, string(unesc), nil
}

// Parse SS_PLUGIN options from environment variables. SS_PLUGIN_OPTIONS is
// always validated via parsePluginOptions, independently of whether the
// SS_* chain-handoff vars below are present. The SS_*-derived addresses
// are added to opts only when all four vars are present; a partial set
// (some but not all four -- never a legitimate invocation shape, per the
// SIP003 contract every real caller follows) is fatal, matching every
// other illegitimate-input-state this file rejects, rather than silently
// falling back to whatever SS_PLUGIN_OPTIONS/flag defaults happen to
// supply for all four of localAddr/localPort/remoteAddr/remotePort at
// once. A fully-absent set is the legitimate standalone-invocation case
// and is not an error.
func parseEnv() (opts Args, err error) {
	otherOpts, err := parsePluginOptions(os.Getenv("SS_PLUGIN_OPTIONS"))
	if err != nil {
		return nil, err
	}

	opts = make(Args)
	for k, v := range otherOpts {
		opts[k] = v
	}

	// LookupEnv, not Getenv: presence (the var was exported at all, even
	// as "") is what distinguishes "a caller attempted the chain-handoff
	// protocol and got it wrong" (partial, fatal) from "no caller ever
	// mentioned SS_* at all" (the standalone case, not an error).
	// os.Getenv can't tell those apart -- it returns "" for both an unset
	// var and one explicitly exported empty, so `SS_REMOTE_PORT=` with
	// the other three genuinely unset used to read as fully standalone.
	ssRemoteHost, remoteHostSet := os.LookupEnv("SS_REMOTE_HOST")
	ssRemotePort, remotePortSet := os.LookupEnv("SS_REMOTE_PORT")
	ssLocalHost, localHostSet := os.LookupEnv("SS_LOCAL_HOST")
	ssLocalPort, localPortSet := os.LookupEnv("SS_LOCAL_PORT")
	allUsable := ssRemoteHost != "" && ssRemotePort != "" && ssLocalHost != "" && ssLocalPort != ""
	if !allUsable {
		if remoteHostSet || remotePortSet || localHostSet || localPortSet {
			// Env var names only -- never operator/secret content, safe to
			// name directly.
			return nil, errors.New("SS_* chain-handoff env is incomplete: some but not all of SS_REMOTE_HOST/SS_REMOTE_PORT/SS_LOCAL_HOST/SS_LOCAL_PORT are set")
		}
		return opts, nil
	}

	opts.Add("remoteAddr", ssRemoteHost)
	opts.Add("remotePort", ssRemotePort)
	opts.Add("localAddr", ssLocalHost)
	opts.Add("localPort", ssLocalPort)
	return opts, nil
}

// parsePluginOptions parses a SS_PLUGIN_OPTIONS k=v;k=v string (';', '=', '\\'
// are backslash-escaped). Example: secret=nou;cache=/tmp/cache;secret=yes
func parsePluginOptions(s string) (opts Args, err error) {
	opts = make(Args)
	if len(s) == 0 {
		return
	}
	i := 0
	for segmentIndex := 0; ; segmentIndex++ {
		var key, value string
		var offset int

		if i >= len(s) {
			break
		}
		offset, key, err = indexUnescaped(s[i:], []byte{'=', ';'})
		if err != nil {
			return
		}
		if len(key) == 0 {
			// No segment content in the message: a value can carry a secret.
			// Mirrors crates/garter/src/sip003.rs's MalformedOptions::EmptyKey.
			err = fmt.Errorf("plugin options segment %d has no key", segmentIndex)
			return
		}
		i += offset
		if i >= len(s) || s[i] != '=' {
			opts.Add(key, "1")
			i++
			continue
		}
		i++
		offset, value, err = indexUnescaped(s[i:], []byte{';'})
		if err != nil {
			return
		}
		i += offset
		opts.Add(key, value)
		i++
	}
	return opts, nil
}
