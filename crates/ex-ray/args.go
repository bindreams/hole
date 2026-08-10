package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
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

// parseEnv validates SS_PLUGIN_OPTIONS and, if present, the SS_*
// chain-handoff vars -- a partial SS_* set is fatal (see below); the
// standalone/fully-complete cases are not.
func parseEnv() (opts Args, err error) {
	otherOpts, err := parsePluginOptions(os.Getenv("SS_PLUGIN_OPTIONS"))
	if err != nil {
		return nil, err
	}

	opts = make(Args)
	for k, v := range otherOpts {
		opts[k] = v
	}

	// LookupEnv, not Getenv: Getenv can't tell an unset var from one
	// exported empty, and that distinction drives the partial-vs-absent
	// check below.
	ssRemoteHost, remoteHostSet := os.LookupEnv("SS_REMOTE_HOST")
	ssRemotePort, remotePortSet := os.LookupEnv("SS_REMOTE_PORT")
	ssLocalHost, localHostSet := os.LookupEnv("SS_LOCAL_HOST")
	ssLocalPort, localPortSet := os.LookupEnv("SS_LOCAL_PORT")

	// unset and empty are reported separately: a var that is exported but
	// blank is a materially different operator mistake (e.g. an empty-
	// string default in a wrapping script) than one never mentioned at
	// all, and conflating them into a single "some but not all are set"
	// message is actively misleading when every var IS set, just to "".
	vars := [...]struct {
		name string
		val  string
		set  bool
	}{
		{"SS_REMOTE_HOST", ssRemoteHost, remoteHostSet},
		{"SS_REMOTE_PORT", ssRemotePort, remotePortSet},
		{"SS_LOCAL_HOST", ssLocalHost, localHostSet},
		{"SS_LOCAL_PORT", ssLocalPort, localPortSet},
	}
	var unset, empty []string
	for _, v := range vars {
		switch {
		case !v.set:
			unset = append(unset, v.name)
		case v.val == "":
			empty = append(empty, v.name)
		}
	}
	if len(unset) == len(vars) {
		// Fully absent: the legitimate standalone-invocation case.
		return opts, nil
	}
	if len(unset) > 0 || len(empty) > 0 {
		var detail []string
		if len(unset) > 0 {
			detail = append(detail, fmt.Sprintf("unset: %s", strings.Join(unset, ", ")))
		}
		if len(empty) > 0 {
			detail = append(detail, fmt.Sprintf("set but empty: %s", strings.Join(empty, ", ")))
		}
		// Env var names only -- never operator/secret content, safe to
		// name directly.
		return nil, fmt.Errorf("SS_* chain-handoff env is incomplete (%s)", strings.Join(detail, "; "))
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
