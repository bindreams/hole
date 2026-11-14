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

// Add appends value to the list of values for key.
func (args Args) Add(key, value string) {
	args[key] = append(args[key], value)
}

// indexUnescaped returns the index of the next unescaped byte in s that is in
// the term set, or the length of s if there is none, together with the
// unescaped text before that index. A backslash escapes the byte after it, any
// byte; one that ends s is an error.
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

// parseEnv returns the options in SS_PLUGIN_OPTIONS, plus remoteAddr, remotePort,
// localAddr and localPort taken from SS_REMOTE_HOST, SS_REMOTE_PORT,
// SS_LOCAL_HOST and SS_LOCAL_PORT. The four SS_* variables are all set (the
// plugin is chained) or all unset (standalone); a partial or blank set is an
// error. The errors name variables, never option values.
func parseEnv() (opts Args, err error) {
	otherOpts, err := parsePluginOptions(os.Getenv("SS_PLUGIN_OPTIONS"))
	if err != nil {
		return nil, err
	}

	opts = make(Args)
	for k, v := range otherOpts {
		opts[k] = v
	}

	// LookupEnv, not Getenv: the check below must tell an unset var from an empty one.
	ssRemoteHost, remoteHostSet := os.LookupEnv("SS_REMOTE_HOST")
	ssRemotePort, remotePortSet := os.LookupEnv("SS_REMOTE_PORT")
	ssLocalHost, localHostSet := os.LookupEnv("SS_LOCAL_HOST")
	ssLocalPort, localPortSet := os.LookupEnv("SS_LOCAL_PORT")

	// Unset and empty are reported separately, since "some are unset" would be
	// misleading when every var is set but blank.
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
		return nil, fmt.Errorf("SS_* chain-handoff env is incomplete (%s)", strings.Join(detail, "; "))
	}

	opts.Add("remoteAddr", ssRemoteHost)
	opts.Add("remotePort", ssRemotePort)
	opts.Add("localAddr", ssLocalHost)
	opts.Add("localPort", ssLocalPort)
	return opts, nil
}

// parsePluginOptions parses a SIP003 SS_PLUGIN_OPTIONS string of `key=value`
// segments separated by `;`, for example `secret=nou;cache=/tmp/cache;secret=yes`.
// A backslash escapes the next byte. A repeated key keeps every value in order
// (Args.Get returns the first). A key with no `=` is a bare key and its value is
// "1". A segment with an empty key, or a string ending in an unpaired
// backslash, is an error; the error never contains option content.
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
