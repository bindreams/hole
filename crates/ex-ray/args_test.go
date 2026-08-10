package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// Get returns the FIRST value for a key. The bridge removes a user's copy before
// appending its own precisely because of this; if it ever became last-wins, that
// strip would be pointless and this test is where the change is noticed.
func TestPluginOptionsGetIsFirstWins(t *testing.T) {
	opts, err := parsePluginOptions("ech-doh=https://first.example/dns-query;ech-doh=https://second.example/dns-query")
	if err != nil {
		t.Fatalf("parsePluginOptions returned error: %v", err)
	}
	got, ok := opts.Get("ech-doh")
	if !ok {
		t.Fatal(`Get("ech-doh") reported the key absent`)
	}
	if want := "https://first.example/dns-query"; got != want {
		t.Errorf(`Get("ech-doh") = %q, want %q (the first occurrence)`, got, want)
	}
}

// A backslash escapes whatever byte follows, so `ech\-doh` IS `ech-doh` here.
// The bridge's strip matches keys under this rule; if it used a narrower one, a
// user could hide a duplicate from the strip and win under first-wins.
func TestBackslashEscapesAnyByteInAKey(t *testing.T) {
	opts, err := parsePluginOptions(`ech\-doh=https://evil.example/dns-query`)
	if err != nil {
		t.Fatalf("parsePluginOptions returned error: %v", err)
	}
	if got, ok := opts.Get("ech-doh"); !ok || got != "https://evil.example/dns-query" {
		t.Errorf(`Get("ech-doh") = %q, ok=%v; want the escaped spelling to decode to "ech-doh"`, got, ok)
	}
}

// A trailing unpaired backslash is fatal here, which is why garter refuses to
// append after one: doing so would make the string parse, with the appended
// directive swallowed into the preceding value instead of rejected.
func TestDanglingEscapeIsRejected(t *testing.T) {
	if _, err := parsePluginOptions(`path=/a\`); err == nil {
		t.Error("parsePluginOptions accepted a dangling trailing backslash")
	}
	// What a naive append would have produced: parses, but loglevel is GONE.
	opts, err := parsePluginOptions(`path=/a\;loglevel=debug`)
	if err != nil {
		t.Fatalf("parsePluginOptions returned error: %v", err)
	}
	if _, ok := opts.Get("loglevel"); ok {
		t.Error("expected the escaped separator to swallow loglevel")
	}
	if got, _ := opts.Get("path"); got != "/a;loglevel=debug" {
		t.Errorf(`Get("path") = %q, want "/a;loglevel=debug"`, got)
	}
}

// An empty key is fatal in either shape — `;;` or a leading `=`. garter rejects
// both rather than rewriting them, matching ex-ray's own fatal treatment of a
// malformed options string.
func TestEmptyKeyIsRejected(t *testing.T) {
	for _, s := range []string{"a=1;;b=2", "a=1;;", "=v", "host=h;=v;mux=0"} {
		if _, err := parsePluginOptions(s); err == nil {
			t.Errorf("parsePluginOptions(%q) accepted an empty key", s)
		}
	}
	// A TRAILING separator is not an empty key; garter normalizes it away
	// because appending after it would produce one.
	if _, err := parsePluginOptions("a=1;"); err != nil {
		t.Errorf(`parsePluginOptions("a=1;") rejected a trailing separator: %v`, err)
	}
}

// A bare key parses to "1", not "". The bridge preserves raw segments rather
// than re-serializing parsed pairs because no re-serializer can round-trip both
// this and an explicitly empty `key=`.
func TestBareKeyParsesAsOne(t *testing.T) {
	opts, err := parsePluginOptions("tls;path=")
	if err != nil {
		t.Fatalf("parsePluginOptions returned error: %v", err)
	}
	if got, _ := opts.Get("tls"); got != "1" {
		t.Errorf(`Get("tls") = %q, want "1"`, got)
	}
	if got, _ := opts.Get("path"); got != "" {
		t.Errorf(`Get("path") = %q, want ""`, got)
	}
}

// The exact string shape the bridge emits for a postern-issued config: the
// user's ech-doh removed, Hole's appended, the user's ech mode left alone.
func TestHoleComposedOptionsResolveToHolesValues(t *testing.T) {
	const composed = "host=example.com;tls;ech=always;loglevel=debug;ech-doh=https://1.1.1.1/dns-query"
	opts, err := parsePluginOptions(composed)
	if err != nil {
		t.Fatalf("parsePluginOptions returned error: %v", err)
	}
	for _, c := range []struct{ key, want string }{
		{"ech-doh", "https://1.1.1.1/dns-query"},
		{"loglevel", "debug"},
		{"ech", "always"},
		{"host", "example.com"},
		{"tls", "1"},
	} {
		got, ok := opts.Get(c.key)
		if !ok {
			t.Errorf("Get(%q) reported the key absent", c.key)
			continue
		}
		if got != c.want {
			t.Errorf("Get(%q) = %q, want %q", c.key, got, c.want)
		}
	}
}

// The exact wording, pinned so a future edit that reintroduces %q-formatted
// segment content is caught here. Matches crates/garter/src/sip003.rs's
// MalformedOptions::DanglingEscape.
func TestDanglingEscapeErrorText(t *testing.T) {
	_, err := parsePluginOptions(`path=/a\`)
	if err == nil {
		t.Fatal("parsePluginOptions returned nil error")
	}
	if got, want := err.Error(), "plugin options end in an unpaired backslash"; got != want {
		t.Errorf("error = %q, want %q", got, want)
	}
}

// Segment indices are 0-based over every ';'-delimited segment, counting
// valid ones too -- matches crates/garter/src/sip003.rs's
// MalformedOptions::EmptyKey{index}.
func TestEmptyKeyErrorNamesSegmentIndex(t *testing.T) {
	cases := []struct {
		desc      string
		s         string
		wantIndex int
	}{
		{"leading equals, first segment", "=v", 0},
		{"empty key after a valid segment", "host=h;=v", 1},
		{"empty segment between two valid ones", "host=h;;path=/", 1},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			_, err := parsePluginOptions(c.s)
			if err == nil {
				t.Fatalf("parsePluginOptions(%q) = nil error, want an error", c.s)
			}
			want := fmt.Sprintf("plugin options segment %d has no key", c.wantIndex)
			if err.Error() != want {
				t.Errorf("parsePluginOptions(%q) error = %q, want %q", c.s, err.Error(), want)
			}
		})
	}
}

// crates/garter/src/sip003.rs validates escape-pairing across the whole
// string before splitting into segments, so a string carrying BOTH an empty
// key and a dangling escape reports DanglingEscape there. This parser scans
// left to right and reports whichever fault it reaches first. For `;path=/a\`
// the empty first segment (leading ';') is reached before the scan ever
// gets to the trailing backslash, so THIS parser reports EmptyKey{0} instead.
// Pinned so a future edit to either parser's algorithm notices if the
// precedence changes.
func TestDualFaultReportsFirstReachedNotWholeStringPrepass(t *testing.T) {
	_, err := parsePluginOptions(`;path=/a\`)
	if err == nil {
		t.Fatal("parsePluginOptions returned nil error")
	}
	if got, want := err.Error(), "plugin options segment 0 has no key"; got != want {
		t.Errorf("error = %q, want %q", got, want)
	}
}

// A malformed options string reaches the fatal sitrep verbatim (main.go
// emits err.Error() as the `detail` field), so the error must never echo
// segment content -- a segment can carry a per-connection secret (a
// password, a cert). Mirrors crates/bridge/src/proxy/plugin.rs's own test
// of the same property one layer up.
//
// Only the dangling-escape shape can leak at all: the empty-key error
// names only the segment index (TestEmptyKeyErrorNamesSegmentIndex pins
// its exact wording), so there is no substring to probe there. The secret
// must be placed IN the segment whose value triggers the dangling escape
// (the LAST segment, ending in the unpaired backslash) -- an earlier,
// successfully-parsed segment would never reach the scan that produces
// this error.
func TestMalformedOptionsErrorsNeverEchoSegmentContent(t *testing.T) {
	cases := []struct {
		desc string
		s    string
	}{
		{"dangling escape", `path=/a;certRaw=SUPERSECRETVALUE\`},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			_, err := parsePluginOptions(c.s)
			if err == nil {
				t.Fatalf("parsePluginOptions(%q) = nil error, want an error", c.s)
			}
			if strings.Contains(err.Error(), "SUPERSECRETVALUE") {
				t.Errorf("parsePluginOptions(%q) error %q leaks segment content", c.s, err.Error())
			}
		})
	}
}

// unsetEnv genuinely removes an env var (restored via t.Cleanup), unlike
// t.Setenv(key, "") which exports it as present-but-empty -- a
// meaningfully different state parseEnv distinguishes (see
// TestParseEnvRejectsOnlyGenuinePartialSSEnv's "present but empty" case).
func unsetEnv(t *testing.T, key string) {
	t.Helper()
	orig, wasSet := os.LookupEnv(key)
	if wasSet {
		t.Cleanup(func() { _ = os.Setenv(key, orig) })
	}
	_ = os.Unsetenv(key)
}

// A partial SS_* set (some but not all four of SS_REMOTE_HOST/
// SS_REMOTE_PORT/SS_LOCAL_HOST/SS_LOCAL_PORT) is fatal -- it is never a
// legitimate invocation shape, and letting it fall back to
// SS_PLUGIN_OPTIONS/flag defaults for all four addresses at once is
// exactly the "silently broken but reports ready" class this file
// otherwise fails loud on. A fully-absent set (the standalone case) and a
// fully-complete set are both legitimate and must not error.
func TestParseEnvRejectsOnlyGenuinePartialSSEnv(t *testing.T) {
	const wantErrSubstr = "SS_* chain-handoff env is incomplete"

	t.Run("one var missing errors", func(t *testing.T) {
		t.Setenv("SS_REMOTE_HOST", "chain.example.net")
		unsetEnv(t, "SS_REMOTE_PORT")
		t.Setenv("SS_LOCAL_HOST", "10.1.2.3")
		t.Setenv("SS_LOCAL_PORT", "45999")
		t.Setenv("SS_PLUGIN_OPTIONS", "")
		_, err := parseEnv()
		if err == nil {
			t.Fatal("parseEnv() = nil error, want the incomplete-env error")
		}
		if !strings.Contains(err.Error(), wantErrSubstr) {
			t.Errorf("error = %q, want it to contain %q", err.Error(), wantErrSubstr)
		}
	})

	t.Run("three vars missing errors", func(t *testing.T) {
		unsetEnv(t, "SS_REMOTE_HOST")
		unsetEnv(t, "SS_REMOTE_PORT")
		unsetEnv(t, "SS_LOCAL_HOST")
		t.Setenv("SS_LOCAL_PORT", "45999")
		t.Setenv("SS_PLUGIN_OPTIONS", "")
		_, err := parseEnv()
		if err == nil {
			t.Fatal("parseEnv() = nil error, want the incomplete-env error")
		}
		if !strings.Contains(err.Error(), wantErrSubstr) {
			t.Errorf("error = %q, want it to contain %q", err.Error(), wantErrSubstr)
		}
	})

	// The one var that IS present is exported empty, not unset -- presence
	// (os.LookupEnv's ok), not value-emptiness, is what parseEnv keys the
	// partial-set determination on. Using os.Getenv (which can't tell an
	// unset var from one exported empty) would read this as fully
	// standalone and silently pass, exactly the gap this case pins.
	t.Run("one var present but empty, rest genuinely unset, errors", func(t *testing.T) {
		unsetEnv(t, "SS_REMOTE_HOST")
		t.Setenv("SS_REMOTE_PORT", "")
		unsetEnv(t, "SS_LOCAL_HOST")
		unsetEnv(t, "SS_LOCAL_PORT")
		t.Setenv("SS_PLUGIN_OPTIONS", "")
		_, err := parseEnv()
		if err == nil {
			t.Fatal("parseEnv() = nil error, want the incomplete-env error")
		}
		if !strings.Contains(err.Error(), wantErrSubstr) {
			t.Errorf("error = %q, want it to contain %q", err.Error(), wantErrSubstr)
		}
		// SS_REMOTE_HOST/SS_LOCAL_HOST/SS_LOCAL_PORT are genuinely unset;
		// SS_REMOTE_PORT is exported but blank -- the message must say so
		// accurately (not blanket "some but not all are set", which would
		// be true here but imprecise about which var is in which state).
		if !strings.Contains(err.Error(), "unset: SS_REMOTE_HOST, SS_LOCAL_HOST, SS_LOCAL_PORT") {
			t.Errorf("error = %q, want it to list the three unset vars", err.Error())
		}
		if !strings.Contains(err.Error(), "set but empty: SS_REMOTE_PORT") {
			t.Errorf("error = %q, want it to list SS_REMOTE_PORT as set but empty", err.Error())
		}
	})

	// All four ARE set (LookupEnv ok=true for each) -- "some but not all
	// … are set" would be a false statement here, since all of them are.
	// The message must instead say all four are present but blank.
	t.Run("all four present but empty errors, with an accurate message", func(t *testing.T) {
		for _, v := range []string{"SS_REMOTE_HOST", "SS_REMOTE_PORT", "SS_LOCAL_HOST", "SS_LOCAL_PORT"} {
			t.Setenv(v, "")
		}
		t.Setenv("SS_PLUGIN_OPTIONS", "")
		_, err := parseEnv()
		if err == nil {
			t.Fatal("parseEnv() = nil error, want the incomplete-env error")
		}
		if !strings.Contains(err.Error(), wantErrSubstr) {
			t.Errorf("error = %q, want it to contain %q", err.Error(), wantErrSubstr)
		}
		if strings.Contains(err.Error(), "unset:") {
			t.Errorf("error = %q, want no \"unset:\" clause -- all four vars ARE set", err.Error())
		}
		if !strings.Contains(err.Error(), "set but empty: SS_REMOTE_HOST, SS_REMOTE_PORT, SS_LOCAL_HOST, SS_LOCAL_PORT") {
			t.Errorf("error = %q, want it to list all four as set but empty", err.Error())
		}
	})

	t.Run("fully absent SS_* (standalone) is not an error", func(t *testing.T) {
		for _, v := range []string{"SS_REMOTE_HOST", "SS_REMOTE_PORT", "SS_LOCAL_HOST", "SS_LOCAL_PORT"} {
			unsetEnv(t, v)
		}
		t.Setenv("SS_PLUGIN_OPTIONS", "")
		if _, err := parseEnv(); err != nil {
			t.Errorf("parseEnv(): %v, want nil for a fully-standalone invocation", err)
		}
	})

	t.Run("fully complete SS_* is not an error", func(t *testing.T) {
		t.Setenv("SS_REMOTE_HOST", "chain.example.net")
		t.Setenv("SS_REMOTE_PORT", "9443")
		t.Setenv("SS_LOCAL_HOST", "10.1.2.3")
		t.Setenv("SS_LOCAL_PORT", "45999")
		t.Setenv("SS_PLUGIN_OPTIONS", "")
		opts, err := parseEnv()
		if err != nil {
			t.Fatalf("parseEnv(): %v, want nil when SS_* is complete", err)
		}
		if v, _ := opts.Get("remoteAddr"); v != "chain.example.net" {
			t.Errorf("remoteAddr = %q, want the SS_REMOTE_HOST-derived value", v)
		}
		if v, _ := opts.Get("remotePort"); v != "9443" {
			t.Errorf("remotePort = %q, want the SS_REMOTE_PORT-derived value", v)
		}
		if v, _ := opts.Get("localAddr"); v != "10.1.2.3" {
			t.Errorf("localAddr = %q, want the SS_LOCAL_HOST-derived value", v)
		}
		if v, _ := opts.Get("localPort"); v != "45999" {
			t.Errorf("localPort = %q, want the SS_LOCAL_PORT-derived value", v)
		}
	})
}
