package main

import "testing"

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
// both rather than rewriting them, because ex-ray discards the whole options
// string here and silently reverts every flag to its default.
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
