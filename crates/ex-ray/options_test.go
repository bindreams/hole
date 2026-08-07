package main

import (
	"strings"
	"testing"
)

// flagSnapshot captures every package-level flag parseOptsIntoFlags can
// write, so a test can restore the exact pre-call state regardless of which
// keys its SS_PLUGIN_OPTIONS happens to touch. `version` is the only
// declared flag (config.go) parseOptsIntoFlags never writes, so it is
// excluded.
type flagSnapshot struct {
	mode, host, path, cert, certRaw, key, logLevel, echMode, echDoh string
	localAddrV, localPortV, remoteAddrV, remotePortV                string
	mux, fwmark, tcpKeepAliveV                                      int
	tlsEnabledV, serverV, fastOpenV, vpnV                           bool
}

func snapshotFlags() flagSnapshot {
	return flagSnapshot{
		mode: *mode, host: *host, path: *path, cert: *cert, certRaw: *certRaw, key: *key,
		logLevel: *logLevel, echMode: *echMode, echDoh: *echDoh,
		localAddrV: *localAddr, localPortV: *localPort, remoteAddrV: *remoteAddr, remotePortV: *remotePort,
		mux: *mux, fwmark: *fwmark, tcpKeepAliveV: *tcpKeepAlive,
		tlsEnabledV: *tlsEnabled, serverV: *server, fastOpenV: *fastOpen, vpnV: *vpn,
	}
}

func (s flagSnapshot) restore() {
	*mode, *host, *path, *cert, *certRaw, *key = s.mode, s.host, s.path, s.cert, s.certRaw, s.key
	*logLevel, *echMode, *echDoh = s.logLevel, s.echMode, s.echDoh
	*localAddr, *localPort, *remoteAddr, *remotePort = s.localAddrV, s.localPortV, s.remoteAddrV, s.remotePortV
	*mux, *fwmark, *tcpKeepAlive = s.mux, s.fwmark, s.tcpKeepAliveV
	*tlsEnabled, *server, *fastOpen, *vpn = s.tlsEnabledV, s.serverV, s.fastOpenV, s.vpnV
}

// withEnv snapshots every flag, THEN sets env; t.Cleanup restores the
// snapshot. t.Cleanup callbacks run after the calling test function's own
// defers, so a caller that also mutates a flag manually must do so AFTER
// this call and rely on this snapshot's restore rather than a separate
// defer -- two independent restore mechanisms race, and this one runs last.
func withEnv(t *testing.T, pluginOptions string) {
	t.Helper()
	snap := snapshotFlags()
	t.Cleanup(snap.restore)
	for k, v := range map[string]string{
		"SS_REMOTE_HOST":    "example.com",
		"SS_REMOTE_PORT":    "443",
		"SS_LOCAL_HOST":     "127.0.0.1",
		"SS_LOCAL_PORT":     "1984",
		"SS_PLUGIN_OPTIONS": pluginOptions,
	} {
		t.Setenv(k, v)
	}
}

// withDistinctEnv sets the four SS_* vars to values that differ from every
// flag default (127.0.0.1/1984 local, 127.0.0.1/1080 remote), so a test
// cannot pass by silently falling back to defaults instead of actually
// wiring the SS_*-derived values.
func withDistinctEnv(t *testing.T, pluginOptions string) {
	t.Helper()
	snap := snapshotFlags()
	t.Cleanup(snap.restore)
	for k, v := range map[string]string{
		"SS_REMOTE_HOST":    "chain.example.net",
		"SS_REMOTE_PORT":    "9443",
		"SS_LOCAL_HOST":     "10.1.2.3",
		"SS_LOCAL_PORT":     "45999",
		"SS_PLUGIN_OPTIONS": pluginOptions,
	} {
		t.Setenv(k, v)
	}
}

// Every malformed string must make parseOptsIntoFlags fail, leaving all
// four address flags untouched. Substrings are parsePluginOptions' own
// error text (pinned separately in args_test.go).
func TestParseOptsIntoFlagsRejectsMalformedOptions(t *testing.T) {
	cases := []struct {
		name          string
		opts          string
		wantErrSubstr string
	}{
		{"dangling escape", `host=example.com;path=/a\`, "unpaired backslash"},
		{"empty key", `host=example.com;=v`, "has no key"},
		{"empty segment", `host=example.com;;path=/`, "has no key"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := snapshotFlags() // captured pre-call, compared below -- proves "untouched", not just "equals a hardcoded literal"
			withDistinctEnv(t, c.opts)
			err := parseOptsIntoFlags()
			if err == nil {
				t.Fatalf("parseOptsIntoFlags() = nil error, want an error mentioning %q", c.wantErrSubstr)
			}
			if !strings.Contains(err.Error(), c.wantErrSubstr) {
				t.Errorf("parseOptsIntoFlags() error = %q, want it to contain %q", err.Error(), c.wantErrSubstr)
			}
			if *localAddr != before.localAddrV || *localPort != before.localPortV {
				t.Errorf("localAddr/localPort = %q/%q after a rejected options string, want the untouched pre-call values %q/%q", *localAddr, *localPort, before.localAddrV, before.localPortV)
			}
			if *remoteAddr != before.remoteAddrV || *remotePort != before.remotePortV {
				t.Errorf("remoteAddr/remotePort = %q/%q after a rejected options string, want the untouched pre-call values %q/%q", *remoteAddr, *remotePort, before.remoteAddrV, before.remotePortV)
			}
		})
	}
}

// A malformed SS_PLUGIN_OPTIONS must be fatal even when the SS_* chain-
// handoff vars are incomplete -- parseEnv validates the options string
// independently of that completeness check. t.Setenv("SS_REMOTE_PORT", "")
// makes the absence explicit rather than relying on the ambient
// environment happening not to export it.
func TestParseOptsIntoFlagsRejectsMalformedOptionsWithPartialSSEnv(t *testing.T) {
	snap := snapshotFlags()
	t.Cleanup(snap.restore)
	t.Setenv("SS_REMOTE_HOST", "chain.example.net")
	t.Setenv("SS_REMOTE_PORT", "")
	t.Setenv("SS_LOCAL_HOST", "10.1.2.3")
	t.Setenv("SS_LOCAL_PORT", "45999")
	t.Setenv("SS_PLUGIN_OPTIONS", `host=example.com;path=/a\`)

	err := parseOptsIntoFlags()
	if err == nil {
		t.Fatal("parseOptsIntoFlags() = nil error, want an error (malformed options, even with SS_REMOTE_PORT unset)")
	}
	if !strings.Contains(err.Error(), "unpaired backslash") {
		t.Errorf("error = %q, want it to mention the unpaired backslash", err.Error())
	}
	if *localAddr != snap.localAddrV || *localPort != snap.localPortV {
		t.Errorf("localAddr/localPort = %q/%q after a rejected options string, want the untouched pre-call values %q/%q", *localAddr, *localPort, snap.localAddrV, snap.localPortV)
	}
}

// The control row: a valid options string must still wire all four
// SS_*-derived addresses through (withDistinctEnv's values differ from
// every flag default, so a default-fallback wouldn't pass).
func TestParseOptsIntoFlagsAcceptsControlOptions(t *testing.T) {
	withDistinctEnv(t, "host=example.com;path=/")
	if err := parseOptsIntoFlags(); err != nil {
		t.Fatalf("parseOptsIntoFlags() with a valid options string = %v, want nil", err)
	}
	if *localAddr != "10.1.2.3" || *localPort != "45999" {
		t.Errorf("localAddr/localPort = %q/%q, want the SS_LOCAL_*-derived 10.1.2.3/45999", *localAddr, *localPort)
	}
	if *remoteAddr != "chain.example.net" || *remotePort != "9443" {
		t.Errorf("remoteAddr/remotePort = %q/%q, want the SS_REMOTE_*-derived chain.example.net/9443", *remoteAddr, *remotePort)
	}
}

// SS_PLUGIN_OPTIONS applies even with no SS_* env at all (the
// fully-standalone case). A CLI flag set first must still survive
// SS_PLUGIN_OPTIONS being empty for that key.
func TestParseOptsIntoFlagsAppliesOptionsWithNoSSEnvAtAll(t *testing.T) {
	snap := snapshotFlags()
	t.Cleanup(snap.restore)
	// unsetEnv (args_test.go), not t.Setenv(v, ""): parseEnv distinguishes
	// a genuinely-unset var from one exported empty (see
	// TestParseEnvRejectsOnlyGenuinePartialSSEnv), and this test means to
	// cover true standalone absence, not "all four present but empty"
	// (which is itself fatal).
	for _, v := range []string{"SS_REMOTE_HOST", "SS_REMOTE_PORT", "SS_LOCAL_HOST", "SS_LOCAL_PORT"} {
		unsetEnv(t, v)
	}
	t.Setenv("SS_PLUGIN_OPTIONS", "host=standalone.example.com")

	if err := parseOptsIntoFlags(); err != nil {
		t.Fatalf("parseOptsIntoFlags(): %v, want nil", err)
	}
	if *host != "standalone.example.com" {
		t.Errorf("*host = %q, want the SS_PLUGIN_OPTIONS-derived value (no SS_* env was set at all)", *host)
	}
}

// An explicit empty value ("ech=") is rejected like any other value
// outside allowedEchModes -- not a no-op, matching parseIntOption/
// parseBoolOption's rule that only an absent key is a no-op.
func TestParseOptsIntoFlagsEchRejectsExplicitEmptyValue(t *testing.T) {
	withEnv(t, "ech=")
	withEchFlags(t, "auto", "")
	err := parseOptsIntoFlags()
	if err == nil {
		t.Fatal("parseOptsIntoFlags() = nil error, want an error mentioning ech")
	}
	if !strings.Contains(err.Error(), "ech") {
		t.Errorf("error %q does not mention ech", err.Error())
	}
	if *echMode != "auto" {
		t.Errorf("*echMode = %q after a rejected value, want it untouched at %q", *echMode, "auto")
	}
}

// ech-doh is the DoH URL ECH's own config fetch uses; a malformed value is
// otherwise never caught before ready -- v2ray-core's own ApplyECH only
// logs a dohQuery failure, so ech=auto silently never arms ECH (cleartext
// SNI) and ech=always silently arms RequireEch with no way to ever satisfy
// it, in both cases with ex-ray already having reported ready.
func TestParseOptsIntoFlagsEchDohRejectsNonHTTPSValue(t *testing.T) {
	for _, bad := range []string{"not a url", "http://1.1.1.1/dns-query", "ftp://1.1.1.1/dns-query", "https://"} {
		t.Run(bad, func(t *testing.T) {
			withEnv(t, "ech-doh="+bad)
			withEchFlags(t, "auto", "")
			err := parseOptsIntoFlags()
			if err == nil {
				t.Fatalf("parseOptsIntoFlags() = nil error, want an error mentioning ech-doh")
			}
			if !strings.Contains(err.Error(), "ech-doh") {
				t.Errorf("error %q does not mention ech-doh", err.Error())
			}
			if *echDoh != "" {
				t.Errorf("*echDoh = %q after a rejected value, want it untouched at %q", *echDoh, "")
			}
		})
	}
}

// An explicit empty ech-doh value is a documented, legitimate spelling
// (the flag's own description: "Empty disables ECH"), not rejected --
// unlike every other option's empty-value handling in this file.
func TestParseOptsIntoFlagsEchDohAcceptsExplicitEmptyValue(t *testing.T) {
	withEnv(t, "ech-doh=")
	restoreEch := withEchFlags(t, "auto", "https://1.1.1.1/dns-query")
	defer restoreEch()
	if err := parseOptsIntoFlags(); err != nil {
		t.Fatalf("parseOptsIntoFlags(): %v, want nil", err)
	}
	if *echDoh != "" {
		t.Errorf("*echDoh = %q, want empty (explicit ech-doh= clears it)", *echDoh)
	}
}

// The rejected value must never appear in the error text, checked with a
// distinctive value via the same backslash-absorption exploit used
// throughout this file.
func TestParseOptsIntoFlagsEchDohErrorNeverEchoesAbsorbedSecret(t *testing.T) {
	withEnv(t, `ech-doh=abc\;certRaw=SUPERSECRETVALUE`)
	withEchFlags(t, "auto", "")
	err := parseOptsIntoFlags()
	if err == nil {
		t.Fatal("parseOptsIntoFlags() = nil error, want an error mentioning ech-doh")
	}
	if strings.Contains(err.Error(), "SUPERSECRETVALUE") {
		t.Errorf("error %q leaks an absorbed segment", err.Error())
	}
}

// ech=always is a fail-closed promise ("refusing to start without a DoH
// source for fail-closed ECH" is buildTLSConfig's own reasoning for the
// missing-ech-doh case); without tls set at all, buildTLSConfig never
// runs, so this must be validated in generateConfig itself or the promise
// silently applies nothing -- the operator asked for concealed SNI and
// gets a fully plaintext transport instead, with no diagnostic.
func TestGenerateConfigRejectsEchAlwaysWithoutTLS(t *testing.T) {
	restore := withFlags(t, 1, 0, false)
	defer restore()
	restoreEch := withEchFlags(t, "always", "https://1.1.1.1/dns-query")
	defer restoreEch()
	origTLS := *tlsEnabled
	*tlsEnabled = false
	defer func() { *tlsEnabled = origTLS }()

	_, err := generateConfig()
	if err == nil {
		t.Fatal("generateConfig() = nil error, want an error mentioning ech and tls")
	}
	if !strings.Contains(err.Error(), "ech") || !strings.Contains(err.Error(), "tls") {
		t.Errorf("error %q does not mention both ech and tls", err.Error())
	}
}

// mode=quic sets *tlsEnabled = true itself (config.go's mode switch), a
// side effect the ech=always/tls gate must observe -- the gate runs after
// the mode switch specifically so a quic config with ech=always and no
// separately-set tls flag is accepted, not rejected as "tls not enabled"
// when quic enforces TLS unconditionally.
func TestGenerateConfigAcceptsEchAlwaysWithQuicMode(t *testing.T) {
	restore := withFlags(t, 1, 0, false)
	defer restore()
	restoreEch := withEchFlags(t, "always", "https://1.1.1.1/dns-query")
	defer restoreEch()
	origMode, origTLS := *mode, *tlsEnabled
	*mode, *tlsEnabled = "quic", false
	defer func() { *mode, *tlsEnabled = origMode, origTLS }()

	if _, err := generateConfig(); err != nil {
		t.Errorf("generateConfig() with mode=quic, ech=always, tls not separately set = %v, want nil", err)
	}
}

// ech=auto/never make no fail-closed promise, so they must NOT require
// tls -- opportunistic ECH with no TLS at all is simply a no-op, not a
// broken guarantee. Guards against a future edit widening the
// always-requires-tls check to every non-"never" value, which would
// reject the flag's own registered default (echMode=auto, tlsEnabled=false).
func TestGenerateConfigAcceptsEchAutoAndNeverWithoutTLS(t *testing.T) {
	restore := withFlags(t, 1, 0, false)
	defer restore()
	for _, mode := range []string{"auto", "never"} {
		restoreEch := withEchFlags(t, mode, "")
		origTLS := *tlsEnabled
		*tlsEnabled = false

		_, err := generateConfig()
		restoreEch()
		*tlsEnabled = origTLS
		if err != nil {
			t.Errorf("ech=%s, tls disabled: generateConfig() = %v, want nil", mode, err)
		}
	}
}

// intOptionSeedSentinel never equals any want value in this file's tables
// (0, 1, 8, muxDefault, tcpKeepAliveDefault, fwmarkDefault are all small
// non-negative ints), so every subtest can tell "correctly computed" apart
// from "never touched, still the seed".
const intOptionSeedSentinel = -999

// mux-specific coverage beyond the shared intOptions table below:
// first-wins override and the escape/absorption edge cases from args.go's
// grammar. galoshes' ex_ray_options relies on exactly these shapes to
// decide what it must refuse to emit.
func TestParseOptsIntoFlagsMux(t *testing.T) {
	// The mux key is present in the parsed options; its value (or absence
	// of a usable one) determines *mux.
	presentCases := []struct {
		desc string
		opts string
		want int
	}{
		{"appended alone", "mux=0", 0},
		{"appended after directives", "host=cloudfront.com;path=/;mux=0", 0},
		{"appended after an escaped semicolon", `path=/a\;;mux=0`, 0},
		{"operator override wins (first-wins)", "mux=8;path=/;mux=0", 8},
		{"bare key resolves to the literal value 1 (== muxDefault here)", "mux", muxDefault},
		{"two backslashes are a literal backslash, separator holds", `path=b\\;mux=0`, 0},
	}
	for _, c := range presentCases {
		t.Run(c.desc, func(t *testing.T) {
			withEnv(t, c.opts)
			*mux = intOptionSeedSentinel
			if err := parseOptsIntoFlags(); err != nil {
				t.Fatalf("%s: parseOptsIntoFlags() = %v, want nil", c.desc, err)
			}
			if *mux != c.want {
				t.Errorf("%s: *mux = %d, want %d", c.desc, *mux, c.want)
			}
		})
	}

	// The mux key never reaches parseIntOption for these inputs -- *mux
	// must be left completely untouched (stays the seed), not reset to any
	// default.
	absentCases := []struct {
		desc string
		opts string
	}{
		{"no mux key at all", "host=cloudfront.com;path=/"},
		// A single backslash before ';' escapes the semicolon, so "mux=0" is
		// absorbed into the preceding value instead of becoming its own
		// directive -- no mux key is ever produced.
		{"one backslash before ';' absorbs the rest into the value, no mux key", `path=b\;mux=0`},
		// Three backslashes: one literal backslash + one more escaping the
		// ';' the same way -- absorbs the rest identically.
		{"three backslashes: one literal backslash + escaped ';', absorbs the rest", `path=b\\\;mux=0`},
	}
	for _, c := range absentCases {
		t.Run(c.desc, func(t *testing.T) {
			withEnv(t, c.opts)
			*mux = intOptionSeedSentinel
			if err := parseOptsIntoFlags(); err != nil {
				t.Fatalf("%s: parseOptsIntoFlags() = %v, want nil", c.desc, err)
			}
			if *mux != intOptionSeedSentinel {
				t.Errorf("%s: *mux = %d, want it untouched at the seed %d", c.desc, *mux, intOptionSeedSentinel)
			}
		})
	}
}

// intOption bundles what the shared tests below need for each
// Atoi-parsed option in parseOptsIntoFlags.
type intOption struct {
	key string
	get func() int
	set func(int)
}

func intOptions() []intOption {
	return []intOption{
		{"mux", func() int { return *mux }, func(v int) { *mux = v }},
		{"tcp-keepalive", func() int { return *tcpKeepAlive }, func(v int) { *tcpKeepAlive = v }},
		{"fwmark", func() int { return *fwmark }, func(v int) { *fwmark = v }},
	}
}

// Unlike an absent key, an explicit empty value ("key=") is rejected, not
// a no-op -- mirrors TestParseOptsIntoFlagsBoolOptionsRejectsExplicitEmptyValue's
// reasoning: for mux specifically, galoshes' ex_ray_options appends
// `mux=0` and ex-ray is first-wins, so a no-op on an operator's earlier
// `mux=` would let it win over the append while leaving Mux.Cool at
// whatever default it already held (often ON), defeating the append's
// whole purpose. Seeded with the sentinel (a value parseIntOption could
// never legitimately produce) so the assertion can tell "correctly
// rejected" apart from "silently applied anyway".
func TestParseOptsIntoFlagsIntOptionsRejectsExplicitEmptyValue(t *testing.T) {
	for _, o := range intOptions() {
		t.Run(o.key, func(t *testing.T) {
			withEnv(t, o.key+"=")
			o.set(intOptionSeedSentinel)
			err := parseOptsIntoFlags()
			if err == nil {
				t.Fatalf("parseOptsIntoFlags() = nil error, want an error mentioning %q", o.key)
			}
			if !strings.Contains(err.Error(), o.key) {
				t.Errorf("error %q does not mention %q", err.Error(), o.key)
			}
			if got := o.get(); got != intOptionSeedSentinel {
				t.Errorf("%s=: value = %d after a rejected value, want the untouched pre-call value %d", o.key, got, intOptionSeedSentinel)
			}
		})
	}
}

// Documents a known, tested mismatch, not a silent one: a bare key
// resolves to the parser's literal "1", which equals muxDefault but not
// tcpKeepAliveDefault/fwmarkDefault. Fixing this needs args.go's Args type
// to distinguish a bare key from an explicit "=1", a grammar change not
// attempted here.
func TestParseOptsIntoFlagsBareKeyResolvesToLiteralOne(t *testing.T) {
	for _, o := range intOptions() {
		t.Run(o.key, func(t *testing.T) {
			withEnv(t, o.key)
			o.set(intOptionSeedSentinel)
			if err := parseOptsIntoFlags(); err != nil {
				t.Fatalf("parseOptsIntoFlags(): %v, want nil", err)
			}
			if got := o.get(); got != 1 {
				t.Errorf("bare %s -> %d, want the literal value 1", o.key, got)
			}
		})
	}
}

// A partial SS_* env is fatal independent of what SS_PLUGIN_OPTIONS
// contains: parseEnv's SS_*-completeness check runs before parseIntOption
// ever sees the option, so even a syntactically-valid but semantically-bad
// value (mux=off) never reaches its own validation -- the error names the
// incomplete env, not the option. Loops over all three int options like
// every sibling test in this file.
func TestParseOptsIntoFlagsIntOptionsNeverReachedWithPartialSSEnv(t *testing.T) {
	for _, o := range intOptions() {
		t.Run(o.key, func(t *testing.T) {
			snap := snapshotFlags()
			t.Cleanup(snap.restore)
			t.Setenv("SS_REMOTE_HOST", "chain.example.net")
			t.Setenv("SS_REMOTE_PORT", "")
			t.Setenv("SS_LOCAL_HOST", "10.1.2.3")
			t.Setenv("SS_LOCAL_PORT", "45999")
			t.Setenv("SS_PLUGIN_OPTIONS", o.key+"=off")
			o.set(intOptionSeedSentinel)

			err := parseOptsIntoFlags()
			if err == nil {
				t.Fatal("parseOptsIntoFlags() = nil error, want the SS_* incomplete-env error")
			}
			if !strings.Contains(err.Error(), "SS_* chain-handoff env is incomplete") {
				t.Errorf("error = %q, want it to mention the incomplete SS_* env (parseEnv must fail before %q's own validation ever runs)", err.Error(), o.key)
			}
			if got := o.get(); got != intOptionSeedSentinel {
				t.Errorf("%s: value = %d after a rejected env, want the untouched pre-call value %d", o.key, got, intOptionSeedSentinel)
			}
		})
	}
}

// A non-empty, non-numeric value must be rejected, not silently kept as the
// default -- mux=off must not leave Mux.Cool ON; the identical shape
// applies to tcp-keepalive and fwmark. The error must name the option.
func TestParseOptsIntoFlagsIntOptionsRejectNonNumericValue(t *testing.T) {
	for _, o := range intOptions() {
		for _, bad := range []string{"off", "false", "no"} {
			t.Run(o.key+"="+bad, func(t *testing.T) {
				withEnv(t, o.key+"="+bad)
				o.set(intOptionSeedSentinel)
				err := parseOptsIntoFlags()
				if err == nil {
					t.Fatalf("parseOptsIntoFlags() = nil error, want an error mentioning %q", o.key)
				}
				if !strings.Contains(err.Error(), o.key) {
					t.Errorf("error %q does not mention %q", err.Error(), o.key)
				}
				if got := o.get(); got != intOptionSeedSentinel {
					t.Errorf("%s=%s: value = %d after a rejected value, want the untouched pre-call value %d", o.key, bad, got, intOptionSeedSentinel)
				}
			})
		}
	}
}

// The rejected value must never appear in the error text. Checked with a
// distinctive, secret-shaped value via the same backslash-absorption
// exploit as TestMalformedOptionsErrorsNeverEchoSegmentContent, rather than
// substring-checking against short English words like "off"/"no" -- "no" is
// a substring of "not" (as in "value is not an integer"), which would make
// that check fail on the correct, non-leaking message.
func TestParseOptsIntoFlagsIntOptionsErrorNeverEchoesAbsorbedSecret(t *testing.T) {
	for _, o := range intOptions() {
		t.Run(o.key, func(t *testing.T) {
			withEnv(t, o.key+`=abc\;certRaw=SUPERSECRETVALUE`)
			o.set(intOptionSeedSentinel)
			err := parseOptsIntoFlags()
			if err == nil {
				t.Fatalf("parseOptsIntoFlags() = nil error, want an error mentioning %q", o.key)
			}
			if strings.Contains(err.Error(), "SUPERSECRETVALUE") {
				t.Errorf("error %q leaks an absorbed segment", err.Error())
			}
		})
	}
}

// A malformed SS_PLUGIN_OPTIONS string is fatal before any of these
// per-option blocks run, and must leave every one of them untouched.
func TestParseOptsIntoFlagsIntOptionsUntouchedByMalformedOptions(t *testing.T) {
	const malformed = "host=h;=v;mux=0;tcp-keepalive=0;fwmark=1"
	for _, o := range intOptions() {
		t.Run(o.key, func(t *testing.T) {
			withEnv(t, malformed)
			o.set(intOptionSeedSentinel)
			err := parseOptsIntoFlags()
			if err == nil {
				t.Fatal("parseOptsIntoFlags() = nil error, want an error (malformed SS_PLUGIN_OPTIONS)")
			}
			if got := o.get(); got != intOptionSeedSentinel {
				t.Errorf("%s: value = %d after a rejected string, want the untouched pre-call value %d", o.key, got, intOptionSeedSentinel)
			}
		})
	}
}

// boolOption bundles what the shared tests below need for each
// presence-only option in parseOptsIntoFlags.
type boolOption struct {
	key string
	get func() bool
	set func(bool)
}

func boolOptions() []boolOption {
	return []boolOption{
		{"tls", func() bool { return *tlsEnabled }, func(v bool) { *tlsEnabled = v }},
		{"server", func() bool { return *server }, func(v bool) { *server = v }},
		{"fastOpen", func() bool { return *fastOpen }, func(v bool) { *fastOpen = v }},
		{"__android_vpn", func() bool { return *vpn }, func(v bool) { *vpn = v }},
	}
}

// Bare key or explicit "key=1" enables the flag -- the only two spellings
// args.go's grammar can produce for "the operator wrote this key with no
// value" and "the operator wrote this key with the parser's own bare-key
// literal", respectively.
func TestParseOptsIntoFlagsBoolOptionsBareKeyOrExplicitOneEnables(t *testing.T) {
	for _, o := range boolOptions() {
		for _, opts := range []string{o.key, o.key + "=1"} {
			t.Run(opts, func(t *testing.T) {
				withEnv(t, opts)
				o.set(false)
				if err := parseOptsIntoFlags(); err != nil {
					t.Fatalf("parseOptsIntoFlags(): %v, want nil", err)
				}
				if !o.get() {
					t.Errorf("%s -> false, want true", opts)
				}
			})
		}
	}
}

// An explicit empty value is rejected for a presence-only boolean too,
// not just for the int/enum options -- it is rejected like any other
// unrecognized value (parseBoolOption's doc comment explains why: garter
// mirrors ex-ray's old "presence regardless of value" semantics for
// `server`, and a silent no-op here would let ex-ray and garter disagree
// about mode without either side erroring).
func TestParseOptsIntoFlagsBoolOptionsRejectsExplicitEmptyValue(t *testing.T) {
	for _, o := range boolOptions() {
		t.Run(o.key, func(t *testing.T) {
			withEnv(t, o.key+"=")
			o.set(false)
			err := parseOptsIntoFlags()
			if err == nil {
				t.Fatalf("parseOptsIntoFlags() = nil error, want an error mentioning %q", o.key)
			}
			if !strings.Contains(err.Error(), o.key) {
				t.Errorf("error %q does not mention %q", err.Error(), o.key)
			}
			if o.get() {
				t.Errorf("%s=: value = true after a rejected value, want it untouched at false", o.key)
			}
		})
	}
}

// tls=false must not enable TLS; server=no must not flip into server
// mode -- any unrecognized value is rejected, not silently treated as
// enable. No value-echo check here: "no" is a substring of "not" (as in
// "value is not recognized"), which would make that check fail on the
// correct, non-leaking message -- the same trap the int-option tests
// document. The dedicated no-echo test below covers that property with a
// value the message text can't accidentally contain. Seeded false (not
// true, the value parseBoolOption ever writes): true would never
// distinguish "correctly rejected" from "the rejection silently enabled
// the flag anyway" -- mirrors the int-option tests' use of a sentinel the
// implementation could never legitimately produce.
func TestParseOptsIntoFlagsBoolOptionsRejectUnrecognizedValue(t *testing.T) {
	for _, o := range boolOptions() {
		for _, bad := range []string{"false", "0", "no", "true", "yes"} {
			t.Run(o.key+"="+bad, func(t *testing.T) {
				withEnv(t, o.key+"="+bad)
				o.set(false)
				err := parseOptsIntoFlags()
				if err == nil {
					t.Fatalf("parseOptsIntoFlags() = nil error, want an error mentioning %q", o.key)
				}
				if !strings.Contains(err.Error(), o.key) {
					t.Errorf("error %q does not mention %q", err.Error(), o.key)
				}
				if o.get() {
					t.Errorf("%s=%s: value = true after a rejected value, want it untouched at false", o.key, bad)
				}
			})
		}
	}
}

// The rejected value must never appear in the error text, checked with a
// distinctive value via the same backslash-absorption exploit, mirroring
// TestParseOptsIntoFlagsIntOptionsErrorNeverEchoesAbsorbedSecret.
func TestParseOptsIntoFlagsBoolOptionsErrorNeverEchoesAbsorbedSecret(t *testing.T) {
	for _, o := range boolOptions() {
		t.Run(o.key, func(t *testing.T) {
			withEnv(t, o.key+`=abc\;certRaw=SUPERSECRETVALUE`)
			o.set(true)
			err := parseOptsIntoFlags()
			if err == nil {
				t.Fatalf("parseOptsIntoFlags() = nil error, want an error mentioning %q", o.key)
			}
			if strings.Contains(err.Error(), "SUPERSECRETVALUE") {
				t.Errorf("error %q leaks an absorbed segment", err.Error())
			}
		})
	}
}

// remotePort must reject the same out-of-range shape localPort already
// does (net.PortFromString range-checks to 0..65535); the freedom
// outbound's own uint32->uint16 cast otherwise truncates a too-large value
// to a silently different port instead of failing loudly.
func TestGenerateConfigRejectsOutOfRangeRemotePort(t *testing.T) {
	restore := withFlags(t, 1, 0, false)
	defer restore()
	origLocalPort, origRemotePort := *localPort, *remotePort
	defer func() { *localPort, *remotePort = origLocalPort, origRemotePort }()
	*localPort = "1984"

	for _, bad := range []string{"65536", "70000", "4294967295"} {
		*remotePort = bad
		_, err := generateConfig()
		if err == nil {
			t.Errorf("remotePort=%s: generateConfig() = nil error, want an error mentioning remotePort", bad)
			continue
		}
		if !strings.Contains(err.Error(), "remotePort") {
			t.Errorf("remotePort=%s: error %q does not mention remotePort", bad, err.Error())
		}
	}
}

// remotePort=0 is in validPort's accepted range (0..65535) but the
// vendored freedom outbound only applies its destination-port override
// `if server.Port != 0` -- silently dropping it and forwarding to a
// zero port instead of failing loudly.
func TestGenerateConfigRejectsZeroRemotePort(t *testing.T) {
	restore := withFlags(t, 1, 0, false)
	defer restore()
	origLocalPort, origRemotePort := *localPort, *remotePort
	defer func() { *localPort, *remotePort = origLocalPort, origRemotePort }()
	*localPort, *remotePort = "1984", "0"

	_, err := generateConfig()
	if err == nil {
		t.Fatal("generateConfig() with remotePort=0 = nil error, want an error mentioning remotePort")
	}
	if !strings.Contains(err.Error(), "remotePort") {
		t.Errorf("error %q does not mention remotePort", err.Error())
	}
}

// remoteAddr must be rejected when empty (freedom/dokodemo silently
// forward every dial to a broken destination and never fail) or when it
// is the unspecified address 0.0.0.0/:: (net.AnyIP): freedom's own
// isValidAddress rejects that address for the destination override,
// generateConfig validates localAddr itself (not just main()): a
// multi-address `|`-list or a non-IP-literal hostname must fail loudly
// even when generateConfig is called directly, bypassing main()'s own
// guard entirely -- exactly how this file's own tests call it.
func TestGenerateConfigRejectsMultiAddressOrNonIPLocalAddr(t *testing.T) {
	restore := withFlags(t, 1, 0, false)
	defer restore()
	origLocalAddr := *localAddr
	defer func() { *localAddr = origLocalAddr }()

	for _, bad := range []string{"127.0.0.1|127.0.0.2", "localhost", "cloudfront.com"} {
		*localAddr = bad
		_, err := generateConfig()
		if err == nil {
			t.Errorf("localAddr=%q: generateConfig() = nil error, want an error mentioning localAddr", bad)
			continue
		}
		if !strings.Contains(err.Error(), "localAddr") {
			t.Errorf("localAddr=%q: error %q does not mention localAddr", bad, err.Error())
		}
	}
}

// A non-empty cert/certRaw/key without tls set is otherwise never read,
// validated, or applied at all: buildTLSConfig only runs `if
// *tlsEnabled`. ex-ray would silently build a plaintext transport and
// report ready while the operator believes they configured a pinned CA
// or server certificate.
func TestGenerateConfigRejectsCertMaterialWithoutTLS(t *testing.T) {
	restore := withFlags(t, 1, 0, false)
	defer restore()
	origCert, origCertRaw, origKey, origTLS := *cert, *certRaw, *key, *tlsEnabled
	defer func() { *cert, *certRaw, *key, *tlsEnabled = origCert, origCertRaw, origKey, origTLS }()
	*tlsEnabled = false

	cases := []struct {
		desc               string
		cert, certRaw, key string
	}{
		{"cert set", "/some/cert.pem", "", ""},
		{"certRaw set", "", "some-cert-content", ""},
		{"key set", "", "", "/some/key.pem"},
	}
	for _, c := range cases {
		*cert, *certRaw, *key = c.cert, c.certRaw, c.key
		_, err := generateConfig()
		if err == nil {
			t.Errorf("%s: generateConfig() = nil error, want an error mentioning tls", c.desc)
			continue
		}
		if !strings.Contains(err.Error(), "tls") {
			t.Errorf("%s: error %q does not mention tls", c.desc, err.Error())
		}
	}
}

// host/path have no legitimate "explicitly nothing" spelling (unlike
// cert/certRaw/key, where empty means "use the default"), so an explicit
// empty value is rejected the same way mux=/tls= are.
func TestParseOptsIntoFlagsHostAndPathRejectExplicitEmptyValue(t *testing.T) {
	for _, key := range []string{"host", "path"} {
		t.Run(key, func(t *testing.T) {
			withEnv(t, key+"=")
			err := parseOptsIntoFlags()
			if err == nil {
				t.Fatalf("parseOptsIntoFlags() = nil error, want an error mentioning %q", key)
			}
			if !strings.Contains(err.Error(), key) {
				t.Errorf("error %q does not mention %q", err.Error(), key)
			}
		})
	}
}

// cert/certRaw/key accept an explicit empty value as a documented no-op
// (config.go falls back to the ~/.acme.sh default when both cert and
// certRaw are empty in server mode) -- unlike host/path above.
func TestParseOptsIntoFlagsCertKeyAcceptExplicitEmptyValue(t *testing.T) {
	for _, key := range []string{"cert", "certRaw", "key"} {
		t.Run(key, func(t *testing.T) {
			withEnv(t, key+"=")
			if err := parseOptsIntoFlags(); err != nil {
				t.Fatalf("parseOptsIntoFlags(): %v, want nil", err)
			}
		})
	}
}

// A key outside recognizedOptionKeys -- a typo, or a stale/removed option
// name -- must be fatal, not silently absorbed into opts and never
// applied: the operator's intended setting (here, a typo'd "ech") stays
// at its untouched default with no diagnostic anywhere.
func TestParseOptsIntoFlagsRejectsUnrecognizedKey(t *testing.T) {
	withEnv(t, "eech=always;host=example.com")
	origEchMode := *echMode
	defer func() { *echMode = origEchMode }()
	*echMode = "auto"

	err := parseOptsIntoFlags()
	if err == nil {
		t.Fatal("parseOptsIntoFlags() = nil error, want an error about an unrecognized key")
	}
	if *echMode != "auto" {
		t.Errorf("*echMode = %q, want it untouched at %q -- the typo'd key must not silently apply", *echMode, "auto")
	}
}

// silently discarding it and falling back to dokodemo's net.LocalHostIP
// -- traffic goes somewhere real and wrong, worse than the empty case.
func TestGenerateConfigRejectsEmptyOrAnyIPRemoteAddr(t *testing.T) {
	restore := withFlags(t, 1, 0, false)
	defer restore()
	origLocalPort, origRemotePort, origRemoteAddr := *localPort, *remotePort, *remoteAddr
	defer func() { *localPort, *remotePort, *remoteAddr = origLocalPort, origRemotePort, origRemoteAddr }()
	*localPort, *remotePort = "1984", "443"

	// "::"/"[::]" cover the IPv6 unspecified address (net.AnyIPv6) --
	// distinct from "0.0.0.0" (net.AnyIP), a different constant/type in
	// v2ray-core's net package. " " covers a whitespace-only value:
	// net.ParseAddress trims surrounding whitespace, so a raw non-empty
	// string can still parse to an empty domain.
	for _, bad := range []string{"", " ", "0.0.0.0", "::", "[::]"} {
		*remoteAddr = bad
		_, err := generateConfig()
		if err == nil {
			t.Errorf("remoteAddr=%q: generateConfig() = nil error, want an error mentioning remoteAddr", bad)
			continue
		}
		if !strings.Contains(err.Error(), "remoteAddr") {
			t.Errorf("remoteAddr=%q: error %q does not mention remoteAddr", bad, err.Error())
		}
	}
}

// The same never-echo property args.go's parse errors and parseIntOption
// already have, extended to generateConfig/buildTLSConfig's own fatal
// paths -- these are reachable from SS_PLUGIN_OPTIONS too (localPort,
// remotePort, mode, ech all come straight from parsed options), and the
// same backslash-absorption trick applies to any of them.
func TestGenerateConfigErrorsNeverEchoOptionValues(t *testing.T) {
	restore := withFlags(t, 1, 0, false)
	defer restore()
	origLocalPort, origRemotePort, origMode := *localPort, *remotePort, *mode
	defer func() { *localPort, *remotePort, *mode = origLocalPort, origRemotePort, origMode }()

	*localPort, *remotePort, *mode = `1\;certRaw=SUPERSECRETVALUE`, "1080", "websocket"
	if _, err := generateConfig(); err == nil || strings.Contains(err.Error(), "SUPERSECRETVALUE") {
		t.Errorf("localPort error = %v, want a non-nil error not containing the secret", err)
	}

	*localPort, *remotePort, *mode = "1984", `1\;certRaw=SUPERSECRETVALUE`, "websocket"
	if _, err := generateConfig(); err == nil || strings.Contains(err.Error(), "SUPERSECRETVALUE") {
		t.Errorf("remotePort error = %v, want a non-nil error not containing the secret", err)
	}

	*localPort, *remotePort, *mode = "1984", "1080", `abc\;certRaw=SUPERSECRETVALUE`
	if _, err := generateConfig(); err == nil || strings.Contains(err.Error(), "SUPERSECRETVALUE") {
		t.Errorf("mode error = %v, want a non-nil error not containing the secret", err)
	}
}

// An unrecognized ech value must be fatal even WITHOUT tls set, where
// buildTLSConfig's own check is never reached at all.
func TestParseOptsIntoFlagsRejectsUnrecognizedEchWithoutTLS(t *testing.T) {
	withEnv(t, "ech=alwyas") //nolint:misspell // deliberate typo: a plausible operator mistake, not a real word
	origEchMode := *echMode
	defer func() { *echMode = origEchMode }()
	*echMode = "auto"

	err := parseOptsIntoFlags()
	if err == nil {
		t.Fatal("parseOptsIntoFlags() = nil error, want an error mentioning ech")
	}
	if !strings.Contains(err.Error(), "ech") {
		t.Errorf("error %q does not mention ech", err.Error())
	}
	if *echMode != "auto" {
		t.Errorf("*echMode = %q after a rejected value, want it untouched at %q", *echMode, "auto")
	}
}

// Every documented loglevel value (the flag's own help text: "debug, info,
// warning (default), error, none") must still build without error,
// including the empty string (no option given) and the explicit "warning"
// spelling -- both resolve to the same Warning default.
func TestGenerateConfigAcceptsAllDocumentedLogLevels(t *testing.T) {
	restore := withFlags(t, 1, 0, false)
	defer restore()
	orig := *logLevel
	defer func() { *logLevel = orig }()
	for _, lvl := range []string{"", "debug", "info", "warning", "error", "none"} {
		*logLevel = lvl
		if _, err := generateConfig(); err != nil {
			t.Errorf("generateConfig() with loglevel=%q: %v, want nil", lvl, err)
		}
	}
}

// A typo'd loglevel must not silently resolve to Warning and look
// identical to a correctly-set one.
func TestGenerateConfigRejectsUnrecognizedLogLevel(t *testing.T) {
	restore := withFlags(t, 1, 0, false)
	defer restore()
	orig := *logLevel
	defer func() { *logLevel = orig }()
	*logLevel = "warn" // a plausible typo for "warning"
	_, err := generateConfig()
	if err == nil {
		t.Fatal("generateConfig() = nil error, want an error mentioning loglevel")
	}
	if !strings.Contains(err.Error(), "loglevel") {
		t.Errorf("error %q does not mention loglevel", err.Error())
	}
}

// The rejected value must never appear in the error text. A literal check
// for "warn" would only catch a %q-formatted echo (e.g. `invalid loglevel:
// "warn"`) and pass on a plain-concatenation echo (`invalid loglevel: warn`,
// exactly how every other config.go site was written) -- checked instead
// with a distinctive value via the same backslash-absorption exploit.
func TestGenerateConfigLogLevelErrorNeverEchoesValue(t *testing.T) {
	restore := withFlags(t, 1, 0, false)
	defer restore()
	orig := *logLevel
	defer func() { *logLevel = orig }()
	*logLevel = `abc\;certRaw=SUPERSECRETVALUE`
	_, err := generateConfig()
	if err == nil {
		t.Fatal("generateConfig() = nil error, want an error mentioning loglevel")
	}
	if strings.Contains(err.Error(), "SUPERSECRETVALUE") {
		t.Errorf("error %q leaks an absorbed segment", err.Error())
	}
}
