package main

import (
	"strings"
	"testing"
)

// flagSnapshot captures every package-level flag parseOptsIntoFlags can write, so
// a test can restore the pre-call state whichever keys it touches. `version` is
// the only declared flag it never writes.
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

// withEnv snapshots every flag, then sets the SS_* env; t.Cleanup restores the
// snapshot. Cleanups run after the test function's own defers, so a caller that
// also changes a flag must do so after this call and rely on this restore, not a
// separate defer.
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

// withDistinctEnv sets the four SS_* vars to values that differ from every flag
// default, so a test cannot pass by falling back to defaults instead of wiring
// the SS_*-derived values.
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
			before := snapshotFlags() // compared below, so "untouched" is shown against the pre-call state
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

// A malformed SS_PLUGIN_OPTIONS must be fatal even when the SS_* chain-handoff
// vars are incomplete, since parseEnv validates the options string independently
// of that check.
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

// The control: a valid options string must wire all four SS_*-derived addresses
// through.
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

// An unrecognized SS_PLUGIN_OPTIONS key must not be fatal. This one is galoshes'
// own `udp_timeout`, which galoshes reads and forwards to its embedded ex-ray
// with the rest of the string (see the rules at the top of options.go). An
// allowlist of keys would break that.
func TestParseOptsIntoFlagsToleratesUnrecognizedKey(t *testing.T) {
	withEnv(t, "udp_timeout=300;host=example.com;path=/")
	if err := parseOptsIntoFlags(); err != nil {
		t.Fatalf("parseOptsIntoFlags() with an unrecognized (but legitimately shared) key = %v, want nil", err)
	}
	if *host != "example.com" {
		t.Errorf("*host = %q, want %q -- the unrecognized key must not prevent host from being applied", *host, "example.com")
	}
}

// SS_PLUGIN_OPTIONS applies even with no SS_* env at all (standalone).
func TestParseOptsIntoFlagsAppliesOptionsWithNoSSEnvAtAll(t *testing.T) {
	snap := snapshotFlags()
	t.Cleanup(snap.restore)
	// unsetEnv, not t.Setenv(v, ""): all four set but empty is itself fatal.
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

// An explicit empty value ("ech=") is rejected like any other value outside
// allowedEchModes; only an absent key is a no-op.
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

// A malformed ech-doh value must be fatal: v2ray-core's ApplyECH only logs a
// failed DoH query, so ech=auto would silently never arm ECH (cleartext SNI) and
// ech=always would arm RequireEch with no way to satisfy it, both after ex-ray
// reported ready.
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

// An explicit empty ech-doh clears it ("Empty disables ECH", the flag's own
// description), unlike the empty value of the other options here.
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

// The rejected ech-doh value must not appear in the error text, checked with a
// backslash-absorbed secret as throughout this file.
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

// ech=always is a fail-closed promise. Without tls, buildTLSConfig never runs, so
// generateConfig must reject the combination itself or the operator gets a
// plaintext transport with no diagnostic.
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

// mode=quic sets *tlsEnabled itself, and the ech=always/tls check runs after
// that, so a quic config with ech=always and no separate tls flag is accepted.
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

// ech=auto and never make no fail-closed promise, so they must not require tls.
// Widening the check to every non-"never" value would reject the flag defaults.
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

// intOptionSeedSentinel equals no value any table in this file expects, so a
// subtest can tell a correctly parsed value from one never touched.
const intOptionSeedSentinel = -999

// mux-specific coverage beyond the shared intOptions table below: first-wins
// override, and the escape and absorption edge cases of args.go's grammar that
// galoshes' ex_ray_options has to handle when it appends `mux=0`.
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

	// The mux key never reaches parseIntOption for these inputs, so *mux must
	// stay at the seed, not be reset to a default.
	absentCases := []struct {
		desc string
		opts string
	}{
		{"no mux key at all", "host=cloudfront.com;path=/"},
		// A backslash before ';' escapes it, so "mux=0" is absorbed into the
		// preceding value and no mux key is produced.
		{"one backslash before ';' absorbs the rest into the value, no mux key", `path=b\;mux=0`},
		// Three backslashes: a literal backslash, then an escaped ';' as above.
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

// An explicit empty value ("key=") is rejected, not a no-op. For mux, an empty
// `mux=` that was ignored would win under first-wins over the `mux=0` galoshes
// appends and leave Mux.Cool on. The sentinel seed tells "rejected" apart from
// "applied anyway".
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

// Pins that a bare key reads as the literal 1 for every integer option, which
// equals muxDefault but not tcpKeepAliveDefault or fwmarkDefault.
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

// A partial SS_* env is fatal whatever SS_PLUGIN_OPTIONS holds: parseEnv's
// completeness check runs before any option is validated, so even a bad value
// (mux=off) produces the incomplete-env error, not the option's own.
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

// A non-numeric value must be rejected, not silently left at the default:
// mux=off must not leave Mux.Cool on. The error must name the option.
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

// The rejected value must not appear in the error text. It is checked with a
// secret-shaped value, absorbed as in TestMalformedOptionsErrorsNeverEchoSegmentContent,
// not a short word like "no", which is a substring of the message's "not".
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

// A malformed SS_PLUGIN_OPTIONS string is fatal before any option is applied and
// must leave every integer option untouched.
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

// A bare key or an explicit "key=1" enables the flag; a bare key reads as "1".
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

// An explicit empty value is rejected for a presence option as for any other
// unrecognized value (parseBoolOption explains why: a no-op `server=` would let
// ex-ray and garter disagree about the mode).
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

// tls=false must not enable TLS and server=no must not enable server mode: an
// unrecognized value is rejected, never treated as enable. There is no no-echo
// check here, because "no" is a substring of the message's "not"; the dedicated
// no-echo test below uses a value the message cannot contain. The flag is seeded
// false because parseBoolOption only ever writes true, so a seed of true could not
// show that a rejection did not enable it anyway.
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

// The rejected value must not appear in the error text, checked as in
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

// remotePort must reject an out-of-range value as localPort does
// (net.PortFromString range-checks it); the freedom outbound's uint32-to-uint16
// cast would otherwise truncate it to a different port.
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

// remotePort=0 passes validPort, but the vendored freedom outbound applies its
// destination-port override only `if server.Port != 0`, so it would forward to
// port 0.
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

// generateConfig must reject localPort=0 itself, not rely on main's guard:
// PortRange{0,0} would bind an OS-assigned port that v2ray-core does not report.
func TestGenerateConfigRejectsZeroLocalPort(t *testing.T) {
	restore := withFlags(t, 1, 0, false)
	defer restore()
	origLocalPort, origRemotePort := *localPort, *remotePort
	defer func() { *localPort, *remotePort = origLocalPort, origRemotePort }()
	*localPort, *remotePort = "0", "1080"

	_, err := generateConfig()
	if err == nil {
		t.Fatal("generateConfig() with localPort=0 = nil error, want an error mentioning localPort")
	}
	if !strings.Contains(err.Error(), "localPort") {
		t.Errorf("error %q does not mention localPort", err.Error())
	}
}

// generateConfig must validate localAddr itself, not rely on main's guard: a
// `|`-joined list or a non-IP hostname must fail when it is called directly.
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

// A cert, certRaw or key without tls must be rejected: buildTLSConfig runs only
// `if *tlsEnabled`, so ex-ray would build a plaintext transport and report ready
// while the operator believes a pinned CA or server certificate is in use.
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

// A client-mode `key` is deliberately tolerated: real client options carry an
// unused `key=<path>` beside `cert=<path>` (the ws_tls and quic client fixtures in
// crates/bridge/src/test_support/skuld_fixtures.rs), and rejecting it would break
// them.
func TestGenerateConfigToleratesClientModeKey(t *testing.T) {
	restore := withFlags(t, 1, 0, false) // client mode
	defer restore()
	origCert, origKey, origTLS := *cert, *key, *tlsEnabled
	defer func() { *cert, *key, *tlsEnabled = origCert, origKey, origTLS }()
	*tlsEnabled = true
	*cert, _ = writeSelfSignedCertKey(t, "example.com")
	*key = "/some/key.pem"

	if _, err := generateConfig(); err != nil {
		t.Errorf("generateConfig() with a client-mode key = %v, want nil", err)
	}
}

// host, path and loglevel have no "explicitly nothing" spelling (unlike cert,
// certRaw and key, where empty means "use the default"), so an explicit empty
// value is rejected. For loglevel the default is "warning" or an absent key, and
// an empty value would silently discard a CLI-set -loglevel=debug.
func TestParseOptsIntoFlagsStringOptionsRejectExplicitEmptyValue(t *testing.T) {
	for _, key := range []string{"host", "path", "loglevel"} {
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

// cert, certRaw and key accept an explicit empty value and clear the flag
// (server mode then falls back to the ~/.acme.sh default), unlike host and path.
func TestParseOptsIntoFlagsCertKeyAcceptExplicitEmptyValue(t *testing.T) {
	fields := []struct {
		key string
		get func() string
		set func(string)
	}{
		{"cert", func() string { return *cert }, func(v string) { *cert = v }},
		{"certRaw", func() string { return *certRaw }, func(v string) { *certRaw = v }},
		{"key", func() string { return *key }, func(v string) { *key = v }},
	}
	for _, f := range fields {
		t.Run(f.key, func(t *testing.T) {
			withEnv(t, f.key+"=")
			// Seeded non-empty, so this shows the empty value is applied, not that
			// the flag was already empty.
			f.set("non-empty-sentinel")
			if err := parseOptsIntoFlags(); err != nil {
				t.Fatalf("parseOptsIntoFlags(): %v, want nil", err)
			}
			if got := f.get(); got != "" {
				t.Errorf("%s= -> %q, want empty (explicit key= clears it)", f.key, got)
			}
		})
	}
}

// An empty or unspecified remoteAddr must be rejected. freedom discards a 0.0.0.0
// override (isValidAddress) and dokodemo falls back to net.LocalHostIP, so traffic
// goes to the wrong place instead of failing every dial.
func TestGenerateConfigRejectsEmptyOrAnyIPRemoteAddr(t *testing.T) {
	restore := withFlags(t, 1, 0, false)
	defer restore()
	origLocalPort, origRemotePort, origRemoteAddr := *localPort, *remotePort, *remoteAddr
	defer func() { *localPort, *remotePort, *remoteAddr = origLocalPort, origRemotePort, origRemoteAddr }()
	*localPort, *remotePort = "1984", "443"

	// "::" and "[::]" are the IPv6 unspecified address, a different constant from
	// "0.0.0.0" in v2ray-core's net package. " " is whitespace-only:
	// net.ParseAddress trims it, so it parses to an empty domain.
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

// generateConfig's errors for localPort, remotePort and mode must not embed the
// option value, since each comes straight from SS_PLUGIN_OPTIONS and a
// backslash-absorbed secret can reach it.
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

// An unrecognized ech value must be fatal even without tls, where
// buildTLSConfig's own check is never reached.
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

// Every loglevel value in the flag's help text must build, including the empty
// string (no option) and "warning", which both mean the default.
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

// A typo'd loglevel must be rejected, not resolved to the default.
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

// The rejected loglevel must not appear in the error text, checked with a
// backslash-absorbed secret as elsewhere in this file.
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
