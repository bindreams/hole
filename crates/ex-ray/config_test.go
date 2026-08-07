package main

import (
	"flag"
	"math"
	"strings"
	"testing"

	core "github.com/v2fly/v2ray-core/v5"
	"github.com/v2fly/v2ray-core/v5/app/proxyman"
	"github.com/v2fly/v2ray-core/v5/proxy/dokodemo"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
	"github.com/v2fly/v2ray-core/v5/transport/internet/tls"
	"github.com/v2fly/v2ray-core/v5/transport/internet/tls/utls"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestUint32OptInRange(t *testing.T) {
	cases := []struct {
		name string
		in   int
		want uint32
	}{
		{"mux", 0, 0},
		{"mux", 1, 1},
		{"fwmark", math.MaxUint32, math.MaxUint32},
	}
	for _, c := range cases {
		got, err := uint32Opt(c.name, c.in)
		if err != nil {
			t.Errorf("uint32Opt(%q, %d) returned error: %v", c.name, c.in, err)
		}
		if got != c.want {
			t.Errorf("uint32Opt(%q, %d) = %d, want %d", c.name, c.in, got, c.want)
		}
	}
}

func TestUint32OptOutOfRange(t *testing.T) {
	// tooBig is evaluated in int context; this relies on int being 64-bit (true
	// for all six CI targets). A hypothetical 32-bit port would make this
	// constant overflow int at compile time — an intentional tripwire, not a
	// silent bug.
	const tooBig = math.MaxUint32 + 1
	cases := []struct {
		name string
		in   int
	}{
		{"mux", -1},
		{"fwmark", tooBig},
	}
	for _, c := range cases {
		_, err := uint32Opt(c.name, c.in)
		if err == nil {
			t.Errorf("uint32Opt(%q, %d) = nil error, want out-of-range error", c.name, c.in)
			continue
		}
		if !strings.Contains(err.Error(), c.name) {
			t.Errorf("uint32Opt(%q, %d) error %q does not mention option name", c.name, c.in, err.Error())
		}
	}
}

// withFlags saves the mux/fwmark/server globals, applies the given values, and
// returns a restore func for defer. generateConfig reads these package-level
// flag pointers, so tests must leave them as they found them.
func withFlags(t *testing.T, muxV, fwmarkV int, serverV bool) func() {
	t.Helper()
	origMux, origFwmark, origServer := *mux, *fwmark, *server
	*mux, *fwmark, *server = muxV, fwmarkV, serverV
	return func() { *mux, *fwmark, *server = origMux, origFwmark, origServer }
}

// generateConfig validates mux/fwmark *before* the server/client split, so an
// out-of-range value must be rejected identically in BOTH modes — the "uniform
// validation" invariant. A future refactor that pushed validation back down
// into the client-only cast site would silently regress server mode (where a
// negative mux still flips connectionReuse); this test guards against that.
func TestGenerateConfigRejectsOutOfRange(t *testing.T) {
	cases := []struct {
		desc      string
		server    bool
		mux       int
		fwmark    int
		wantInErr string
	}{
		{"negative mux, client mode", false, -1, 0, "mux"},
		{"negative mux, server mode", true, -1, 0, "mux"},
		{"oversize mux, server mode", true, math.MaxUint32 + 1, 0, "mux"},
		{"negative fwmark, client mode", false, 1, -1, "fwmark"},
		{"negative fwmark, server mode", true, 1, -1, "fwmark"},
	}
	for _, c := range cases {
		restore := withFlags(t, c.mux, c.fwmark, c.server)
		_, err := generateConfig()
		restore()
		if err == nil {
			t.Errorf("%s: generateConfig() = nil error, want error mentioning %q", c.desc, c.wantInErr)
			continue
		}
		if !strings.Contains(err.Error(), c.wantInErr) {
			t.Errorf("%s: generateConfig() error %q does not mention %q", c.desc, err.Error(), c.wantInErr)
		}
	}
}

// The Hole default (mux=1, fwmark=0) and any in-range value must build a config
// without error in both modes — proves the hardening adds no false rejections.
func TestGenerateConfigAcceptsValidDefaults(t *testing.T) {
	for _, srv := range []bool{false, true} {
		restore := withFlags(t, 1, 0, srv)
		_, err := generateConfig()
		restore()
		if err != nil {
			t.Errorf("server=%v: generateConfig() with valid defaults returned error: %v", srv, err)
		}
	}
}

// withEchFlags saves the ech/ech-doh globals, applies values, returns a restore
// func for defer. parseOptsIntoFlags + generateConfig read these pointers, so
// tests must leave them as they found them. Mirrors withFlags.
func withEchFlags(t *testing.T, modeV, dohV string) func() {
	t.Helper()
	origMode, origDoh := *echMode, *echDoh
	*echMode, *echDoh = modeV, dohV
	return func() { *echMode, *echDoh = origMode, origDoh }
}

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
	for _, v := range []string{"SS_REMOTE_HOST", "SS_REMOTE_PORT", "SS_LOCAL_HOST", "SS_LOCAL_PORT"} {
		t.Setenv(v, "")
	}
	t.Setenv("SS_PLUGIN_OPTIONS", "host=standalone.example.com")

	if err := parseOptsIntoFlags(); err != nil {
		t.Fatalf("parseOptsIntoFlags(): %v, want nil", err)
	}
	if *host != "standalone.example.com" {
		t.Errorf("*host = %q, want the SS_PLUGIN_OPTIONS-derived value (no SS_* env was set at all)", *host)
	}
}

func TestEchFlagDefaults(t *testing.T) {
	if *echMode != "auto" {
		t.Errorf("ech flag default = %q, want %q", *echMode, "auto")
	}
	if *echDoh != "" {
		t.Errorf("ech-doh flag default = %q, want empty", *echDoh)
	}
}

func TestParseOptsIntoFlagsEch(t *testing.T) {
	cases := []struct {
		desc     string
		opts     string
		wantMode string
		wantDoh  string
	}{
		{"both set", "ech=always;ech-doh=https://1.1.1.1/dns-query", "always", "https://1.1.1.1/dns-query"},
		{"mode only", "ech=never", "never", ""},
		{"doh only", "ech-doh=https://dns.google/dns-query", "auto", "https://dns.google/dns-query"},
		{"neither (defaults)", "", "auto", ""},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			// withEnv's snapshot must run before withEchFlags mutates
			// echMode/echDoh, so its t.Cleanup restore (which runs after
			// this func's own defers) captures the true pre-subtest state.
			// withEchFlags's own returned restore func is deliberately left
			// undeferred for the same reason.
			withEnv(t, c.opts)
			withEchFlags(t, "auto", "")
			if err := parseOptsIntoFlags(); err != nil {
				t.Fatalf("parseOptsIntoFlags(): %v", err)
			}
			if *echMode != c.wantMode {
				t.Errorf("%s: *echMode = %q, want %q", c.desc, *echMode, c.wantMode)
			}
			if *echDoh != c.wantDoh {
				t.Errorf("%s: *echDoh = %q, want %q", c.desc, *echDoh, c.wantDoh)
			}
		})
	}
}

func TestBuildTLSConfigEch(t *testing.T) {
	cases := []struct {
		desc      string
		echMode   string
		echDoh    string
		wantDoh   string
		wantErr   bool
		wantInErr string
	}{
		{"never with doh: no-op", "never", "https://1.1.1.1/dns-query", "", false, ""},
		{"auto no doh: cleartext", "auto", "", "", false, ""},
		{"always no doh: config error", "always", "", "", true, "ech-doh"},
		{"auto with doh: populated", "auto", "https://dns.google/dns-query", "https://dns.google/dns-query", false, ""},
		{"always with doh: populated", "always", "https://1.1.1.1/dns-query", "https://1.1.1.1/dns-query", false, ""},
		{"invalid mode: error", "bogus", "https://1.1.1.1/dns-query", "", true, "ech mode"},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			restoreEch := withEchFlags(t, c.echMode, c.echDoh)
			defer restoreEch()
			origHost, origTLS := *host, *tlsEnabled
			*host, *tlsEnabled = "example.com", true
			defer func() { *host, *tlsEnabled = origHost, origTLS }()

			tc, err := buildTLSConfig()
			if c.wantErr {
				if err == nil {
					t.Fatalf("%s: buildTLSConfig() = nil error, want error mentioning %q", c.desc, c.wantInErr)
				}
				if !strings.Contains(err.Error(), c.wantInErr) {
					t.Fatalf("%s: error %q does not mention %q", c.desc, err.Error(), c.wantInErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: buildTLSConfig() error = %v, want nil", c.desc, err)
			}
			if tc.Ech_DOHserver != c.wantDoh {
				t.Errorf("%s: Ech_DOHserver = %q, want %q", c.desc, tc.Ech_DOHserver, c.wantDoh)
			}
			if tc.ServerName != "example.com" {
				t.Errorf("%s: ServerName = %q, want SNI preserved", c.desc, tc.ServerName)
			}
		})
	}
}

// RequireEch is set iff ech=always: only "always" promises fail-closed ECH, so
// only it arms the v2ray-side pre-handshake gate.
func TestBuildTLSConfigRequireEch(t *testing.T) {
	cases := []struct {
		desc, echMode, echDoh string
		wantRequire           bool
	}{
		{"always sets RequireEch", "always", "https://1.1.1.1/dns-query", true},
		{"auto does not", "auto", "https://1.1.1.1/dns-query", false},
		{"never does not", "never", "https://1.1.1.1/dns-query", false},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			restore := withEchFlags(t, c.echMode, c.echDoh)
			defer restore()
			origHost, origTLS := *host, *tlsEnabled
			*host, *tlsEnabled = "example.com", true
			defer func() { *host, *tlsEnabled = origHost, origTLS }()
			tc, err := buildTLSConfig()
			if err != nil {
				t.Fatalf("%s: buildTLSConfig() error = %v", c.desc, err)
			}
			if tc.RequireEch != c.wantRequire {
				t.Errorf("%s: RequireEch = %v, want %v", c.desc, tc.RequireEch, c.wantRequire)
			}
		})
	}
}

// withModeServer saves and restores *mode and *server, which securitySettings
// reads to decide whether to wrap the tls.Config in the uTLS engine.
func withModeServer(t *testing.T, modeV string, serverV bool) func() {
	t.Helper()
	origMode, origServer := *mode, *server
	*mode, *server = modeV, serverV
	return func() { *mode, *server = origMode, origServer }
}

func TestSecuritySettingsClientWebsocketWrapsUTLS(t *testing.T) {
	restore := withModeServer(t, "websocket", false)
	defer restore()
	sec := securitySettings(&tls.Config{ServerName: "example.com"})
	uc, ok := sec.(*utls.Config)
	if !ok {
		t.Fatalf("client websocket must wrap in uTLS, got %T", sec)
	}
	if uc.Imitate != "chrome_auto" {
		t.Errorf("Imitate = %q, want chrome_auto", uc.Imitate)
	}
	if uc.TlsConfig == nil || uc.TlsConfig.ServerName != "example.com" {
		t.Errorf("inner tls.Config not preserved: %+v", uc.TlsConfig)
	}
}

func TestSecuritySettingsServerKeepsPlainTLS(t *testing.T) {
	restore := withModeServer(t, "websocket", true)
	defer restore()
	if _, ok := securitySettings(&tls.Config{ServerName: "example.com"}).(*tls.Config); !ok {
		t.Fatal("server mode must keep the bare tls.Config")
	}
}

func TestSecuritySettingsQuicKeepsPlainTLS(t *testing.T) {
	restore := withModeServer(t, "quic", false)
	defer restore()
	if _, ok := securitySettings(&tls.Config{ServerName: "example.com"}).(*tls.Config); !ok {
		t.Fatal("quic must keep the bare tls.Config (it hard-requires *tls.Config)")
	}
}

func senderSecurity(t *testing.T, cfg *core.Config) *anypb.Any {
	t.Helper()
	sender := new(proxyman.SenderConfig)
	if err := cfg.Outbound[0].SenderSettings.UnmarshalTo(sender); err != nil {
		t.Fatalf("unmarshal sender settings: %v", err)
	}
	if sender.StreamSettings == nil || len(sender.StreamSettings.SecuritySettings) == 0 {
		t.Fatal("no stream security settings on the outbound sender")
	}
	return sender.StreamSettings.SecuritySettings[0]
}

// generateConfig must actually route the client stream security through
// securitySettings: a websocket client dial gets a uTLS config, quic keeps a bare
// tls.Config. Testing securitySettings() alone stays green if the reroute is
// reverted, so this asserts the wired output of generateConfig itself.
func TestGenerateConfigWiresUTLSForWebsocketClient(t *testing.T) {
	restore := withFlags(t, 1, 0, false)
	defer restore()
	origMode, origTLS := *mode, *tlsEnabled
	*mode, *tlsEnabled = "websocket", true
	defer func() { *mode, *tlsEnabled = origMode, origTLS }()

	cfg, err := generateConfig()
	if err != nil {
		t.Fatalf("generateConfig: %v", err)
	}
	uc := new(utls.Config)
	if err := senderSecurity(t, cfg).UnmarshalTo(uc); err != nil {
		t.Fatalf("client websocket security must be a uTLS config: %v", err)
	}
	if uc.Imitate != "chrome_auto" {
		t.Errorf("Imitate = %q, want chrome_auto", uc.Imitate)
	}
}

func TestGenerateConfigKeepsPlainTLSForQuicClient(t *testing.T) {
	restore := withFlags(t, 1, 0, false)
	defer restore()
	origMode, origTLS := *mode, *tlsEnabled
	*mode, *tlsEnabled = "quic", true
	defer func() { *mode, *tlsEnabled = origMode, origTLS }()

	cfg, err := generateConfig()
	if err != nil {
		t.Fatalf("generateConfig: %v", err)
	}
	tc := new(tls.Config)
	if err := senderSecurity(t, cfg).UnmarshalTo(tc); err != nil {
		t.Fatalf("quic client security must stay a bare tls.Config: %v", err)
	}
}

// withKeepAliveFlag saves the tcp-keepalive global, applies a value, and returns
// a restore func. Mirrors withFlags/withEchFlags: generateConfig and
// registerTCPKeepAlive read this package-level pointer.
func withKeepAliveFlag(t *testing.T, v int) func() {
	t.Helper()
	orig := *tcpKeepAlive
	*tcpKeepAlive = v
	return func() { *tcpKeepAlive = orig }
}

// outboundSocketConfig returns the SocketConfig generateConfig puts on the
// client outbound, or nil when there is no outbound sender (server mode).
func outboundSocketConfig(t *testing.T) *internet.SocketConfig {
	t.Helper()
	cfg, err := generateConfig()
	if err != nil {
		t.Fatalf("generateConfig: %v", err)
	}
	if cfg.Outbound[0].SenderSettings == nil {
		return nil
	}
	sender := new(proxyman.SenderConfig)
	if err := cfg.Outbound[0].SenderSettings.UnmarshalTo(sender); err != nil {
		t.Fatalf("unmarshal sender settings: %v", err)
	}
	if sender.StreamSettings == nil {
		return nil
	}
	return sender.StreamSettings.SocketSettings
}

// inboundSocketConfig returns the SocketConfig on the server-mode inbound
// receiver. Server mode puts streamConfig there, NOT on an outbound sender, so
// this is the surface a server-mode keepalive leak would show up on.
func inboundSocketConfig(t *testing.T) *internet.SocketConfig {
	t.Helper()
	cfg, err := generateConfig()
	if err != nil {
		t.Fatalf("generateConfig: %v", err)
	}
	receiver := new(proxyman.ReceiverConfig)
	if err := cfg.Inbound[0].ReceiverSettings.UnmarshalTo(receiver); err != nil {
		t.Fatalf("unmarshal receiver settings: %v", err)
	}
	if receiver.StreamSettings == nil {
		return nil
	}
	return receiver.StreamSettings.SocketSettings
}

func TestTCPKeepAliveDefaultIsFifteen(t *testing.T) {
	// flag.Lookup reads the registered default, so this is immune to the other
	// tests in this binary mutating *tcpKeepAlive.
	if got := flag.Lookup("tcp-keepalive").DefValue; got != "15" {
		t.Errorf("tcp-keepalive default = %q, want \"15\"", got)
	}
}

func TestTCPKeepAliveParams(t *testing.T) {
	for _, bad := range []int{-1, 32768} {
		restore := withKeepAliveFlag(t, bad)
		_, err := tcpKeepAliveParams()
		restore()
		if err == nil {
			t.Errorf("tcpKeepAliveParams() with %d = nil error, want out-of-range error", bad)
		}
	}

	restore := withKeepAliveFlag(t, 0)
	got, err := tcpKeepAliveParams()
	restore()
	if err != nil {
		t.Fatalf("tcpKeepAliveParams() with 0 returned error: %v", err)
	}
	if got.enabled() {
		t.Errorf("tcpKeepAliveParams() with 0 = %+v, want disabled", got)
	}

	// The accepted side of the fencepost, so a `>=` typo in the bound check
	// cannot pass with only the 32768 rejection covered.
	restore = withKeepAliveFlag(t, keepAliveMaxSeconds)
	got, err = tcpKeepAliveParams()
	restore()
	if err != nil {
		t.Fatalf("tcpKeepAliveParams() with %d returned error: %v", keepAliveMaxSeconds, err)
	}
	if got.IdleSeconds != keepAliveMaxSeconds {
		t.Errorf("tcpKeepAliveParams() with %d = %+v, want IdleSeconds %d", keepAliveMaxSeconds, got, keepAliveMaxSeconds)
	}

	restore = withKeepAliveFlag(t, 15)
	got, err = tcpKeepAliveParams()
	restore()
	if err != nil {
		t.Fatalf("tcpKeepAliveParams() with 15 returned error: %v", err)
	}
	if want := (keepAliveParams{IdleSeconds: 15, IntervalSeconds: 15, Probes: 3}); got != want {
		t.Errorf("tcpKeepAliveParams() = %+v, want %+v", got, want)
	}
}

func TestTCPKeepAliveReachesSocketConfig(t *testing.T) {
	restore := withKeepAliveFlag(t, 15)
	sock := outboundSocketConfig(t)
	restore()
	if sock == nil {
		t.Fatal("outbound SocketConfig is nil; the keepalive fields must force one to exist")
	}
	if sock.TcpKeepAliveIdle != 15 || sock.TcpKeepAliveInterval != 15 {
		t.Errorf("idle/interval = %d/%d, want 15/15", sock.TcpKeepAliveIdle, sock.TcpKeepAliveInterval)
	}

	// tcp-keepalive=0 must disable Go's own keepalive too, not merely skip
	// ex-ray's; see the sentinel comment in config.go for why a negative value
	// is what does that.
	restore = withKeepAliveFlag(t, 0)
	sock = outboundSocketConfig(t)
	restore()
	if sock == nil || sock.TcpKeepAliveIdle >= 0 {
		t.Fatalf("SocketConfig with tcp-keepalive=0 = %+v, want a negative TcpKeepAliveIdle sentinel", sock)
	}
}

// Server mode puts streamConfig on the INBOUND receiver, where a keepalive
// field would strip Go's own keepalive from every accepted connection
// (DefaultListener sets lc.KeepAlive = -1 and no dialer controller reaches a
// listener). Asserting on the outbound would be vacuous: server mode builds no
// outbound sender at all.
func TestTCPKeepAliveSkippedInServerMode(t *testing.T) {
	restoreFlags := withFlags(t, 1, 0, true)
	restoreKA := withKeepAliveFlag(t, 15)
	sock := inboundSocketConfig(t)
	regErr := registerTCPKeepAlive()
	restoreKA()
	restoreFlags()

	if sock != nil && (sock.TcpKeepAliveIdle != 0 || sock.TcpKeepAliveInterval != 0) {
		t.Errorf("server mode inbound SocketConfig = %+v, want no keepalive fields", sock)
	}
	if regErr != nil {
		t.Errorf("registerTCPKeepAlive() in server mode = %v, want nil", regErr)
	}
}

// registerTCPKeepAlive short-circuits before validating in server mode, so
// generateConfig is the only gate that rejects an out-of-range value there.
func TestGenerateConfigRejectsOutOfRangeKeepAlive(t *testing.T) {
	for _, srv := range []bool{false, true} {
		restoreFlags := withFlags(t, 1, 0, srv)
		restoreKA := withKeepAliveFlag(t, 32768)
		_, err := generateConfig()
		restoreKA()
		restoreFlags()
		if err == nil {
			t.Errorf("server=%v: generateConfig() with tcp-keepalive=32768 = nil error, want out-of-range error", srv)
			continue
		}
		if !strings.Contains(err.Error(), "tcp-keepalive") {
			t.Errorf("server=%v: error %q does not mention tcp-keepalive", srv, err.Error())
		}
	}
}

// The declared default is what makes galoshes' appended mux=0 necessary at all.
func TestMuxFlagDefault(t *testing.T) {
	if *mux != 1 {
		t.Errorf("mux flag default = %d, want 1", *mux)
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
		{"two backslashes are a literal backslash, separator holds", `a=b\\;mux=0`, 0},
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
		{"one backslash before ';' absorbs the rest into the value, no mux key", `a=b\;mux=0`},
		// Three backslashes: one literal backslash + one more escaping the
		// ';' the same way -- absorbs the rest identically.
		{"three backslashes: one literal backslash + escaped ';', absorbs the rest", `a=b\\\;mux=0`},
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

// Unlike the int/enum options, an explicit empty value is NOT a no-op for a
// presence-only boolean -- it is rejected like any other unrecognized
// value (parseBoolOption's doc comment explains why: garter mirrors
// ex-ray's old "presence regardless of value" semantics for `server`, and
// a silent no-op here would let ex-ray and garter disagree about mode
// without either side erroring).
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
// correct, non-leaking message --
// the same trap the int-option tests document. The dedicated no-echo test
// below covers that property with a value the message text can't
// accidentally contain. Seeded false (not true, the value parseBoolOption
// ever writes): true would never distinguish "correctly rejected" from "the
// rejection silently enabled the flag anyway" -- mirrors the int-option
// tests' use of a sentinel the implementation could never legitimately
// produce.
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

// The same property for buildTLSConfig's cert/key read-failure sites --
// cert, key, and host (via the ~/.acme.sh/{host}/... default path
// construction) are all reachable from SS_PLUGIN_OPTIONS, and a missing
// file's os.PathError text would otherwise embed the raw path verbatim.
func TestBuildTLSConfigCertKeyErrorsNeverEchoOptionValues(t *testing.T) {
	restore := withFlags(t, 1, 0, true) // server mode
	defer restore()
	origCert, origKey, origHost, origTLS := *cert, *key, *host, *tlsEnabled
	defer func() { *cert, *key, *host, *tlsEnabled = origCert, origKey, origHost, origTLS }()
	*tlsEnabled = true

	// cert points at a nonexistent path carrying an absorbed secret.
	*cert, *key, *host = `/nope\;certRaw=SUPERSECRETVALUE`, "", "example.com"
	if _, err := buildTLSConfig(); err == nil || strings.Contains(err.Error(), "SUPERSECRETVALUE") {
		t.Errorf("cert error = %v, want a non-nil error not containing the secret", err)
	}

	// key points at a nonexistent path carrying an absorbed secret; cert
	// must be a real, readable file so the flow reaches the key read.
	certPath, _ := writeSelfSignedCertKey(t, "example.com")
	*cert, *key, *host = certPath, `/nope\;certRaw=SUPERSECRETVALUE`, "example.com"
	if _, err := buildTLSConfig(); err == nil || strings.Contains(err.Error(), "SUPERSECRETVALUE") {
		t.Errorf("key error = %v, want a non-nil error not containing the secret", err)
	}

	// host feeds the default ~/.acme.sh/{host}/... cert path when neither
	// cert nor certRaw is given.
	*cert, *key, *host = "", "", `nosuchhost.invalid\;certRaw=SUPERSECRETVALUE`
	if _, err := buildTLSConfig(); err == nil || strings.Contains(err.Error(), "SUPERSECRETVALUE") {
		t.Errorf("host-derived cert path error = %v, want a non-nil error not containing the secret", err)
	}
}

// The same property for buildTLSConfig's invalid-ech-mode site, which
// needs tlsEnabled=true to reach (TestBuildTLSConfigEch's own precondition).
func TestBuildTLSConfigEchErrorNeverEchoesValue(t *testing.T) {
	restore := withEchFlags(t, `abc\;certRaw=SUPERSECRETVALUE`, "")
	defer restore()
	origHost, origTLS := *host, *tlsEnabled
	*host, *tlsEnabled = "example.com", true
	defer func() { *host, *tlsEnabled = origHost, origTLS }()

	if _, err := buildTLSConfig(); err == nil || strings.Contains(err.Error(), "SUPERSECRETVALUE") {
		t.Errorf("buildTLSConfig() error = %v, want a non-nil error not containing the secret", err)
	}
}

// The bug parseEnumOption exists to close: an unrecognized ech value must
// be fatal even WITHOUT tls set, where buildTLSConfig's own check is never
// reached at all.
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

// mux=0 must disable Mux.Cool on BOTH ends of a websocket chain: the client
// stops attaching MultiplexSettings, and the server stops pointing dokodemo at
// the v1.mux.cool sentinel. The server half is why a mux=0 client cannot talk
// to a mux=1 server.
func TestGenerateConfigMuxDisablesMultiplexing(t *testing.T) {
	cases := []struct {
		desc          string
		mux           int
		wantMultiplex bool
		wantSrvAddr   string
	}{
		{"mux=1 keeps Mux.Cool", 1, true, "v1.mux.cool"},
		{"mux=0 disables Mux.Cool", 0, false, "127.0.0.1"},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			restore := withFlags(t, c.mux, 0, false)
			clientCfg, err := generateConfig()
			restore()
			if err != nil {
				t.Fatalf("client generateConfig(): %v", err)
			}
			sender := new(proxyman.SenderConfig)
			if err := clientCfg.Outbound[0].SenderSettings.UnmarshalTo(sender); err != nil {
				t.Fatalf("unmarshal sender settings: %v", err)
			}
			if got := sender.MultiplexSettings != nil; got != c.wantMultiplex {
				t.Errorf("client: MultiplexSettings present = %v, want %v", got, c.wantMultiplex)
			}

			restore = withFlags(t, c.mux, 0, true)
			serverCfg, err := generateConfig()
			restore()
			if err != nil {
				t.Fatalf("server generateConfig(): %v", err)
			}
			dk := new(dokodemo.Config)
			if err := serverCfg.Inbound[0].ProxySettings.UnmarshalTo(dk); err != nil {
				t.Fatalf("unmarshal dokodemo settings: %v", err)
			}
			if got := dk.Address.AsAddress().String(); got != c.wantSrvAddr {
				t.Errorf("server: dokodemo address = %q, want %q", got, c.wantSrvAddr)
			}
		})
	}
}
