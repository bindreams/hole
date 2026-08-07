package main

import (
	"flag"
	"math"
	"path/filepath"
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

// A readable cert/key pair that isn't a valid X509 key pair is otherwise
// never caught before ready: v2ray-core's own BuildCertificates logs
// "ignoring invalid X509 key pair" at Warning and silently drops it,
// leaving zero certificates configured (TLS handshakes then fail with no
// diagnostic ever reaching the sitrep) rather than failing to start.
func TestBuildTLSConfigServerRejectsInvalidX509KeyPair(t *testing.T) {
	restore := withFlags(t, 1, 0, true) // server mode
	defer restore()
	origCert, origKey, origHost, origTLS := *cert, *key, *host, *tlsEnabled
	defer func() { *cert, *key, *host, *tlsEnabled = origCert, origKey, origHost, origTLS }()
	*tlsEnabled = true

	dir := t.TempDir()
	garbageCertPath := filepath.Join(dir, "garbage-cert.pem")
	garbageKeyPath := filepath.Join(dir, "garbage-key.pem")
	writePEMFile(t, garbageCertPath, "CERTIFICATE", []byte("not a real certificate"))
	writePEMFile(t, garbageKeyPath, "PRIVATE KEY", []byte("not a real key"))

	realCertPath, realKeyPath := writeSelfSignedCertKey(t, "example.com")

	*cert, *key, *host = garbageCertPath, realKeyPath, "example.com"
	if _, err := buildTLSConfig(); err == nil {
		t.Error("garbage cert, valid key: buildTLSConfig() = nil error, want an error mentioning X509")
	} else if !strings.Contains(err.Error(), "X509") {
		t.Errorf("garbage cert, valid key: error %q does not mention X509", err.Error())
	}

	*cert, *key, *host = realCertPath, garbageKeyPath, "example.com"
	if _, err := buildTLSConfig(); err == nil {
		t.Error("valid cert, garbage key: buildTLSConfig() = nil error, want an error mentioning X509")
	} else if !strings.Contains(err.Error(), "X509") {
		t.Errorf("valid cert, garbage key: error %q does not mention X509", err.Error())
	}
}

// The client-side pinned-CA equivalent: an unparseable PEM cert is
// otherwise never caught before ready either -- v2ray-core's GetTLSConfig
// only logs AppendCertsFromPEM's failure and leaves RootCAs nil, silently
// falling back to the system root pool instead of the operator's pinned
// CA.
func TestBuildTLSConfigClientRejectsInvalidPEMCert(t *testing.T) {
	restore := withFlags(t, 1, 0, false) // client mode
	defer restore()
	origCert, origCertRaw, origHost, origTLS := *cert, *certRaw, *host, *tlsEnabled
	defer func() { *cert, *certRaw, *host, *tlsEnabled = origCert, origCertRaw, origHost, origTLS }()
	*tlsEnabled = true
	*cert = ""

	dir := t.TempDir()
	garbageCertPath := filepath.Join(dir, "garbage-cert.pem")
	writePEMFile(t, garbageCertPath, "CERTIFICATE", []byte("not a real certificate"))

	*cert, *host = garbageCertPath, "example.com"
	_, err := buildTLSConfig()
	if err == nil {
		t.Fatal("buildTLSConfig() = nil error, want an error mentioning PEM")
	}
	if !strings.Contains(err.Error(), "PEM") {
		t.Errorf("error %q does not mention PEM", err.Error())
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
