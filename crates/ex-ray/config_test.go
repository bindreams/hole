package main

import (
	"math"
	"strings"
	"testing"
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
// tests must leave them as they found them. Mirrors withFlags (config_test.go:58).
func withEchFlags(t *testing.T, modeV, dohV string) func() {
	t.Helper()
	origMode, origDoh := *echMode, *echDoh
	*echMode, *echDoh = modeV, dohV
	return func() { *echMode, *echDoh = origMode, origDoh }
}

// withEnv sets SS_PLUGIN_OPTIONS plus the four SS_* vars parseEnv gates on, for
// the duration of the test (t.Setenv restores originals on cleanup). It also
// snapshots and restores the address/port globals that a subsequent
// parseOptsIntoFlags writes from SS_REMOTE_*/SS_LOCAL_*, so the restore boundary
// matches the full mutation surface (withEchFlags only covers ech/ech-doh).
func withEnv(t *testing.T, pluginOptions string) {
	t.Helper()
	origLocalAddr, origLocalPort := *localAddr, *localPort
	origRemoteAddr, origRemotePort := *remoteAddr, *remotePort
	t.Cleanup(func() {
		*localAddr, *localPort = origLocalAddr, origLocalPort
		*remoteAddr, *remotePort = origRemoteAddr, origRemotePort
	})
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
			restore := withEchFlags(t, "auto", "")
			defer restore()
			withEnv(t, c.opts)
			parseOptsIntoFlags()
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
