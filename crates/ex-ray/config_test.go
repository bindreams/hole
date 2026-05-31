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
