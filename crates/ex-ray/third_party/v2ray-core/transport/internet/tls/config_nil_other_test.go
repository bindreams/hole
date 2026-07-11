//go:build !windows

package tls

import "testing"

// A nil *Config receiver must not panic, and on non-Windows must return the
// system root pool — never a nil pool (which would silently disable verification).
func TestGetCertPoolNilReceiver(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("getCertPool(nil) panicked: %v", r)
		}
	}()
	var c *Config
	if pool, err := c.getCertPool(); err == nil && pool == nil {
		t.Fatal("getCertPool(nil): (nil, nil) — system roots silently disabled")
	}
}
