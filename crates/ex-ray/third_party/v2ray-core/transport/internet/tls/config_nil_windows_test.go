//go:build windows

package tls

import "testing"

// A nil *Config receiver must not panic; on Windows it returns (nil, nil) so Go
// uses the platform verifier.
func TestGetCertPoolNilReceiver(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("getCertPool(nil) panicked: %v", r)
		}
	}()
	var c *Config
	if pool, err := c.getCertPool(); err != nil || pool != nil {
		t.Fatalf("getCertPool(nil): want (nil, nil), got (%v, %v)", pool, err)
	}
}
