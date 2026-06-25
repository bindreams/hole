package hysteria2_test

import (
	"strings"
	"testing"

	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
	"github.com/v2fly/v2ray-core/v5/transport/internet/hysteria2"
	"github.com/v2fly/v2ray-core/v5/transport/internet/tls"
)

// hyClient.TLSConfig carries no ECH field, so hysteria2 cannot satisfy
// ech=always and must fail closed by refusing; with require_ech off it builds a
// client TLS config as before.
func TestGetClientTLSConfigRequireEch(t *testing.T) {
	dest := net.TCPDestination(net.LocalHostIP, 443)
	streamSettings := func(requireEch bool) *internet.MemoryStreamConfig {
		return &internet.MemoryStreamConfig{
			ProtocolName:     "hysteria2",
			ProtocolSettings: &hysteria2.Config{Password: "123"},
			SecurityType:     "tls",
			SecuritySettings: &tls.Config{ServerName: "www.v2fly.org", RequireEch: requireEch},
		}
	}

	t.Run("require_ech refuses", func(t *testing.T) {
		cfg, err := hysteria2.GetClientTLSConfig(dest, streamSettings(true))
		if cfg != nil {
			t.Fatal("a refused GetClientTLSConfig must return a nil config")
		}
		if err == nil || !strings.Contains(err.Error(), "ech=always") {
			t.Fatalf("require_ech must make GetClientTLSConfig refuse, got: %v", err)
		}
	})

	t.Run("auto proceeds", func(t *testing.T) {
		cfg, err := hysteria2.GetClientTLSConfig(dest, streamSettings(false))
		if err != nil {
			t.Fatalf("without require_ech GetClientTLSConfig must not refuse: %v", err)
		}
		if cfg == nil {
			t.Fatal("GetClientTLSConfig must return a config")
		}
	})
}
