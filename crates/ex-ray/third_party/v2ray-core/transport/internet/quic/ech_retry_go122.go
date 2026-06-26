//go:build !go1.23
// +build !go1.23

package quic

import (
	gotls "crypto/tls"

	"github.com/quic-go/quic-go"

	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/transport/internet/tls"
)

// dialQUICWithECHRetry without go1.23 has no *tls.ECHRejectionError to observe,
// so it just builds the gated config and dials once (no retry).
func dialQUICWithECHRetry(tlsConfig *tls.Config, dest net.Destination, dial func(*gotls.Config) (*quic.Conn, error)) (*quic.Conn, error) {
	gotlsConfig, err := tlsConfig.GetTLSConfigForClient(tls.WithDestination(dest))
	if err != nil {
		return nil, err
	}
	return dial(gotlsConfig)
}
