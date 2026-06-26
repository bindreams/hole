//go:build !go1.23
// +build !go1.23

package tls

import (
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/transport/internet/security"
)

// DialClientWithECHRetry without go1.23 has no *tls.ECHRejectionError to observe,
// so it just dials and wraps through the engine (no retry).
func DialClientWithECHRetry(engine security.Engine, c *Config, dial func() (net.Conn, error), opts ...security.Option) (security.Conn, error) {
	raw, err := dial()
	if err != nil {
		return nil, err
	}
	conn, err := engine.Client(raw, opts...)
	if err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}
