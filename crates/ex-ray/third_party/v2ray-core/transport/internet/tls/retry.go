//go:build go1.23
// +build go1.23

package tls

import (
	gotls "crypto/tls"
	"errors"

	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/transport/internet/security"
)

// DialClientWithECHRetry dials via the closure, wraps the raw conn through the
// security engine, and forces the handshake. On an ECH rejection carrying
// retry_configs (RFC 9849) it refreshes the ECH cache best-effort (for future
// dials) and retries ONCE on a fresh conn with the server's retry_configs
// threaded directly into the config via OptionWithECHConfigOverride — race-free,
// independent of the shared cache. Any other handshake error, or an empty
// RetryConfigList, surfaces unchanged: no loop.
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

	err = forceHandshake(conn)
	if err == nil {
		return conn, nil
	}
	conn.Close()

	var echRej *gotls.ECHRejectionError
	if !errors.As(err, &echRej) || len(echRej.RetryConfigList) == 0 {
		return nil, err
	}

	newError("ECH rejected; retrying once with server retry_configs").AtDebug().WriteToLog()
	serverName := ""
	if c != nil {
		serverName = c.parseServerName()
	}
	RefreshECHCache(c, serverName, echRej.RetryConfigList)

	raw2, err := dial()
	if err != nil {
		return nil, newError("ECH retry re-dial failed").Base(err).AtWarning()
	}
	conn2, err := engine.Client(raw2, append(opts, security.OptionWithECHConfigOverride{Configs: echRej.RetryConfigList})...)
	if err != nil {
		raw2.Close()
		return nil, newError("ECH retry client wrap failed").Base(err).AtWarning()
	}
	if err := forceHandshake(conn2); err != nil {
		conn2.Close()
		return nil, newError("ECH retry handshake failed").Base(err).AtWarning()
	}
	return conn2, nil
}

// forceHandshake drives the TLS handshake so an ECH rejection surfaces at the dial
// site, before any payload. Every production engine conn exposes Handshake(); a
// conn lacking it is an unexpected engine — a contract violation, not a no-op.
func forceHandshake(conn security.Conn) error {
	if h, ok := conn.(interface{ Handshake() error }); ok {
		return h.Handshake()
	}
	return newError("forceHandshake: conn lacks Handshake; cannot observe ECH rejection")
}
