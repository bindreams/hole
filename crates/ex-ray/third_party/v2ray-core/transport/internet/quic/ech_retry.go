//go:build go1.23
// +build go1.23

package quic

import (
	gotls "crypto/tls"
	"errors"

	"github.com/quic-go/quic-go"

	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/transport/internet/tls"
)

// dialQUICWithECHRetry builds the gated client config and dials via the injected
// closure; on an ECH rejection carrying retry_configs (RFC 9849) it refreshes the
// ECH cache best-effort and retries ONCE with the server's retry_configs threaded
// directly into the config (race-free, ungated since the override is non-empty).
// QUIC bypasses the security engine, so the require-ECH gate runs here. Any other
// dial error, or an empty RetryConfigList, surfaces unchanged: no loop.
func dialQUICWithECHRetry(tlsConfig *tls.Config, dest net.Destination, dial func(*gotls.Config) (*quic.Conn, error)) (*quic.Conn, error) {
	gotlsConfig, err := tlsConfig.GetTLSConfigForClient(tls.WithDestination(dest))
	if err != nil {
		return nil, err
	}

	conn, err := dial(gotlsConfig)
	if err == nil {
		return conn, nil
	}

	var echRej *gotls.ECHRejectionError
	if !errors.As(err, &echRej) || len(echRej.RetryConfigList) == 0 {
		return nil, err
	}

	newError("ECH rejected; retrying QUIC dial once with server retry_configs").AtDebug().WriteToLog()
	tls.RefreshECHCache(tlsConfig, gotlsConfig.ServerName, echRej.RetryConfigList)

	retryCfg := tlsConfig.GetTLSConfig(tls.WithDestination(dest))
	retryCfg.EncryptedClientHelloConfigList = echRej.RetryConfigList
	conn, err = dial(retryCfg)
	if err != nil {
		return nil, newError("ECH retry QUIC dial failed").Base(err).AtWarning()
	}
	return conn, nil
}
