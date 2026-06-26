package transportcommon

import (
	"context"

	"github.com/v2fly/v2ray-core/v5/transport/internet/security"
	"github.com/v2fly/v2ray-core/v5/transport/internet/tls"

	"github.com/v2fly/v2ray-core/v5/common/environment"
	"github.com/v2fly/v2ray-core/v5/common/environment/envctx"

	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
)

func DialWithSecuritySettings(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (internet.Connection, error) {
	transportEnvironment := envctx.EnvironmentFromContext(ctx).(environment.TransportEnvironment)
	dialer := transportEnvironment.Dialer()
	dialRaw := func() (net.Conn, error) { return dialer.Dial(ctx, nil, dest, streamSettings.SocketSettings) }

	securityEngine, err := security.CreateSecurityEngineFromSettings(ctx, streamSettings)
	if err != nil {
		return nil, newError("unable to create security engine").Base(err)
	}

	var conn net.Conn
	if securityEngine != nil {
		// Retry once on an ECH rejection with the server's retry_configs (RFC 9849).
		conn, err = tls.DialClientWithECHRetry(securityEngine, tls.TLSConfigFromStreamSettings(streamSettings), dialRaw,
			security.OptionWithDestination{Dest: dest})
		if err != nil {
			return nil, newError("unable to create security protocol client from security engine").Base(err)
		}
	} else {
		conn, err = dialRaw()
		if err != nil {
			return nil, newError("failed to dial to ", dest).Base(err)
		}
	}
	return internet.Connection(conn), nil
}
