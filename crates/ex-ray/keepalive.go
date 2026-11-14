package main

import "strings"

// keepAliveParams are the TCP keepalive timings applied to ex-ray's outbound
// connections.
//
// The fields are int32 so the validated values reach both setsockopt and
// v2ray's SocketConfig (whose keepalive fields are int32) without a narrowing
// conversion at the use sites, which gosec G115 would flag.
type keepAliveParams struct {
	IdleSeconds     int32
	IntervalSeconds int32
	Probes          int32
}

// enabled reports whether keepalive is configured (a zero idle time means off).
func (p keepAliveParams) enabled() bool { return p.IdleSeconds > 0 }

// keepAliveDialerController returns a dialer controller that applies p to every
// TCP socket before it connects, or nil when p is not enabled. It exists to set
// the probe count, which v2ray-core's SocketConfig cannot express: SocketConfig
// carries only the idle time and the interval. v2ray-core turns Go's own default
// keepalive off once SocketConfig carries either, so what the socket gets is p,
// not Go's default. Non-TCP setsockopt calls would fail, hence the network check below.
func keepAliveDialerController(p keepAliveParams) func(network, address string, fd uintptr) error {
	if !p.enabled() {
		return nil
	}
	return func(network, address string, fd uintptr) error {
		if !strings.HasPrefix(network, "tcp") {
			return nil
		}
		if err := setTCPKeepAlive(fd, p); err != nil {
			// v2ray-core discards this error, so the warning is the only report. The
			// error names the option that failed rather than claiming the socket's
			// state: on linux and darwin the vendored applyOutboundSocketOptions has
			// already applied idle and interval from the same SocketConfig, so a
			// failure on the probe count alone leaves those intact.
			logWarn("TCP keepalive not fully applied to " + address + ": " + err.Error())
			return err
		}
		return nil
	}
}
