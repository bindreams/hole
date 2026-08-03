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

func (p keepAliveParams) enabled() bool { return p.IdleSeconds > 0 }

// keepAliveDialerController carries the probe count, which SocketConfig cannot
// express and which is the whole difference between Go's ~150s bound and ours.
// Non-TCP setsockopt calls would fail, hence the network check below.
func keepAliveDialerController(p keepAliveParams) func(network, address string, fd uintptr) error {
	if !p.enabled() {
		return nil
	}
	return func(network, address string, fd uintptr) error {
		if !strings.HasPrefix(network, "tcp") {
			return nil
		}
		if err := setTCPKeepAlive(fd, p); err != nil {
			// Unreachable on installed builds (pre-16299 Windows only, see
			// README); v2ray-core discards this error, so a loud log is the
			// only recourse. The wrapped error names the option that failed
			// rather than asserting the resulting socket state: on linux and
			// darwin the vendored applyOutboundSocketOptions has already
			// applied idle and interval from the same SocketConfig, so a
			// failure on the probe count alone leaves those intact.
			logWarn("TCP keepalive not fully applied to " + address + ": " + err.Error())
			return err
		}
		return nil
	}
}
