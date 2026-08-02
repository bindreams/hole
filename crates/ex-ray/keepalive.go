package main

import (
	"math"
	"strings"
)

// sockoptInt32 narrows a getsockopt result to the int32 keepAliveParams carries.
// The bound guard wrapping the conversion is gosec G115's recognized
// mitigation, matching uint32Opt in config.go.
func sockoptInt32(name string, v int) (int32, error) {
	if v >= 0 && v <= math.MaxInt32 {
		return int32(v), nil
	}
	return 0, newError("out-of-range ", name, " read back from the socket: ", v)
}

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
			// README); v2ray-core discards this error, so a loud log naming the
			// failed option is the only recourse.
			logWarn("TCP keepalive could not be applied to " + address +
				", falling back to the OS default: " + err.Error())
			return err
		}
		return nil
	}
}
