//go:build !linux && !darwin && !windows

package main

// ex-ray ships for windows, linux and darwin. These keep `go build ./...`
// honest on any other host without pretending the options were applied.
func setTCPKeepAlive(_ uintptr, _ keepAliveParams) error {
	return newError("TCP keepalive is not supported on this platform")
}

func readTCPKeepAlive(_ uintptr) (keepAliveParams, bool, error) {
	return keepAliveParams{}, false, newError("TCP keepalive is not supported on this platform")
}
