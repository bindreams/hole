//go:build !linux && !darwin && !windows

package main

// setTCPKeepAlive always fails: ex-ray ships for windows, linux and darwin, and
// this stub keeps `go build ./...` working on any other host without pretending
// the options were applied.
func setTCPKeepAlive(_ uintptr, _ keepAliveParams) error {
	return newError("TCP keepalive is not supported on this platform")
}
