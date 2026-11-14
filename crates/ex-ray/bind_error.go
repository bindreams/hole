package main

import (
	"errors"
	"net"
	"syscall"
)

// classifyBindError reports whether err is a listener-bind failure: the first
// *net.OpError in its chain (errors.As stops there) has Op "listen", whatever
// the errno. A chain whose first *net.OpError has another Op is not a bind
// failure, even if a later one in the chain is "listen". It returns the OS errno
// (0 if the chain carries none) and the address of the failed bind (empty if
// the error carries none).
func classifyBindError(err error) (errno int, addr string, isBindConflict bool) {
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != "listen" {
		return 0, "", false
	}
	var se syscall.Errno
	errors.As(opErr, &se) // no syscall.Errno in chain → errno stays 0
	if opErr.Addr != nil {
		addr = opErr.Addr.String()
	}
	return int(se), addr, true
}
