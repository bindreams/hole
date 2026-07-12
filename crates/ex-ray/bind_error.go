package main

import (
	"errors"
	"net"
	"syscall"
)

// classifyBindError reports whether err is a listener-bind failure and, if so,
// the OS errno and the authoritative failed-bind addr to surface.
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
