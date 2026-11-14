// sitrep is the SIP003u plugin-to-host control protocol that ex-ray speaks on
// STDOUT: newline-delimited JSON events, `hello` first and then exactly one of
// `ready`, `bind_conflict` or `fatal`. STDOUT carries only these events; every
// v2ray-core log goes to stderr (logsink.go). The spec is crates/garter/SITREP.md.
//
// The bytes must match garter's `SitrepEvent` (crates/garter/src/sitrep.rs),
// which serde serializes with the `event` tag first and then the variant's
// fields in declaration order. encoding/json emits struct fields in declaration
// order (a map[string]any would sort its keys), so each event struct below
// declares its fields in garter's order.

package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// sitrepProtocol is the protocol version `hello` announces.
const sitrepProtocol = "sitrep-1.0.0"

// The event structs. Field order is the wire order (see the file header).

// helloEvent is the first line ex-ray writes.
type helloEvent struct {
	Event    string `json:"event"`
	Protocol string `json:"protocol"`
}

// readyEvent reports that the inbound listener is accepting, at Listen, over Transports.
type readyEvent struct {
	Event      string   `json:"event"`
	Listen     string   `json:"listen"`
	Transports []string `json:"transports"`
}

// bindConflictEvent reports that the inbound listener could not bind Addr, with
// the OS errno (see classifyBindError).
type bindConflictEvent struct {
	Event string `json:"event"`
	Errno int    `json:"errno"`
	Addr  string `json:"addr"`
}

// fatalEvent reports a failure to start. Detail must not embed operator-supplied
// option values.
type fatalEvent struct {
	Event  string `json:"event"`
	Detail string `json:"detail"`
	// Errno is omitted when nil (matches serde's skip_serializing_if on Fatal).
	Errno *int `json:"errno,omitempty"`
}

// emitSitrep writes one sitrep event as a single JSON line to STDOUT. A marshal
// or write failure is logged to stderr and otherwise ignored: a failed write
// means the host closed the pipe, which must not crash the tunnel.
func emitSitrep(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ex-ray: sitrep marshal error:", err)
		return
	}
	// One write of the line and its newline, so there is one error to check.
	if _, werr := os.Stdout.Write(append(b, '\n')); werr != nil {
		fmt.Fprintln(os.Stderr, "ex-ray: sitrep write error:", werr)
	}
}

// emitHello, emitReady, emitBindConflict and emitFatal each write one event.
// A nil errno is omitted from `fatal`.
func emitHello() { emitSitrep(helloEvent{Event: "hello", Protocol: sitrepProtocol}) }

func emitReady(listen string, transports []string) {
	emitSitrep(readyEvent{Event: "ready", Listen: listen, Transports: transports})
}

func emitBindConflict(errno int, addr string) {
	emitSitrep(bindConflictEvent{Event: "bind_conflict", Errno: errno, Addr: addr})
}

func emitFatal(detail string, errno *int) {
	emitSitrep(fatalEvent{Event: "fatal", Detail: detail, Errno: errno})
}
