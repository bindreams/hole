// sitrep — the SIP003u plugin→host control protocol on STDOUT.
//
// ex-ray emits newline-delimited JSON events on STDOUT: `hello` first,
// then exactly one of `ready` / `bind_conflict` / `fatal`. STDOUT carries
// ONLY these events — every v2ray-core log goes to stderr (logsink.go).
//
// The wire bytes MUST match garter's `SitrepEvent` (crates/garter/src/sitrep.rs),
// which serializes via serde `#[serde(tag = "event", rename_all = "snake_case")]`:
// the `event` tag is emitted FIRST, then the variant's fields in declaration
// order. Go's `encoding/json` emits STRUCT fields in declaration order (unlike
// `map[string]any`, which sorts keys alphabetically), so the event structs
// below declare their fields in garter's exact order to byte-match the wire.
// The normative spec is crates/garter/SITREP.md.
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

const sitrepProtocol = "sitrep-1.0.0"

// Event structs (field order matters — see file header).

type helloEvent struct {
	Event    string `json:"event"`
	Protocol string `json:"protocol"`
}

type readyEvent struct {
	Event      string   `json:"event"`
	Listen     string   `json:"listen"`
	Transports []string `json:"transports"`
}

type bindConflictEvent struct {
	Event string `json:"event"`
	Errno int    `json:"errno"`
	Addr  string `json:"addr"`
}

type fatalEvent struct {
	Event  string `json:"event"`
	Detail string `json:"detail"`
	// errno is omitted when nil (matches serde's skip_serializing_if on Fatal).
	Errno *int `json:"errno,omitempty"`
}

// emitSitrep writes one sitrep event as a single JSON line to STDOUT.
func emitSitrep(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ex-ray: sitrep marshal error:", err)
		return
	}
	// A failed stdout write means the parent closed the pipe — log to stderr,
	// don't crash the tunnel. One write (b + '\n') so the line is atomic-ish
	// and there's a single error to check (errcheck is active).
	if _, werr := os.Stdout.Write(append(b, '\n')); werr != nil {
		fmt.Fprintln(os.Stderr, "ex-ray: sitrep write error:", werr)
	}
}

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
