package main

import (
	"encoding/json"
	"testing"
)

// These canonical lines are byte-identical to the pinned examples in
// crates/garter/SITREP.md (and the garter sitrep_tests). The whole point of
// using structs (not map[string]any) is that json.Marshal emits fields in
// declaration order, so the bytes match serde's `#[serde(tag = "event")]`
// output exactly. If garter's SitrepEvent field order ever changes, these
// assertions break — which is the intended cross-impl tripwire.

func marshalLine(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal(%T) returned error: %v", v, err)
	}
	return string(b)
}

func TestHelloMarshalsToCanonicalBytes(t *testing.T) {
	const want = `{"event":"hello","protocol":"sitrep-1.0.0"}`
	got := marshalLine(t, helloEvent{Event: "hello", Protocol: sitrepProtocol})
	if got != want {
		t.Errorf("hello bytes mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestReadyMarshalsToCanonicalBytes(t *testing.T) {
	const want = `{"event":"ready","listen":"127.0.0.1:1984","transports":["tcp"]}`
	got := marshalLine(t, readyEvent{
		Event:      "ready",
		Listen:     "127.0.0.1:1984",
		Transports: []string{"tcp"},
	})
	if got != want {
		t.Errorf("ready bytes mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestBindConflictMarshalsToCanonicalBytes(t *testing.T) {
	const want = `{"event":"bind_conflict","errno":48,"addr":"127.0.0.1:1984"}`
	got := marshalLine(t, bindConflictEvent{
		Event: "bind_conflict",
		Errno: 48,
		Addr:  "127.0.0.1:1984",
	})
	if got != want {
		t.Errorf("bind_conflict bytes mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestFatalMarshalsToCanonicalBytes_ErrnoOmittedWhenNil(t *testing.T) {
	const want = `{"event":"fatal","detail":"config invalid"}`
	got := marshalLine(t, fatalEvent{Event: "fatal", Detail: "config invalid", Errno: nil})
	if got != want {
		t.Errorf("fatal (no errno) bytes mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestFatalMarshalsToCanonicalBytes_ErrnoPresentWhenKnown(t *testing.T) {
	// When errno is known, the key is present (after detail, matching serde's
	// declaration order). errno is the last field.
	errno := 22
	const want = `{"event":"fatal","detail":"start failed","errno":22}`
	got := marshalLine(t, fatalEvent{Event: "fatal", Detail: "start failed", Errno: &errno})
	if got != want {
		t.Errorf("fatal (with errno) bytes mismatch:\n got: %s\nwant: %s", got, want)
	}
}
