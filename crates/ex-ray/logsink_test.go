package main

import (
	"testing"

	vlog "github.com/v2fly/v2ray-core/v5/app/log"
)

// TestStderrConsoleCreatorReturnsHandler verifies that stderrConsoleCreator
// produces a non-nil Handler. This exercises the function that init() wires
// as the Console HandlerCreator, confirming the wiring is structurally sound.
//
// This is the structural guarantee that v2ray-core log output reaches
// stderr and NOT fd 1: init() installs stderrConsoleCreator as the Console
// HandlerCreator, so the only thing this test must confirm is that the
// creator yields a usable handler. The plugin-e2e interop test
// (plugin-e2e/tests/interop.rs) additionally exercises the live path — it parses
// ex-ray's `ready` sitrep off stdout for a successful round-trip — but note
// it does NOT assert stdout is *exclusively* sitrep (garter's ExpectSitrep
// reader tolerates stray non-JSON stdout lines as log passthrough). Reliable
// fd-level "stdout is sitrep-only" capture inside a Go unit test is not
// practical here because v2ray's generalLogger is asynchronous (channel +
// goroutine), so any pipe-read without internal sync would be inherently
// racy; the byte-identical sitrep marshal is unit-tested in sitrep_test.go.
func TestStderrConsoleCreatorReturnsHandler(t *testing.T) {
	handler, err := stderrConsoleCreator(vlog.LogType_Console, vlog.HandlerCreatorOptions{})
	if err != nil {
		t.Fatalf("stderrConsoleCreator returned error: %v", err)
	}
	if handler == nil {
		t.Fatal("stderrConsoleCreator returned nil handler")
	}
}
