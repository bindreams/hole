package main

import (
	"testing"

	vlog "github.com/v2fly/v2ray-core/v5/app/log"
)

// TestStderrConsoleCreatorReturnsHandler verifies that stderrConsoleCreator
// produces a non-nil Handler. This exercises the function that init() wires
// as the Console HandlerCreator, confirming the wiring is structurally sound.
//
// End-to-end stdout cleanliness (i.e. that v2ray-core log output reaches
// stderr and NOT fd 1) is verified by the Task 8 integration test, which
// spawns ex-ray as a subprocess and asserts its stdout contains only sitrep
// JSON. Reliable fd-level capture inside a Go unit test is not practical
// here because v2ray's generalLogger is asynchronous (channel + goroutine),
// so any pipe-read without internal sync would be inherently racy.
func TestStderrConsoleCreatorReturnsHandler(t *testing.T) {
	handler, err := stderrConsoleCreator(vlog.LogType_Console, vlog.HandlerCreatorOptions{})
	if err != nil {
		t.Fatalf("stderrConsoleCreator returned error: %v", err)
	}
	if handler == nil {
		t.Fatal("stderrConsoleCreator returned nil handler")
	}
}
