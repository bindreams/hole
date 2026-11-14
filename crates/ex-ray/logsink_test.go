package main

import (
	"testing"

	vlog "github.com/v2fly/v2ray-core/v5/app/log"
)

// TestStderrConsoleCreatorReturnsHandler checks that stderrConsoleCreator, which
// init installs as the Console HandlerCreator, yields a usable Handler. That is
// the structural guarantee that v2ray-core log output reaches stderr and not fd 1.
//
// A fd-level check that stdout is sitrep-only is not practical in a Go unit test:
// v2ray's generalLogger writes asynchronously (a channel and a goroutine), so
// reading the pipe would be racy. The plugin-e2e interop test
// (crates/plugin-e2e/tests/interop.rs) covers the live path, but it does not
// assert that stdout is exclusively sitrep, because garter's ExpectSitrep reader
// tolerates stray non-JSON stdout lines. The sitrep bytes are tested in
// sitrep_test.go.
func TestStderrConsoleCreatorReturnsHandler(t *testing.T) {
	handler, err := stderrConsoleCreator(vlog.LogType_Console, vlog.HandlerCreatorOptions{})
	if err != nil {
		t.Fatalf("stderrConsoleCreator returned error: %v", err)
	}
	if handler == nil {
		t.Fatal("stderrConsoleCreator returned nil handler")
	}
}
