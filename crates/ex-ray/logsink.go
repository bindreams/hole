// Route ALL v2ray-core logs to stderr so stdout carries ONLY sitrep events.
// The init() runs before main() and before core.New(), so the Console
// HandlerCreator override is in place before app/log.New reads the map.
package main

import (
	vlog "github.com/v2fly/v2ray-core/v5/app/log"
	"github.com/v2fly/v2ray-core/v5/common"
	clog "github.com/v2fly/v2ray-core/v5/common/log"
)

// stderrConsoleCreator is the HandlerCreator registered for LogType_Console.
// It is extracted as a named function so unit tests can call it directly and
// assert it returns a non-nil Handler without touching global state.
func stderrConsoleCreator(_ vlog.LogType, _ vlog.HandlerCreatorOptions) (clog.Handler, error) {
	return clog.NewLogger(clog.CreateStderrLogWriter()), nil
}

func init() {
	// (a) The app loggers (error + access): override Console to use stderr.
	common.Must(vlog.RegisterHandlerCreator(vlog.LogType_Console, stderrConsoleCreator))

	// (b) The pre-app global handler: anything logged before app/log.New runs
	//     defaults to stdout, so override it to stderr too.
	clog.RegisterHandler(clog.NewLogger(clog.CreateStderrLogWriter()))
}
