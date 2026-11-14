// Routes all v2ray-core logs to stderr, so stdout carries only sitrep events.
// init runs before main and before core.New, so the Console HandlerCreator
// override is in place before app/log.New reads the registered creators.

package main

import (
	vlog "github.com/v2fly/v2ray-core/v5/app/log"
	"github.com/v2fly/v2ray-core/v5/common"
	clog "github.com/v2fly/v2ray-core/v5/common/log"
)

// stderrConsoleCreator is the HandlerCreator registered for LogType_Console. It is
// a named function so tests can call it directly.
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
