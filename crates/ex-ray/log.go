package main

import "log"

// logInit does nothing. Log routing to stderr is set up in logsink.go's init().
func logInit() {
}

// logFatal, logWarn and logInfo write to stderr through the standard logger.
// logFatal only logs; the caller exits.
func logFatal(v ...interface{}) {
	log.Println(v...)
}

func logWarn(v ...interface{}) {
	log.Println(v...)
}

func logInfo(v ...interface{}) {
	log.Println(v...)
}
