package main

import "log"

// logInit is a no-op retained as a call hook in main(); the actual log
// routing to stderr is configured in logsink.go's init().
func logInit() {
}

func logFatal(v ...interface{}) {
	log.Println(v...)
}

func logWarn(v ...interface{}) {
	log.Println(v...)
}

func logInfo(v ...interface{}) {
	log.Println(v...)
}
