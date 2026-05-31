// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
