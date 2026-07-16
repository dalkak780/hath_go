package hath

import (
	"os"
	"sync/atomic"
	"time"
)

var activeClient atomic.Pointer[HathClient]

// fatalError is the terminal handler invoked by dieErr. It is a variable so
// tests can replace os.Exit with a panic (recoverable) and assert the failure
// path without killing the test binary.
var fatalError func(string)

const fatalShutdownTimeout = 30 * time.Second

func defaultFatalError(msg string) {
	Error("Critical Error: " + msg)
	done := make(chan struct{})
	go func() {
		shutdownActiveClient()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(fatalShutdownTimeout):
		Error("graceful shutdown timed out; forcing exit")
	}
	os.Exit(1)
}

func shutdownActiveClient() {
	if client := activeClient.Load(); client != nil {
		client.doShutdown()
	}
}

// dieErr mirrors HentaiAtHomeClient.dieWithError: surface the error and stop.
func dieErr(msg string) {
	if fatalError != nil {
		fatalError(msg)
		return
	}
	defaultFatalError(msg)
}
