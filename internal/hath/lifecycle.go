package hath

import "os"

// fatalError is the terminal handler invoked by dieErr. It is a variable so
// tests can replace os.Exit with a panic (recoverable) and assert the failure
// path without killing the test binary.
var fatalError = func(msg string) {
	Error("Critical Error: " + msg)
	os.Exit(1)
}

// dieErr mirrors HentaiAtHomeClient.dieWithError: surface the error and stop.
func dieErr(msg string) { fatalError(msg) }
