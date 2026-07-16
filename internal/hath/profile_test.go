package hath

import "testing"

func TestStartPprofDisabledAndEphemeral(t *testing.T) {
	stop, err := StartPprof("")
	if err != nil {
		t.Fatal(err)
	}
	stop()
	stop, err = StartPprof("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stop()
}
