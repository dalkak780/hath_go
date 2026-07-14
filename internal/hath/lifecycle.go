package hath

import (
	"os"
)

// dieErr mirrors HentaiAtHomeClient.dieWithError: log the critical error and
// terminate. The original also flushed a clean shutdown; for fatal config/parse
// errors an immediate exit is the honest behavior.
func dieErr(msg string) {
	Error("Critical Error: " + msg)
	os.Exit(1)
}
