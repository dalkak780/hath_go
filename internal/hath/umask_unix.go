//go:build !windows

package hath

import (
	"os"
	"strconv"
	"syscall"
)

// ApplyUmaskFromEnv applies the optional octal UMASK used by the Docker image.
// UID/GID selection remains Docker's responsibility via --user.
func ApplyUmaskFromEnv() {
	value, ok := os.LookupEnv("UMASK")
	if !ok || value == "" {
		return
	}
	n, err := strconv.ParseUint(value, 8, 9)
	if err != nil || n > 0o777 {
		Warn("ignoring invalid UMASK", "value", value)
		return
	}
	syscall.Umask(int(n))
}
