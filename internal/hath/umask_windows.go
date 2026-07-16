//go:build windows

package hath

// ApplyUmaskFromEnv is a no-op because Windows has no process umask.
func ApplyUmaskFromEnv() {}
