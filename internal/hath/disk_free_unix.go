//go:build !windows

package hath

import "golang.org/x/sys/unix"

// diskFree returns free bytes available to unprivileged users. Uses Bavail
// rather than Bfree to match the original getFreeSpace() intent.
func diskFree(path string) int64 {
	var s unix.Statfs_t
	if err := unix.Statfs(path, &s); err != nil {
		return 1<<63 - 1 // unknown → treat as effectively unlimited
	}
	return int64(s.Bavail) * int64(s.Bsize)
}
