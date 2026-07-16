//go:build !windows

package hath

import "golang.org/x/sys/unix"

// diskFree matches java.io.File.getFreeSpace(), which reports unallocated
// bytes rather than only the portion available to an unprivileged caller.
func diskFree(path string) int64 {
	var s unix.Statfs_t
	if err := unix.Statfs(path, &s); err != nil {
		return 0 // unknown: fail closed like File.getFreeSpace()
	}
	return int64(s.Bfree) * int64(s.Bsize)
}
