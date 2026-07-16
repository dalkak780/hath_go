//go:build windows

package hath

import "golang.org/x/sys/windows"

// diskFree returns free bytes available to unprivileged users on Windows.
func diskFree(path string) int64 {
	root, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 1<<63 - 1
	}
	var free, total, available uint64
	if err := windows.GetDiskFreeSpaceEx(root, &available, &total, &free); err != nil {
		return 1<<63 - 1
	}
	if available > uint64(1<<63-1) {
		return 1<<63 - 1
	}
	return int64(available)
}
