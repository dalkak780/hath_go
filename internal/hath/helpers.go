package hath

// Shared helpers: directory walking, file SHA-1 validation, free-disk queries,
// and error formatting. Kept here to keep the feature files focused.

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// errf is a short fmt.Errorf alias used across the package.
func errf(format string, args ...any) error { return fmt.Errorf(format, args...) }

// walkRangeDirs visits every cache/xx/yy/ directory, invoking fn with the two
// dir-name components and the regular files directly inside it.
func walkRangeDirs(root string, fn func(l1, l2 string, files []os.DirEntry)) error {
	l1s, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, e1 := range l1s {
		if !e1.IsDir() {
			continue
		}
		l1path := filepath.Join(root, e1.Name())
		l2s, err := os.ReadDir(l1path)
		if err != nil {
			continue
		}
		for _, e2 := range l2s {
			if !e2.IsDir() {
				continue
			}
			l2path := filepath.Join(l1path, e2.Name())
			entries, err := os.ReadDir(l2path)
			if err != nil {
				continue
			}
			var files []os.DirEntry
			for _, fe := range entries {
				if !fe.IsDir() {
					files = append(files, fe)
				}
			}
			fn(e1.Name(), e2.Name(), files)
		}
	}
	return nil
}

// validateFileSHA1 computes a streaming SHA-1 of a file and compares it to the
// expected hex digest.
func validateFileSHA1(path, expected string) bool {
	h := sha1.New()
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	if _, err := io.Copy(h, f); err != nil {
		return false
	}
	return hex.EncodeToString(h.Sum(nil)) == expected
}

// diskFree returns the free bytes available to unprivileged users on the
// filesystem holding path. Uses Bavail (not bfree) to match the original
// getFreeSpace() intent.
func diskFree(path string) int64 {
	var s unix.Statfs_t
	if err := unix.Statfs(path, &s); err != nil {
		return 1<<63 - 1 // unknown → treat as effectively unlimited
	}
	return int64(s.Bavail) * int64(s.Bsize)
}
