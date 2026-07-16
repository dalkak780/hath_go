package hath

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCacheStartupScanCountsAndRelocates: a proper L2 file is counted, a stray
// L1 file is relocated, an invalid file is removed.
func TestCacheStartupScanCountsAndRelocates(t *testing.T) {
	s := NewSettings()
	s.ClientID = testClientID
	s.ClientKey = testClientKey
	dir := t.TempDir()
	s.CacheDir = filepath.Join(dir, "cache")
	s.TempDir = filepath.Join(dir, "tmp")
	s.DataDir = filepath.Join(dir, "data")
	s.FSBlockSize = 4096
	s.StaticRanges = map[string]bool{"abcd": true}
	s.StaticRangeCount = 1
	for _, d := range []string{s.CacheDir, s.TempDir, s.DataDir} {
		os.MkdirAll(d, 0o755)
	}

	// proper file in ab/cd (static range abcd), correct size
	f1 := ParseHVFile("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd-5-jpg")
	writeFile(t, filepath.Join(s.CacheDir, "ab", "cd", f1.Fileid()), []byte("hello"))
	// stray valid file directly under L1 (ab) → relocated to ab/cd
	f2 := ParseHVFile("abcd0123abcd0123abcd0123abcd0123abcd0123-4-jpg")
	writeFile(t, filepath.Join(s.CacheDir, "ab", f2.Fileid()), []byte("data"))
	// invalid filename at L2 → removed
	writeFile(t, filepath.Join(s.CacheDir, "ab", "cd", "garbage"), []byte("x"))

	c := &HathClient{settings: s, stats: NewStats()}
	ch, err := NewCacheHandler(c)
	if err != nil {
		t.Fatalf("NewCacheHandler: %v", err)
	}
	t.Cleanup(func() { ch.pruner.stop() })

	if ch.CacheCount() != 2 {
		t.Fatalf("expected 2 cached files, got %d", ch.CacheCount())
	}
	// f2 should have been relocated into ab/cd
	if _, ok := ch.Lookup(f2.Fileid()); !ok {
		t.Fatal("stray file was not relocated")
	}
}

// TestCacheStartupVerifyDeletesCorrupt: with --verify-cache, a file whose SHA-1
// does not match its id is purged at startup.
func TestCacheStartupVerifyDeletesCorrupt(t *testing.T) {
	s := NewSettings()
	s.ClientID = testClientID
	s.ClientKey = testClientKey
	dir := t.TempDir()
	s.CacheDir = filepath.Join(dir, "cache")
	s.TempDir = filepath.Join(dir, "tmp")
	s.DataDir = filepath.Join(dir, "data")
	s.FSBlockSize = 4096
	s.StaticRanges = map[string]bool{"aaf4": true}
	s.StaticRangeCount = 1
	s.VerifyCache = true
	for _, d := range []string{s.CacheDir, s.TempDir, s.DataDir} {
		os.MkdirAll(d, 0o755)
	}
	// sha1("hello") = aaf4c61d... → static range aaf4; content matches → kept
	good := ParseHVFile("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d-5-jpg")
	writeFile(t, filepath.Join(s.CacheDir, "aa", "f4", good.Fileid()), []byte("hello"))
	// same hash id but wrong content → removed by verify
	bad := ParseHVFile("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d-5-jpg")
	_ = bad // same id; instead place a different-id file with wrong content
	wrong := ParseHVFile("aaf4000000000000000000000000000000000000-5-jpg")
	writeFile(t, filepath.Join(s.CacheDir, "aa", "f4", wrong.Fileid()), []byte("world"))

	c := &HathClient{settings: s, stats: NewStats()}
	ch, err := NewCacheHandler(c)
	if err != nil {
		t.Fatalf("NewCacheHandler: %v", err)
	}
	t.Cleanup(func() { ch.pruner.stop() })

	if ch.CacheCount() != 1 {
		t.Fatalf("verify should keep 1 (good) and drop 1 (corrupt), got %d", ch.CacheCount())
	}
	if _, ok := ch.Lookup(good.Fileid()); !ok {
		t.Fatal("good file should remain")
	}
}

func writeFile(t *testing.T, path string, content []byte) {
	t.Helper()
	os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDiskFreePositive(t *testing.T) {
	if diskFree(t.TempDir()) <= 0 {
		t.Fatal("diskFree should report positive free space")
	}
}

func TestWalkRangeDirs(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "ab", "cd", "f1"), []byte("x"))
	writeFile(t, filepath.Join(root, "ab", "ef", "f2"), []byte("y"))
	var seen []string
	walkRangeDirs(root, func(l1, l2 string, files []os.DirEntry) {
		seen = append(seen, l1+l2+":"+fmt.Sprintf("%d", len(files)))
	})
	if len(seen) != 2 {
		t.Fatalf("expected 2 range dirs, got %d: %v", len(seen), seen)
	}
}

func TestCopyFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	os.WriteFile(src, []byte("copyme"), 0o644)
	if err := copyFile(src, dst); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(dst)
	if string(b) != "copyme" {
		t.Fatalf("copy mismatch: %q", b)
	}
}

func TestCrashRestartUsesFilesystemNotStaleSnapshot(t *testing.T) {
	ch, s := buildCache(t)
	ch.pruner.stop()
	f := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-5-jpg")
	ch.savePersistent() // stale snapshot says empty
	os.MkdirAll(filepath.Dir(ch.LocalPath(f)), 0o777)
	os.WriteFile(ch.LocalPath(f), []byte("hello"), 0o666)
	s.StaticRanges = map[string]bool{f.StaticRange(): true}
	s.StaticRangeCount = 1
	c2 := &HathClient{settings: s, stats: NewStats()}
	reloaded, err := NewCacheHandler(c2)
	if err != nil {
		t.Fatal(err)
	}
	reloaded.pruner.stop()
	if reloaded.CacheCount() != 1 {
		t.Fatalf("filesystem import lost after crash: %d", reloaded.CacheCount())
	}
	reloaded.savePersistent() // stale snapshot now says one
	os.Remove(reloaded.LocalPath(f))
	c3 := &HathClient{settings: s, stats: NewStats()}
	reloadedAgain, err := NewCacheHandler(c3)
	if err != nil {
		t.Fatal(err)
	}
	reloadedAgain.pruner.stop()
	if reloadedAgain.CacheCount() != 0 {
		t.Fatalf("deleted file resurrected after crash: %d", reloadedAgain.CacheCount())
	}
}

func TestInitLogVariants(t *testing.T) {
	dir := t.TempDir()
	InitLog(true, false, dir) // file logger
	Info("caller probe")
	_ = logger.Load().Sync()
	logBytes, err := os.ReadFile(filepath.Join(dir, "log_all"))
	if err != nil {
		t.Fatal(err)
	}
	logText := string(logBytes)
	if !strings.Contains(logText, "cache_startup_test.go") || strings.Contains(logText, "hath/log.go") {
		t.Fatalf("wrapped logger lost real caller: %q", logText)
	}
	InitLog(false, true, "") // stdout, no file
	InitLog(true, false, "") // stdout debug
	Info("test info")
	Debug("test debug")
	Warn("test warn")
	Error("test error")
}
