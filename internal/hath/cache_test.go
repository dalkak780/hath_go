package hath

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func buildCache(t *testing.T) (*CacheHandler, *Settings) {
	ch, s := buildCacheNoPruner(t)
	c := &HathClient{settings: s, stats: NewStats()}
	ch.client = c
	realCh, err := NewCacheHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if realCh.pruner != nil {
			realCh.pruner.stop()
		}
	})
	return realCh, s
}

// buildCacheNoPruner constructs a CacheHandler without scanning or starting the
// pruner goroutine — for deterministic unit tests of prune/blacklist/import.
func buildCacheNoPruner(t *testing.T) (*CacheHandler, *Settings) {
	t.Helper()
	s := NewSettings()
	s.ClientID = testClientID
	s.ClientKey = testClientKey
	s.SetServerTime(1_700_000_000)
	dir := t.TempDir()
	s.CacheDir = filepath.Join(dir, "cache")
	s.TempDir = filepath.Join(dir, "tmp")
	s.DataDir = filepath.Join(dir, "data")
	s.FSBlockSize = 4096
	s.StaticRangeCount = 5
	os.MkdirAll(s.CacheDir, 0o755)
	os.MkdirAll(s.TempDir, 0o755)
	os.MkdirAll(s.DataDir, 0o755)
	ch := &CacheHandler{
		client:            &HathClient{settings: s},
		settings:          s, stats: NewStats(),
		lru:               make([]uint16, lruCacheSize),
		staticRangeOldest: make(map[string]int64),
	}
	return ch, s
}

func TestCacheImportAndLookup(t *testing.T) {
	ch, _ := buildCache(t)
	f := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-5-jpg")
	// write a temp source file
	src := filepath.Join(ch.settings.TempDir, "src")
	os.WriteFile(src, []byte("hello"), 0o644)
	if !ch.ImportFileToCache(src, f) {
		t.Fatal("import should succeed")
	}
	got, onDisk := ch.Lookup(f.Fileid())
	if got == nil || !onDisk {
		t.Fatal("lookup should find imported file")
	}
	if ch.CacheCount() != 1 {
		t.Fatalf("cache count = %d", ch.CacheCount())
	}
	if ch.CacheSizeWithOverhead() != 5+4096/2 {
		t.Fatalf("overhead size = %d", ch.CacheSizeWithOverhead())
	}
}

func TestCacheDeleteFile(t *testing.T) {
	ch, _ := buildCache(t)
	f := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-5-jpg")
	src := filepath.Join(ch.settings.TempDir, "src")
	os.WriteFile(src, []byte("hello"), 0o644)
	ch.ImportFileToCache(src, f)
	ch.DeleteFileFromCache(f)
	if ch.CacheCount() != 0 {
		t.Fatalf("count after delete = %d", ch.CacheCount())
	}
	if _, ok := ch.Lookup(f.Fileid()); ok {
		t.Fatal("file should be gone after delete")
	}
}

func TestCacheMarkRecentlyAccessed(t *testing.T) {
	ch, _ := buildCache(t)
	f := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-5-jpg")
	if !ch.MarkRecentlyAccessed(f) {
		t.Fatal("first access should mark (return true)")
	}
	if ch.MarkRecentlyAccessed(f) {
		t.Fatal("second access within window should return false")
	}
}

func TestCacheVerifyFile(t *testing.T) {
	ch, _ := buildCache(t)
	// SHA-1 of "hello" = aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
	f := &HVFile{Hash: "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", Size: 5, Type: "jpg"}
	path := ch.LocalPath(f)
	os.MkdirAll(filepath.Dir(path), 0o755)
	os.WriteFile(path, []byte("hello"), 0o644)
	if !ch.VerifyFile(f) {
		t.Fatal("verify should pass for correct content")
	}
	os.WriteFile(path, []byte("world"), 0o644)
	if ch.VerifyFile(f) {
		t.Fatal("verify should fail for wrong content")
	}
}

func TestCachePersistentRoundTrip(t *testing.T) {
	ch, _ := buildCache(t)
	f := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-7-jpg")
	src := filepath.Join(ch.settings.TempDir, "src")
	os.WriteFile(src, []byte("hello!!"), 0o644)
	ch.ImportFileToCache(src, f)
	ch.TerminateCache() // save

	ch2 := &CacheHandler{
		client: ch.client, settings: ch.settings, stats: NewStats(),
		lru:               make([]uint16, lruCacheSize),
		staticRangeOldest: make(map[string]int64),
	}
	if !ch2.loadPersistent() {
		t.Fatal("persistent load failed")
	}
	if ch2.CacheCount() != 1 {
		t.Fatalf("restored count = %d", ch2.CacheCount())
	}
}

func TestCachePruneOverLimit(t *testing.T) {
	ch, s := buildCache(t)
	s.DiskLimit = 1 // tiny → always over limit
	f := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-5-jpg")
	src := filepath.Join(ch.settings.TempDir, "src")
	os.WriteFile(src, []byte("hello"), 0o644)
	ch.ImportFileToCache(src, f)
	// backdate the file so the age-weighted cutoff prunes it
	path := ch.LocalPath(f)
	old := time.Now().Add(-400 * 24 * time.Hour)
	os.Chtimes(path, old, old)
	ch.mu.Lock()
	ch.staticRangeOldest[f.StaticRange()] = old.UnixMilli()
	ch.mu.Unlock()
	ch.CheckAndPruneCache()
	if ch.CacheCount() != 0 {
		t.Fatalf("prune should have removed the file, count=%d", ch.CacheCount())
	}
}

func TestCacheProcessBlacklist(t *testing.T) {
	ch, _ := buildCache(t)
	m, _, rpc := newMockRPC(t)
	f := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-5-jpg")
	src := filepath.Join(ch.settings.TempDir, "src")
	os.WriteFile(src, []byte("hello"), 0o644)
	ch.ImportFileToCache(src, f)
	m.setResponse(ActGetBlacklist, "OK\n"+f.Fileid()+"\n")
	ch.ProcessBlacklist(rpc, 0)
	if ch.CacheCount() != 0 {
		t.Fatalf("blacklisted file should be removed, count=%d", ch.CacheCount())
	}
}

func TestCacheHasFreeDiskSpace(t *testing.T) {
	ch, _ := buildCache(t)
	if !ch.HasFreeDiskSpace() {
		t.Fatal("temp dir should have free space")
	}
	ch.settings.SkipFreeSpaceCheck = true
	if !ch.HasFreeDiskSpace() {
		t.Fatal("skip check should always report free")
	}
}

func TestCacheCycleLRU(t *testing.T) {
	ch, _ := buildCache(t)
	// should not panic and should rotate the clear pointer
	for i := 0; i < 10; i++ {
		ch.CycleLRUCacheTable()
	}
}
