package hath

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestCachePruneAgeTiersKeepsNewerDeletesOlder: in the >6-month tier, files
// older than (oldest+30d) are pruned while newer ones stay and refresh the
// range's age record.
func TestCachePruneAgeTiersKeepsNewerDeletesOlder(t *testing.T) {
	ch, s := buildCacheNoPruner(t)
	s.DiskLimit = 1 // over limit → fastDelete
	rng := "abcd"
	dir := filepath.Join(ch.settings.CacheDir, "ab", "cd")
	os.MkdirAll(dir, 0o755)

	old := ParseHVFile("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd-4-jpg")
	newF := ParseHVFile("abcd0123abcd0123abcd0123abcd0123abcd0123-4-jpg")
	writeFile(t, filepath.Join(dir, old.Fileid()), []byte("oldd"))
	writeFile(t, filepath.Join(dir, newF.Fileid()), []byte("neww"))

	oldMtime := time.Now().Add(-400 * 24 * time.Hour)
	newMtime := time.Now().Add(-5 * 24 * time.Hour)
	os.Chtimes(filepath.Join(dir, old.Fileid()), oldMtime, oldMtime)
	os.Chtimes(filepath.Join(dir, newF.Fileid()), newMtime, newMtime)

	ch.mu.Lock()
	ch.staticRangeOldest[rng] = oldMtime.UnixMilli()
	ch.cacheCount = 2
	ch.cacheSize = 8
	ch.mu.Unlock()

	ch.CheckAndPruneCache()

	if _, ok := ch.Lookup(old.Fileid()); ok {
		t.Fatal("old file should be pruned")
	}
	if _, ok := ch.Lookup(newF.Fileid()); !ok {
		t.Fatal("newer file should be kept")
	}
	ch.mu.Lock()
	age := ch.staticRangeOldest[rng]
	ch.mu.Unlock()
	if age != newMtime.UnixMilli() {
		t.Fatalf("range age should refresh to newer file's mtime, got %d want %d", age, newMtime.UnixMilli())
	}
}

// TestCachePruneEmptiesRange: pruning the last file removes the range dir and
// its age entry.
func TestCachePruneEmptiesRange(t *testing.T) {
	ch, s := buildCacheNoPruner(t)
	s.DiskLimit = 1
	rng := "abef"
	dir := filepath.Join(ch.settings.CacheDir, "ab", "ef")
	os.MkdirAll(dir, 0o755)
	f := ParseHVFile("abef0123abcd0123abcd0123abcd0123abcd0123-3-jpg")
	writeFile(t, filepath.Join(dir, f.Fileid()), []byte("old"))
	oldMtime := time.Now().Add(-400 * 24 * time.Hour)
	os.Chtimes(filepath.Join(dir, f.Fileid()), oldMtime, oldMtime)
	ch.mu.Lock()
	ch.staticRangeOldest[rng] = oldMtime.UnixMilli()
	ch.cacheCount = 1
	ch.cacheSize = 3
	ch.mu.Unlock()

	ch.CheckAndPruneCache()

	ch.mu.Lock()
	_, has := ch.staticRangeOldest[rng]
	ch.mu.Unlock()
	if has {
		t.Fatal("emptied range should be removed from staticRangeOldest")
	}
	if _, err := os.Stat(dir); err == nil {
		t.Fatal("empty range dir should be removed")
	}
}

// TestStartupRemovesWrongSizeAndNonStatic: at scan time, a file whose size
// doesn't match its id and a file outside an assigned static range are dropped.
func TestStartupRemovesWrongSizeAndNonStatic(t *testing.T) {
	s := NewSettings()
	s.ClientID = testClientID
	s.ClientKey = testClientKey
	dir := t.TempDir()
	s.CacheDir = filepath.Join(dir, "cache")
	s.TempDir = filepath.Join(dir, "tmp")
	s.DataDir = filepath.Join(dir, "data")
	s.FSBlockSize = 4096
	s.StaticRanges = map[string]bool{"aaaa": true}
	s.StaticRangeCount = 100 // >= number of L1 dirs to avoid the startup safety pause
	for _, d := range []string{s.CacheDir, s.TempDir, s.DataDir} {
		os.MkdirAll(d, 0o755)
	}
	// correct: static range aaaa, size matches
	good := ParseHVFile("aaaa0123abcd0123abcd0123abcd0123abcd0123-5-jpg")
	writeFile(t, filepath.Join(s.CacheDir, "aa", "aa", good.Fileid()), []byte("hello"))
	// wrong size (id says 9, file is 5) → removed
	badsize := ParseHVFile("aaaaabcd0123abcd0123abcd0123abcd0123abcd-9-jpg")
	writeFile(t, filepath.Join(s.CacheDir, "aa", "aa", badsize.Fileid()), []byte("hello"))
	// not in assigned static range (bbbb) → removed
	nonstatic := ParseHVFile("bbbb0123abcd0123abcd0123abcd0123abcd0123-5-jpg")
	writeFile(t, filepath.Join(s.CacheDir, "bb", "bb", nonstatic.Fileid()), []byte("hello"))

	c := &HathClient{settings: s, stats: NewStats()}
	ch, err := NewCacheHandler(c)
	if err != nil {
		t.Fatalf("NewCacheHandler: %v", err)
	}
	t.Cleanup(func() { ch.pruner.stop() })
	if ch.CacheCount() != 1 {
		t.Fatalf("expected only the good file counted, got %d", ch.CacheCount())
	}
	if _, ok := ch.Lookup(good.Fileid()); !ok {
		t.Fatal("good file should remain")
	}
}

// TestCacheFrequencyAdjustment: when under limit with plenty of headroom, the
// pruner frequency is set to a relaxed cadence (covers the headroom branches).
func TestCacheFrequencyAdjustment(t *testing.T) {
	ch, s := buildCacheNoPruner(t)
	s.DiskLimit = 1 << 40 // huge → lots of headroom
	// import one file so cacheCount>=1
	f := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-5-jpg")
	src := filepath.Join(ch.settings.TempDir, "src")
	os.WriteFile(src, []byte("hello"), 0o644)
	ch.ImportFileToCache(src, f)
	ch.CheckAndPruneCache()
	// no assertion on exact frequency (internal), just that it ran without pruning
	if ch.CacheCount() != 1 {
		t.Fatalf("file should not be pruned under huge limit, count=%d", ch.CacheCount())
	}
}
