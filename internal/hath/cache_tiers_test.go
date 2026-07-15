package hath

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// pruneWithTier sets up a single old file in a range, with the oldest-mtime
// record aged `ageDays`, runs CheckAndPruneCache, and reports whether the file
// was pruned. Covers each age-weighted cutoff tier.
func pruneWithTier(t *testing.T, ageDays int) bool {
	ch, s := buildCacheNoPruner(t)
	s.DiskLimit = 1 // over limit → fastDelete
	rng := "abcd"
	dir := filepath.Join(ch.settings.CacheDir, "ab", "cd")
	os.MkdirAll(dir, 0o755)
	f := ParseHVFile("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd-4-jpg")
	writeFile(t, filepath.Join(dir, f.Fileid()), []byte("oldd"))
	mtime := time.Now().Add(-time.Duration(ageDays) * 24 * time.Hour)
	os.Chtimes(filepath.Join(dir, f.Fileid()), mtime, mtime)
	ch.mu.Lock()
	ch.staticRangeOldest[rng] = mtime.UnixMilli()
	ch.cacheCount = 1
	ch.cacheSize = 4
	ch.mu.Unlock()
	ch.CheckAndPruneCache()
	_, kept := ch.Lookup(f.Fileid())
	return !kept // pruned?
}

func TestCachePruneTierUnderOneMonth(t *testing.T) {
	// < 1 month tier: cutoff = oldest + 1 day. File aged 5d, oldest=5d → pruned.
	if !pruneWithTier(t, 5) {
		t.Fatal("5-day-old file should be pruned in the <1mo tier (cutoff = oldest+1d)")
	}
}

func TestCachePruneTierOneToThreeMonths(t *testing.T) {
	// 1-3 month tier: cutoff = oldest + 3d. File aged 40d, oldest=40d → pruned.
	if !pruneWithTier(t, 40) {
		t.Fatal("40-day-old file should be pruned in the 1-3mo tier")
	}
}

func TestCachePruneTierThreeToSixMonths(t *testing.T) {
	// 3-6 month tier: cutoff = oldest + 7d. File aged 100d → pruned.
	if !pruneWithTier(t, 100) {
		t.Fatal("100-day-old file should be pruned in the 3-6mo tier")
	}
}

func TestCachePersistentSaveLoadViaTerminate(t *testing.T) {
	ch, _ := buildCacheNoPruner(t)
	f := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-6-jpg")
	src := filepath.Join(ch.settings.TempDir, "src")
	os.WriteFile(src, []byte("abcdef"), 0o644)
	ch.ImportFileToCache(src, f)
	ch.TerminateCache() // savePersistent

	other, _ := buildCacheNoPruner(t)
	other.settings = ch.settings // same dirs
	if !other.loadPersistent() {
		t.Fatal("persistent load should succeed after TerminateCache")
	}
	if other.CacheCount() != 1 {
		t.Fatalf("restored count = %d", other.CacheCount())
	}
}
