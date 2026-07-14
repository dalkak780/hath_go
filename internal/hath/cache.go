package hath

// CacheHandler manages the on-disk file cache: cache/xx/yy/<fileid>.
// Counts, LRU bookkeeping, blacklist pruning, and (optional) SHA-1 integrity
// checks live here. The persistent format is a local concern (not on the wire),
// so we use encoding/gob instead of the original bespoke binary layout.

import (
	"crypto/sha1"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const lruCacheSize = 1048576

// persistentCache is serialized to data/pcache for fast startup.
type persistentCache struct {
	Count int64
	Size  int64
	LRU   []uint16
}

// CacheHandler manages cached files.
type CacheHandler struct {
	settings *Settings
	stats    *Stats

	mu               sync.Mutex
	cacheCount       int64
	cacheSize        int64
	lru              []uint16
	lruClearPointer  int
	staticRangeOldest map[string]int64
	lastFileVerify   time.Time
}

// NewCacheHandler initializes the cache, scanning the cache dir if no valid
// persistent snapshot exists.
func NewCacheHandler(s *Settings, stats *Stats) (*CacheHandler, error) {
	c := &CacheHandler{
		settings:          s,
		stats:             stats,
		lru:               make([]uint16, lruCacheSize),
		staticRangeOldest: make(map[string]int64),
	}
	// purge orphans from tmp
	if entries, err := os.ReadDir(s.TempDir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			n := e.Name()
			if !startsWith(n, "log_") && !startsWith(n, "pcache_") && n != "client_login" {
				os.Remove(filepath.Join(s.TempDir, n))
			}
		}
	}

	if !s.RescanCache && c.loadPersistent() {
		Info("cache handler: loaded persistent cache data")
	} else {
		Info("cache handler: scanning cache directory...")
		if err := c.scanCache(); err != nil {
			return nil, err
		}
		c.savePersistent()
	}

	c.updateStats()

	if c.cacheCount < 1 && s.StaticRangeCount > 20 {
		return nil, errf("cache is empty but %d static ranges are assigned; reset ranges at "+
			"https://e-hentai.org/hentaiathome.php?cid=%d", s.StaticRangeCount, s.ClientID)
	}
	return c, nil
}

// LocalPath returns the on-disk path for a file.
func (c *CacheHandler) LocalPath(f *HVFile) string {
	return filepath.Join(c.settings.CacheDir, f.Hash[:2], f.Hash[2:4], f.Fileid())
}

// Lookup returns the parsed file if the id is valid and the cached file exists
// with the correct size.
func (c *CacheHandler) Lookup(fileid string) (*HVFile, bool) {
	f := ParseHVFile(fileid)
	if f == nil {
		return nil, false
	}
	fi, err := os.Stat(c.LocalPath(f))
	if err != nil || fi.Size() != f.Size {
		return f, false
	}
	return f, true
}

// MarkRecentlyAccessed updates the LRU bit table. Returns false if the file was
// already marked within the current window (i.e. skip metadata update).
func (c *CacheHandler) MarkRecentlyAccessed(f *HVFile) bool {
	fileid := f.Fileid()
	if len(fileid) < 10 {
		return true
	}
	arrayIndex, ok1 := parseHex(fileid[4:9])
	bit, ok2 := parseHex(fileid[9:10])
	if !ok1 || !ok2 {
		return true
	}
	bitMask := uint16(1 << bit)

	c.mu.Lock()
	mark := true
	if c.lru[arrayIndex]&bitMask != 0 {
		mark = false
	} else {
		c.lru[arrayIndex] |= bitMask
	}
	c.mu.Unlock()

	if mark {
		// bump mtime if older than a week (limits metadata churn)
		path := c.LocalPath(f)
		now := time.Now()
		if fi, err := os.Stat(path); err == nil && fi.ModTime().Before(now.Add(-7*24*time.Hour)) {
			os.Chtimes(path, now, now)
		}
	}
	return mark
}

// IsFileVerificationOnCooldown allows one SHA-1 verification per 2s.
func (c *CacheHandler) IsFileVerificationOnCooldown() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if c.lastFileVerify.After(now.Add(-2 * time.Second)) {
		return true
	}
	c.lastFileVerify = now
	return false
}

// VerifyFile checks the SHA-1 of a cached file against its id.
func (c *CacheHandler) VerifyFile(f *HVFile) bool {
	h := sha1.New()
	fl, err := os.Open(c.LocalPath(f))
	if err != nil {
		return false
	}
	defer fl.Close()
	if _, err := io.Copy(h, fl); err != nil {
		return false
	}
	return hex.EncodeToString(h.Sum(nil)) == f.Hash
}

// DeleteFileFromCache removes a file and decrements counters.
func (c *CacheHandler) DeleteFileFromCache(f *HVFile) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := os.Remove(c.LocalPath(f)); err == nil {
		c.cacheCount--
		c.cacheSize -= f.Size
		c.updateStatsLocked()
	}
}

// ProcessBlacklist deletes any cached file listed by the server.
func (c *CacheHandler) ProcessBlacklist(rpc *ServerHandler, deltatime int64) {
	Info("cache handler: retrieving blacklist...")
	blacklisted := rpc.GetBlacklist(deltatime)
	if blacklisted == nil {
		Warn("cache handler: failed to retrieve blacklist; will retry later")
		return
	}
	removed := 0
	for _, fileid := range blacklisted {
		f, ok := c.Lookup(fileid)
		if f != nil && ok {
			c.DeleteFileFromCache(f)
			removed++
		}
	}
	Info("cache handler: removed blacklisted files", "count", removed)
}

// CycleLRUCacheTable clears 17 shorts per call (a ~1-week rotation).
func (c *CacheHandler) CycleLRUCacheTable() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clearUntil := c.lruClearPointer + 17
	if clearUntil > lruCacheSize {
		clearUntil = lruCacheSize
	}
	for c.lruClearPointer < clearUntil {
		c.lru[c.lruClearPointer] = 0
		c.lruClearPointer++
	}
	if clearUntil >= lruCacheSize {
		c.lruClearPointer = 0
	}
}

// CacheCount returns the current file count.
func (c *CacheHandler) CacheCount() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cacheCount
}

// TerminateCache persists state for the next startup.
func (c *CacheHandler) TerminateCache() {
	c.savePersistent()
}

// --- internals ---

func (c *CacheHandler) updateStats() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.updateStatsLocked()
}

func (c *CacheHandler) updateStatsLocked() {
	if c.stats != nil {
		c.stats.SetCacheCount(int(c.cacheCount))
		c.stats.SetCacheSize(c.cacheSize)
	}
}

func (c *CacheHandler) scanCache() error {
	c.mu.Lock()
	c.cacheCount = 0
	c.cacheSize = 0
	c.staticRangeOldest = make(map[string]int64)
	c.mu.Unlock()

	return filepath.WalkDir(c.settings.CacheDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		f := ParseHVFile(d.Name())
		if f == nil {
			return nil
		}
		fi, err := d.Info()
		if err != nil || fi.Size() != f.Size {
			return nil // wrong size; will be re-fetched on demand
		}
		c.mu.Lock()
		c.cacheCount++
		c.cacheSize += f.Size
		if oldest, ok := c.staticRangeOldest[f.StaticRange()]; !ok || fi.ModTime().UnixMilli() < oldest {
			c.staticRangeOldest[f.StaticRange()] = fi.ModTime().UnixMilli()
		}
		c.mu.Unlock()
		return nil
	})
}

func (c *CacheHandler) persistentPath() string {
	return filepath.Join(c.settings.DataDir, "pcache")
}

func (c *CacheHandler) loadPersistent() bool {
	f, err := os.Open(c.persistentPath())
	if err != nil {
		return false
	}
	defer f.Close()
	var p persistentCache
	if err := gob.NewDecoder(f).Decode(&p); err != nil {
		return false
	}
	if len(p.LRU) != lruCacheSize {
		return false
	}
	c.mu.Lock()
	c.cacheCount = p.Count
	c.cacheSize = p.Size
	copy(c.lru, p.LRU)
	c.mu.Unlock()
	return true
}

func (c *CacheHandler) savePersistent() {
	c.mu.Lock()
	p := persistentCache{Count: c.cacheCount, Size: c.cacheSize, LRU: append([]uint16(nil), c.lru...)}
	c.mu.Unlock()
	tmp := c.persistentPath() + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return
	}
	if err := gob.NewEncoder(f).Encode(p); err != nil {
		f.Close()
		os.Remove(tmp)
		return
	}
	f.Close()
	os.Rename(tmp, c.persistentPath())
}

func startsWith(s, prefix string) bool { return len(s) >= len(prefix) && s[:len(prefix)] == prefix }

func parseHex(s string) (int, bool) {
	n := 0
	for _, r := range s {
		var v int
		switch {
		case r >= '0' && r <= '9':
			v = int(r - '0')
		case r >= 'a' && r <= 'f':
			v = int(r-'a') + 10
		case r >= 'A' && r <= 'F':
			v = int(r-'A') + 10
		default:
			return 0, false
		}
		n = n*16 + v
	}
	return n, true
}

func errf(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}
