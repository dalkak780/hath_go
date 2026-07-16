package hath

// CacheHandler manages the on-disk file cache: cache/xx/yy/<fileid>.
// This is a faithful port of the original CacheHandler — counts, per-static-range
// oldest-mtime tracking, LRU bit-table, blacklist pruning, optional SHA-1
// integrity verification, and age-weighted pruning. The persistent snapshot
// format is a local concern (not on the wire), so we use encoding/gob instead
// of the original bespoke layout.

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

const (
	lruCacheSize = 1048576
	weekMs       = int64(604800000)
)

// persistentCache is serialized to data/pcache for fast startup.
type persistentCache struct {
	Count             int64
	Size              int64
	LRUClearPointer   int
	LRU               []uint16
	StaticRangeOldest map[string]int64
}

// CacheHandler manages cached files.
type CacheHandler struct {
	client   *HathClient
	settings *Settings
	stats    *Stats
	pruner   *CachePruner

	mu                sync.Mutex
	cacheCount        int64
	cacheSize         int64
	lru               []uint16
	lruClearPointer   int
	staticRangeOldest map[string]int64
	lastFileVerify    time.Time
}

// NewCacheHandler initializes the cache. It relocates stray files, scans the
// cache to compute counts/sizes and the per-range age table, and starts the
// pruner goroutine.
func NewCacheHandler(c *HathClient) (*CacheHandler, error) {
	s, stats := c.settings, c.stats
	ch := &CacheHandler{
		client:            c,
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
			if !startsWith(n, "log_") && !startsWith(n, "pcache") && n != "client_login" {
				os.Remove(filepath.Join(s.TempDir, n))
			}
		}
	}

	// The filesystem is authoritative. A snapshot can be stale after an
	// unclean exit, so trusting one can resurrect deleted entries or omit
	// completed imports. Scanning also accepts an existing Java cache directly.
	Info("cache handler: initializing the cache system...")
	ch.startupCacheCleanup()
	if c.IsShuttingDown() {
		return ch, nil
	}
	if err := ch.startupInitCache(); err != nil {
		return nil, err
	}
	ch.updateStats()

	// free-space sanity check
	if !s.SkipFreeSpaceCheck {
		free := dirFreeBytes(s.CacheDir)
		if s.DiskLimit > 0 && free < s.DiskLimit-ch.cacheSizeWithOverheadLocked() {
			return nil, fmt.Errorf("storage device lacks space for the configured cache size (free=%d). Free space or reduce the cache at https://e-hentai.org/hentaiathome.php?cid=%d", free, s.ClientID)
		}
	}

	if ch.CacheCount() < 1 && s.StaticRangeCount > 20 {
		return nil, fmt.Errorf("cache is empty but %d static ranges are assigned; reset ranges at https://e-hentai.org/hentaiathome.php?cid=%d", s.StaticRangeCount, s.ClientID)
	}

	ch.pruner = newCachePruner(ch, c)
	return ch, nil
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
// already marked within the current window.
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
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.verifyFileLocked(f)
}

func (c *CacheHandler) verifyFileLocked(f *HVFile) bool {
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

// DeleteIfCorrupt verifies and removes the same path under one lock, so a
// concurrent import cannot be mistaken for the file that was checked.
func (c *CacheHandler) DeleteIfCorrupt(f *HVFile) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.verifyFileLocked(f) {
		return false
	}
	if err := os.Remove(c.LocalPath(f)); err != nil {
		return false
	}
	c.cacheCount--
	c.cacheSize -= f.Size
	c.updateStatsLocked()
	if dir := filepath.Dir(c.LocalPath(f)); dirIsEmpty(dir) {
		os.Remove(dir)
		delete(c.staticRangeOldest, f.StaticRange())
	}
	return true
}

// DeleteFileFromCache removes a file and decrements counters.
func (c *CacheHandler) DeleteFileFromCache(f *HVFile) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := os.Remove(c.LocalPath(f)); err == nil {
		c.cacheCount--
		c.cacheSize -= f.Size
		c.updateStatsLocked()
		// prune empty range dir to match original 1.6.5 behavior
		if dir := filepath.Dir(c.LocalPath(f)); dirIsEmpty(dir) {
			os.Remove(dir)
			delete(c.staticRangeOldest, f.StaticRange())
		}
	}
}

// ImportFileToCache moves a validated temp file into the cache and counts it.
func (c *CacheHandler) ImportFileToCache(tempPath string, f *HVFile) bool {
	c.mu.Lock()
	if fi, err := os.Stat(c.LocalPath(f)); err == nil && fi.Size() == f.Size {
		os.Remove(tempPath)
		c.mu.Unlock()
		return true
	}
	if !c.moveFileToCacheDir(tempPath, f) {
		c.mu.Unlock()
		return false
	}
	c.cacheCount++
	c.cacheSize += f.Size
	if _, ok := c.staticRangeOldest[f.StaticRange()]; !ok {
		c.staticRangeOldest[f.StaticRange()] = time.Now().UnixMilli()
	}
	c.updateStatsLocked()
	c.mu.Unlock()
	c.MarkRecentlyAccessed(f)
	return true
}

func (c *CacheHandler) moveFileToCacheDir(src string, f *HVFile) bool {
	dst := c.LocalPath(f)
	if err := os.MkdirAll(filepath.Dir(dst), 0o777); err != nil {
		return false
	}
	if err := os.Rename(src, dst); err != nil {
		// rename across devices can fail; fall back to copy
		if err := copyFile(src, dst); err != nil {
			return false
		}
		os.Remove(src)
	}
	return true
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

// CacheSizeWithOverhead returns cache size + half-block per-file slack.
func (c *CacheHandler) CacheSizeWithOverhead() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cacheSizeWithOverheadLocked()
}

func (c *CacheHandler) cacheSizeWithOverheadLocked() int64 {
	return c.cacheSize + c.cacheCount*c.settings.FSBlockSize/2
}

// HasFreeDiskSpace reports whether the storage device still has the minimum
// required free space.
func (c *CacheHandler) HasFreeDiskSpace() bool {
	if c.settings.SkipFreeSpaceCheck {
		return true
	}
	free := dirFreeBytes(c.settings.CacheDir)
	threshold := c.settings.DiskMinRemaining
	if threshold < 104857600 {
		threshold = 104857600
	}
	return free >= threshold
}

// CheckAndPruneCache frees space by deleting the oldest files in the oldest
// static range, using age-weighted cutoffs. Direct port of the original.
func (c *CacheHandler) CheckAndPruneCache() {
	const wantFree int64 = 104857600

	c.mu.Lock()
	cacheLimit := c.settings.DiskLimit
	cacheSize := c.cacheSize
	cacheSizeOH := c.cacheSizeWithOverheadLocked()
	cacheCount := c.cacheCount
	c.mu.Unlock()

	var bytesToFree int64
	fastDelete := false
	switch {
	case cacheSizeOH > cacheLimit:
		bytesToFree = wantFree + cacheSizeOH - cacheLimit
		fastDelete = true
	case cacheLimit-cacheSizeOH < wantFree:
		bytesToFree = wantFree - (cacheLimit - cacheSizeOH)
	}

	Debug("checked cache space", "cacheSize", cacheSize, "withOverhead", cacheSizeOH, "limit", cacheLimit)

	if bytesToFree <= 0 || cacheCount < 1 || c.settings.StaticRangeCount < 1 {
		// adjust pruner cadence based on headroom
		free := cacheLimit - cacheSizeOH
		switch {
		case free > wantFree*10:
			c.pruner.setCheckFrequency(600)
		case free > wantFree:
			c.pruner.setCheckFrequency(60)
		default:
			c.pruner.setCheckFrequency(10)
		}
		return
	}

	c.mu.Lock()
	var pruneRange string
	now := time.Now().UnixMilli()
	oldestAge := now
	for r, age := range c.staticRangeOldest {
		if age < oldestAge {
			oldestAge = age
			pruneRange = r
		}
	}
	if pruneRange == "" {
		c.mu.Unlock()
		Warn("failed to find aged static range to prune")
		return
	}
	rangeDir := filepath.Join(c.settings.CacheDir, pruneRange[:2], pruneRange[2:4])

	// age-weighted cutoff
	cutoff := oldestAge
	switch {
	case oldestAge < now-15552000000: // > 6 months
		cutoff += 2592000000 // +30d
	case oldestAge < now-7776000000: // > 3 months
		cutoff += 604800000 // +7d
	case oldestAge < now-2592000000: // > 1 month
		cutoff += 259200000 // +3d
	default:
		cutoff += 86400000 // +1d
	}
	c.mu.Unlock()

	Info("pruning to free space", "bytes", bytesToFree, "range", pruneRange)

	fi, err := os.Stat(rangeDir)
	if err != nil || !fi.IsDir() {
		c.mu.Lock()
		delete(c.staticRangeOldest, pruneRange)
		c.mu.Unlock()
		Warn("removed age cache for missing range dir", "range", pruneRange)
		return
	}

	files, _ := os.ReadDir(rangeDir)
	oldestRemaining := now
	remaining := 0
	for _, e := range files {
		if c.client.IsShuttingDown() {
			return
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		lm := info.ModTime().UnixMilli()
		if lm >= cutoff {
			if lm < oldestRemaining {
				oldestRemaining = lm
			}
			remaining++
			continue
		}
		f := ParseHVFile(e.Name())
		if f == nil {
			os.Remove(filepath.Join(rangeDir, e.Name()))
			continue
		}
		c.DeleteFileFromCache(f)
		Debug("pruned file", "fileid", f.Fileid(), "mtime", lm)
		sleepDelay(fastDelete) // 100ms fast / 1000ms normal, to ease disk spikes
	}

	c.mu.Lock()
	if remaining > 0 {
		c.staticRangeOldest[pruneRange] = oldestRemaining
	} else {
		os.Remove(rangeDir)
		delete(c.staticRangeOldest, pruneRange)
		Debug("removed age cache for empty range", "range", pruneRange)
	}
	c.mu.Unlock()

	c.pruner.setCheckFrequency(0)
}

// TerminateCache persists state for the next startup.
func (c *CacheHandler) TerminateCache() { c.savePersistent() }

// --- startup passes ---

// startupCacheCleanup relocates stray files sitting directly in L1 dirs.
func (c *CacheHandler) startupCacheCleanup() {
	Info("cache handler: cache cleanup pass..")
	l1, err := os.ReadDir(c.settings.CacheDir)
	if err != nil {
		dieErr("cache handler: cannot access cache dir: " + err.Error())
		return
	}
	if len(l1) > c.settings.StaticRangeCount && c.settings.StaticRangeCount > 0 {
		Warn("more cache subdirs than assigned static ranges; waiting 30s", "dirs", len(l1), "ranges", c.settings.StaticRangeCount)
		time.Sleep(30 * time.Second)
	}
	if c.client.IsShuttingDown() {
		return
	}
	for _, e1 := range l1 {
		if !e1.IsDir() {
			os.Remove(filepath.Join(c.settings.CacheDir, e1.Name()))
			continue
		}
		l2, err := os.ReadDir(filepath.Join(c.settings.CacheDir, e1.Name()))
		if err != nil {
			continue
		}
		if len(l2) == 0 {
			os.Remove(filepath.Join(c.settings.CacheDir, e1.Name()))
			continue
		}
		for _, e2 := range l2 {
			if e2.IsDir() {
				continue
			}
			// stray file at L1 level → relocate
			full := filepath.Join(c.settings.CacheDir, e1.Name(), e2.Name())
			f := ParseHVFile(e2.Name())
			if f == nil {
				os.Remove(full)
			} else if !c.settings.IsStaticRange(f.Fileid()) {
				os.Remove(full)
			} else {
				c.moveFileToCacheDir(full, f)
			}
		}
	}
}

// startupInitCache scans the cache, counting files and building the per-range
// age table. With --verify-cache, each file's SHA-1 is checked.
func (c *CacheHandler) startupInitCache() error {
	if c.settings.VerifyCache {
		Info("cache handler: loading cache with full file verification (may take a while)")
	} else {
		Info("cache handler: loading cache...")
	}
	cutoff := time.Now().Add(-7 * 24 * time.Hour).UnixMilli()
	foundRanges := 0

	return walkRangeDirs(c.settings.CacheDir, func(l1, l2 string, files []os.DirEntry) {
		if c.client.IsShuttingDown() {
			return
		}
		if len(files) == 0 {
			os.Remove(filepath.Join(c.settings.CacheDir, l1, l2))
			return
		}
		oldest := time.Now().UnixMilli()
		validFiles := 0
		for _, fe := range files {
			fi, err := fe.Info()
			if err != nil {
				continue
			}
			full := filepath.Join(c.settings.CacheDir, l1, l2, fe.Name())
			f := ParseHVFile(fe.Name())
			valid := f != nil
			if valid && c.settings.VerifyCache {
				if !validateFileSHA1(full, f.Hash) {
					valid = false
				}
			}
			if valid && fi.Size() != f.Size {
				valid = false
			}
			if valid && !c.settings.IsStaticRange(f.Fileid()) {
				valid = false
			}
			if !valid {
				os.Remove(full)
				continue
			}
			c.mu.Lock()
			c.cacheCount++
			c.cacheSize += f.Size
			c.mu.Unlock()
			validFiles++
			lm := fi.ModTime().UnixMilli()
			if lm > cutoff {
				c.MarkRecentlyAccessed(f)
			}
			if lm < oldest {
				oldest = lm
			}
		}
		if validFiles > 0 {
			c.mu.Lock()
			c.staticRangeOldest[l1+l2] = oldest
			c.mu.Unlock()
			foundRanges++
		} else {
			os.Remove(filepath.Join(c.settings.CacheDir, l1, l2))
		}
		if foundRanges%100 == 0 {
			Info("cache handler: found ranges so far", "count", foundRanges)
		}
	})
}

// --- persistence ---

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
	c.lruClearPointer = p.LRUClearPointer
	copy(c.lru, p.LRU)
	if p.StaticRangeOldest != nil {
		c.staticRangeOldest = p.StaticRangeOldest
	}
	c.mu.Unlock()
	return true
}

func (c *CacheHandler) savePersistent() {
	c.mu.Lock()
	p := persistentCache{
		Count:             c.cacheCount,
		Size:              c.cacheSize,
		LRUClearPointer:   c.lruClearPointer,
		LRU:               append([]uint16(nil), c.lru...),
		StaticRangeOldest: copyRangeMap(c.staticRangeOldest),
	}
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

// --- helpers ---

func (c *CacheHandler) updateStats() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.updateStatsLocked()
}

func (c *CacheHandler) updateStatsLocked() {
	if c.stats != nil {
		c.stats.SetCacheCount(int(c.cacheCount))
		c.stats.SetCacheSize(c.cacheSizeWithOverheadLocked())
	}
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

func copyRangeMap(m map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func dirIsEmpty(path string) bool {
	entries, err := os.ReadDir(path)
	if err != nil {
		return false
	}
	return len(entries) == 0
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func dirFreeBytes(path string) int64 {
	return diskFree(path)
}

func sleepDelay(fast bool) {
	if fast {
		time.Sleep(100 * time.Millisecond)
	} else {
		time.Sleep(time.Second)
	}
}
