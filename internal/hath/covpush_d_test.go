package hath

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	sslmate "software.sslmate.com/src/go-pkcs12"
)

// --- cache.go branches ---

func TestCacheOrphanPurge(t *testing.T) {
	s := NewSettings()
	s.ClientID = testClientID
	s.ClientKey = testClientKey
	dir := t.TempDir()
	s.CacheDir = filepath.Join(dir, "cache")
	s.TempDir = filepath.Join(dir, "tmp")
	s.DataDir = filepath.Join(dir, "data")
	os.MkdirAll(s.CacheDir, 0o755)
	os.MkdirAll(s.TempDir, 0o755)
	os.MkdirAll(s.DataDir, 0o755)
	// a stray file in tmp that is not log_/pcache/client_login → removed
	os.WriteFile(filepath.Join(s.TempDir, "stray.tmp"), []byte("x"), 0o644)
	ch, err := NewCacheHandler(&HathClient{settings: s, stats: NewStats()})
	if err != nil {
		t.Fatal(err)
	}
	defer ch.pruner.stop()
	if _, err := os.Stat(filepath.Join(s.TempDir, "stray.tmp")); !os.IsNotExist(err) {
		t.Fatal("stray tmp file should have been purged")
	}
}

func TestMarkRecentlyAccessedEdges(t *testing.T) {
	ch, _ := buildCacheNoPruner(t)
	// short Fileid (empty hash) → returns true without touching LRU
	if !ch.MarkRecentlyAccessed(&HVFile{Hash: "", Size: 5, Type: "jpg"}) {
		t.Fatal("short fileid → true")
	}
	// normal fileid → marks
	if !ch.MarkRecentlyAccessed(ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-5-jpg")) {
		t.Fatal("normal fileid should mark")
	}
}

func TestMarkRecentlyAccessedChtimesOld(t *testing.T) {
	ch, _ := buildCacheNoPruner(t)
	f := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-5-jpg")
	writeCacheFile(t, ch, f, []byte("hello")) // 5 bytes == f.Size
	// backdate mtime > 7 days so the chtimes branch runs
	old := time.Now().Add(-8 * 24 * time.Hour)
	os.Chtimes(ch.LocalPath(f), old, old)
	if !ch.MarkRecentlyAccessed(f) {
		t.Fatal("mark should succeed")
	}
}

func TestIsFileVerificationOnCooldownTwice(t *testing.T) {
	ch, _ := buildCacheNoPruner(t)
	if ch.IsFileVerificationOnCooldown() {
		t.Fatal("first call should not be on cooldown")
	}
	if !ch.IsFileVerificationOnCooldown() {
		t.Fatal("second call within 2s should be on cooldown")
	}
}

func TestParseHexUpperAndCopyFileError(t *testing.T) {
	if n, ok := parseHex("ABCDEF"); n != 0xABCDEF || !ok {
		t.Fatalf("uppercase hex wrong: %d %v", n, ok)
	}
	// copyFile with a missing source → error
	if err := copyFile(filepath.Join(t.TempDir(), "nope"), filepath.Join(t.TempDir(), "dst")); err == nil {
		t.Fatal("expected copy error for missing source")
	}
}

func TestCheckAndPruneCadenceAndEmptyRange(t *testing.T) {
	ch, s := buildCacheNoPruner(t)
	// no over-limit, plenty of free space (huge limit) → cadence branch (free > 10x)
	s.DiskLimit = 2_000_000_000
	ch.CheckAndPruneCache()
	_ = s
	// over-limit but no populated static range → pruneRange stays "" → Warn+return
	s.DiskLimit = 1 // tiny limit so any file overflows
	f := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-5-jpg")
	writeCacheFile(t, ch, f, []byte("hello"))
	s.StaticRangeCount = 1
	ch.CheckAndPruneCache()
}

func TestCheckAndPruneActuallyPrunes(t *testing.T) {
	ch, s := buildCacheNoPruner(t)
	s.DiskLimit = 1
	s.StaticRangeCount = 1
	// create a static-range dir with one file and register its age
	rangeDir := filepath.Join(s.CacheDir, "aa", "bb")
	os.MkdirAll(rangeDir, 0o755)
	os.WriteFile(filepath.Join(rangeDir, "abcdef0123456789abcdef0123456789abcdef01-5-jpg"), []byte("hello"), 0o644)
	ch.mu.Lock()
	ch.staticRangeOldest["aabb"] = time.Now().Add(-100 * 24 * time.Hour).UnixMilli()
	ch.cacheCount = 1
	ch.cacheSize = 5
	ch.mu.Unlock()
	ch.CheckAndPruneCache()
}

func TestStartCacheCleanupDieErr(t *testing.T) {
	s := NewSettings()
	s.ClientID = testClientID
	s.ClientKey = testClientKey
	dir := t.TempDir()
	s.CacheDir = filepath.Join(dir, "notadir") // a file where a dir is expected
	os.WriteFile(s.CacheDir, []byte("x"), 0o644)
	s.TempDir = filepath.Join(dir, "tmp")
	s.DataDir = filepath.Join(dir, "data")
	os.MkdirAll(s.TempDir, 0o755)
	os.MkdirAll(s.DataDir, 0o755)
	old := fatalError
	called := false
	fatalError = func(string) { called = true; panic("cleandie") }
	defer func() { fatalError = old }()
	defer func() { recover() }()
	_, _ = NewCacheHandler(&HathClient{settings: s, stats: NewStats()})
	if !called {
		t.Fatal("expected dieErr when cache dir is unreadable")
	}
}

func TestSleepDelayBothPaths(t *testing.T) {
	sleepDelay(true)  // 100ms (covered via prunes too, but explicit)
	sleepDelay(false) // 1s slow path
}

// --- client.go cycle + Run ---

func TestCycleAllBranches(t *testing.T) {
	hs, s, cache, _ := buildTestServer(t)
	_, _, rpc := newMockRPC(t)
	c := NewHathClient(s, NewStats())
	c.rpc = rpc
	c.cache = cache
	c.server = hs
	// normal cycle (counter 0 → StillAlive; server cert not expired)
	hs.cert.expiry = time.Now().Add(48 * time.Hour)
	c.counter = 0
	c.cycle()
	// %6==2 → PruneFloodControl
	c.counter = 2
	c.cycle()
	// %30==1 + large serverTimeDelta → Warn
	s.serverTimeDelta = 100000
	c.counter = 31
	c.cycle()
	s.serverTimeDelta = 0
	// %1440==1439 → ClearRPCServerFailure
	c.counter = 1439
	c.cycle()
	// %2160==2159 → ProcessBlacklist
	c.counter = 2159
	c.cycle()
	// suspended in future → early return
	c.suspendedUntil = time.Now().Add(time.Hour)
	c.counter = 0
	c.cycle()
	// suspended in past → clear + NotifyResume
	c.suspendedUntil = time.Now().Add(-time.Hour)
	c.cycle()
}

func TestCycleCertExpiredDieErr(t *testing.T) {
	hs, s, cache, _ := buildTestServer(t)
	_, _, rpc := newMockRPC(t)
	c := NewHathClient(s, NewStats())
	c.rpc = rpc
	c.cache = cache
	c.server = hs
	hs.cert.expiry = time.Now().Add(-time.Hour) // expired → dieErr
	c.counter = 31
	old := fatalError
	called := false
	fatalError = func(string) { called = true; panic("certexp") }
	defer func() { fatalError = old }()
	defer func() { recover() }()
	c.cycle()
	if !called {
		t.Fatal("expected dieErr on expired cert")
	}
}

func TestRunNoCreds(t *testing.T) {
	s := NewSettings()
	s.DataDir = t.TempDir()
	os.MkdirAll(s.DataDir, 0o755)
	c := NewHathClient(s, NewStats())
	old := fatalError
	called := false
	fatalError = func(string) { called = true; panic("nocreds") }
	defer func() { fatalError = old }()
	func() {
		defer func() { recover() }()
		c.Run(context.Background())
	}()
	if !called {
		t.Fatal("expected dieErr for missing credentials")
	}
}

func TestRunStartupAndLoop(t *testing.T) {
	c, m, s, _ := baseRunClient(t)
	s.ClientID = testClientID
	s.ClientKey = testClientKey
	leaf, key := genCert(t)
	p12, err := sslmate.LegacyRC2.Encode(key, leaf, nil, testClientKey)
	if err != nil {
		t.Fatal(err)
	}
	m.certBytes = p12
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(1500*time.Millisecond, cancel) // let one cycle run, then cancel
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	select {
	case err := <-done:
		_ = err
	case <-time.After(8 * time.Second):
		t.Fatal("Run did not return in time")
	}
}

// --- pruner.go loop (periodic + disk-watch branches) ---

func TestPrunerLoopTicks(t *testing.T) {
	ch, _ := buildCacheNoPruner(t)
	c := &HathClient{settings: ch.settings, stats: NewStats()}
	p := &CachePruner{cache: ch, client: c, diskInt: 0, stopCh: make(chan struct{})}
	go p.loop()
	time.Sleep(1200 * time.Millisecond)
	p.stop()
}

// --- gallery.go loop branches ---

func TestGalleryLoopNoPending(t *testing.T) {
	s := NewSettings()
	s.DownloadDir = t.TempDir()
	s.MaxAllowedFile = 1 << 30
	m, _, rpc := newMockRPC(t)
	m.setResponse("fetchqueue", "NO_PENDING_DOWNLOADS\n")
	old := gallerySleep
	gallerySleep = func(time.Duration) {}
	defer func() { gallerySleep = old }()
	c := NewHathClient(s, NewStats())
	c.rpc = rpc
	g := NewGalleryDownloader(c)
	for i := 0; i < 50; i++ {
		if c.gallery == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = g
}

func TestGalleryLoopDownloads(t *testing.T) {
	content := []byte("A")
	hash := sha1Hex(string(content))
	s := NewSettings()
	s.DownloadDir = t.TempDir()
	s.MaxAllowedFile = 1 << 30
	m, _, rpc := newMockRPC(t)
	m.setResponse("fetchqueue", "OK\nGID 1\nFILECOUNT 1\nMINXRES org\nTITLE G\nFILELIST\n1 0 org "+hash+" jpg p\nINFORMATION\n")
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(content)))
		w.Write(content)
	}))
	defer origin.Close()
	m.setResponse(ActDownloaderFetch, "OK\n"+origin.URL+"/f\n")
	old := gallerySleep
	gallerySleep = func(time.Duration) {}
	defer func() { gallerySleep = old }()
	c := NewHathClient(s, NewStats())
	c.rpc = rpc
	NewGalleryDownloader(c)
	// wait for the file to land, then stop the loop
	done := false
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(filepath.Join(s.DownloadDir, "G [1]", "p.jpg")); err == nil {
			done = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	c.shutdown = true
	if !done {
		t.Fatal("gallery file was not downloaded")
	}
}

func TestGalleryLoopDownloadFails(t *testing.T) {
	hash := sha1Hex("A")
	s := NewSettings()
	s.DownloadDir = t.TempDir()
	s.MaxAllowedFile = 1 << 30
	m, _, rpc := newMockRPC(t)
	m.setResponse("fetchqueue", "OK\nGID 1\nFILECOUNT 1\nMINXRES org\nTITLE G\nFILELIST\n1 0 org "+hash+" jpg p\nINFORMATION\n")
	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", 404)
	}))
	defer fail.Close()
	m.setResponse(ActDownloaderFetch, "OK\n"+fail.URL+"/f\n")
	old := gallerySleep
	gallerySleep = func(time.Duration) {}
	defer func() { gallerySleep = old }()
	c := NewHathClient(s, NewStats())
	c.rpc = rpc
	NewGalleryDownloader(c)
	// let the retry loop exhaust, then stop
	time.AfterFunc(800*time.Millisecond, func() { c.shutdown = true })
	for i := 0; i < 100; i++ {
		if c.gallery == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestGalleryLoopSuspendedAndLowSpace(t *testing.T) {
	hash := sha1Hex("A")
	s := NewSettings()
	s.DownloadDir = t.TempDir()
	s.MaxAllowedFile = 1 << 30
	m, _, rpc := newMockRPC(t)
	m.setResponse("fetchqueue", "OK\nGID 1\nFILECOUNT 1\nMINXRES org\nTITLE G\nFILELIST\n1 0 org "+hash+" jpg p\nINFORMATION\n")
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1")
		w.Write([]byte("A"))
	}))
	defer origin.Close()
	m.setResponse(ActDownloaderFetch, "OK\n"+origin.URL+"/f\n")
	old := gallerySleep
	gallerySleep = func(time.Duration) {}
	defer func() { gallerySleep = old }()
	c := NewHathClient(s, NewStats())
	c.rpc = rpc
	// pre-place the file so the per-file loop runs instantly (dlAlready)
	todir := filepath.Join(s.DownloadDir, "G [1]")
	os.MkdirAll(todir, 0o755)
	os.WriteFile(filepath.Join(todir, "p.jpg"), []byte("A"), 0o644)
	c.suspendedUntil = time.Now().Add(time.Hour)
	NewGalleryDownloader(c)
	time.AfterFunc(400*time.Millisecond, func() {
		c.suspendedUntil = time.Time{}
		// now low-space so the loop hits the 5min-sleep branch (no-op here)
		s.DiskMinRemaining = 1 << 50
	})
	time.AfterFunc(900*time.Millisecond, func() { c.shutdown = true })
	for i := 0; i < 100; i++ {
		if c.gallery == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
}
