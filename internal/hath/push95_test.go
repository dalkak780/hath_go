package hath

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// --- tiny helpers at 0% / low coverage ---

func TestStartsWith(t *testing.T) {
	if !startsWith("abcdef", "abc") {
		t.Fatal("should match prefix")
	}
	if startsWith("ab", "abc") {
		t.Fatal("short string should not match longer prefix")
	}
	if startsWith("xyz", "abc") {
		t.Fatal("should not match different prefix")
	}
}

func TestLimitReaderRead(t *testing.T) {
	src := bytes.NewReader([]byte("hello world"))
	lim := NewBandwidthMonitor(0)
	lr := &limitReader{r: src, lim: lim}
	buf := make([]byte, 4)
	n, err := lr.Read(buf)
	if n != 4 || err != nil {
		t.Fatalf("read n=%d err=%v", n, err)
	}
	rest, _ := io.ReadAll(lr)
	if string(rest) != "o world" {
		t.Fatalf("remaining = %q", rest)
	}
}

func TestCertExpired(t *testing.T) {
	s := NewSettings()
	// expired cert
	cm := &CertManager{settings: s, expiry: time.Now().Add(-time.Hour)}
	if !cm.IsExpired() {
		t.Fatal("past expiry should be expired")
	}
	hs := &HTTPServer{cert: cm, settings: s}
	if !hs.CertExpired() {
		t.Fatal("HTTPServer.CertExpired should delegate to cert")
	}
	// not expired
	cm2 := &CertManager{settings: s, expiry: time.Now().Add(48 * time.Hour)}
	if cm2.IsExpired() {
		t.Fatal("future expiry should not be expired")
	}
}

func TestImageProxyPortOrDefault(t *testing.T) {
	s := NewSettings()
	s.ImageProxyPort = 0
	s.ImageProxyType = "http"
	if got := imageProxyPortOrDefault(s); got != 8080 {
		t.Fatalf("http default = %d", got)
	}
	s.ImageProxyType = "socks"
	if got := imageProxyPortOrDefault(s); got != 1080 {
		t.Fatalf("socks default = %d", got)
	}
	s.ImageProxyPort = 9999
	if got := imageProxyPortOrDefault(s); got != 9999 {
		t.Fatalf("explicit port = %d", got)
	}
}

func TestHostOf(t *testing.T) {
	if got := hostOf("http://example.com:81/path"); got != "example.com" {
		t.Fatalf("hostOf = %q", got)
	}
	if got := hostOf("://bad url"); got != "" {
		t.Fatalf("bad url should yield empty host, got %q", got)
	}
}

func TestIpOf(t *testing.T) {
	if got := ipOf("1.2.3.4:80"); got != "1.2.3.4" {
		t.Fatalf("ipOf = %q", got)
	}
	if got := ipOf("::1"); got != "::1" {
		t.Fatalf("ipOf (no port) = %q", got)
	}
}

func TestAbs64(t *testing.T) {
	if abs64(-5) != 5 {
		t.Fatal("abs64(-5) != 5")
	}
	if abs64(5) != 5 {
		t.Fatal("abs64(5) != 5")
	}
}

func TestHVFileFileidAndMime(t *testing.T) {
	f := HVFile{Hash: "abc", Size: 10, Xres: 2, Yres: 3, Type: "jpg"}
	if f.Fileid() != "abc-10-2-3-jpg" {
		t.Fatalf("fileid with xres = %q", f.Fileid())
	}
	noX := HVFile{Hash: "abc", Size: 10, Type: "png"}
	if noX.Fileid() != "abc-10-png" {
		t.Fatalf("fileid without xres = %q", noX.Fileid())
	}
	if (HVFile{Type: "jpg"}).Mime() != "image/jpeg" {
		t.Fatal("jpg mime wrong")
	}
	if (HVFile{Type: "bogus"}).Mime() != "application/octet-stream" {
		t.Fatal("unknown mime wrong")
	}
}

func TestDirIsEmpty(t *testing.T) {
	if dirIsEmpty(filepath.Join(t.TempDir(), "nope")) {
		t.Fatal("missing dir should not be empty")
	}
	d := t.TempDir()
	if !dirIsEmpty(d) {
		t.Fatal("empty dir should be empty")
	}
	os.WriteFile(filepath.Join(d, "x"), []byte("1"), 0o644)
	if dirIsEmpty(d) {
		t.Fatal("non-empty dir should not be empty")
	}
}

func TestSleepDelay(t *testing.T) {
	// fast path only to keep the suite quick
	start := time.Now()
	sleepDelay(true)
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("fast sleep should be ~100ms")
	}
}

func TestMoveFileToCacheDirError(t *testing.T) {
	ch, _ := buildCacheNoPruner(t)
	f := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-3-jpg")
	// pass a non-existent source: Rename fails, then copyFile cannot open it,
	// so the function returns false (covers the error branch).
	if ch.moveFileToCacheDir(filepath.Join(t.TempDir(), "does-not-exist"), f) {
		t.Fatal("move should fail for a missing source")
	}
}

func TestLoadLoginErrors(t *testing.T) {
	s := NewSettings()
	s.DataDir = t.TempDir()
	os.WriteFile(filepath.Join(s.DataDir, "client_login"), []byte("no dash here\n"), 0o644)
	if err := s.LoadLogin(); err == nil {
		t.Fatal("malformed client_login should error")
	}
	os.WriteFile(filepath.Join(s.DataDir, "client_login"), []byte("notnum-abcdefghijklmnopqrst\n"), 0o644)
	if err := s.LoadLogin(); err == nil {
		t.Fatal("non-numeric id should error")
	}
	os.WriteFile(filepath.Join(s.DataDir, "client_login"), []byte("1234-abcdefghijklmnopqrst\n"), 0o644)
	if err := s.LoadLogin(); err != nil {
		t.Fatal("valid client_login should not error")
	}
	if s.ClientID != 1234 || s.ClientKey != "abcdefghijklmnopqrst" {
		t.Fatalf("parsed login wrong: %d %q", s.ClientID, s.ClientKey)
	}
}

func TestVerifyFileMissing(t *testing.T) {
	ch, _ := buildCacheNoPruner(t)
	f := &HVFile{Hash: "abcdef0123456789abcdef0123456789abcdef01", Size: 5, Type: "jpg"}
	if ch.VerifyFile(f) {
		t.Fatal("verify of missing file should be false")
	}
}

func TestProcessBlacklistNilAndRemoved(t *testing.T) {
	m, s, rpc := newMockRPC(t)
	ch, _ := buildCacheNoPruner(t)
	ch.client = &HathClient{settings: s}
	// nil case: server returns a non-OK body -> GetBlacklist returns nil
	m.setResponse(ActGetBlacklist, "FAIL_X\n")
	ch.ProcessBlacklist(rpc, 43200)

	// removed case: import a file, then blacklist it
	f := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-5-jpg")
	src := filepath.Join(ch.settings.TempDir, "src")
	os.WriteFile(src, []byte("hello"), 0o644)
	if !ch.ImportFileToCache(src, f) {
		t.Fatal("import failed")
	}
	m.setResponse(ActGetBlacklist, "OK\n"+f.Fileid()+"\n")
	ch.ProcessBlacklist(rpc, 43200)
	if _, ok := ch.Lookup(f.Fileid()); ok {
		t.Fatal("blacklisted file should be removed")
	}
}

func TestParseHexInvalid(t *testing.T) {
	if _, ok := parseHex("zz"); ok {
		t.Fatal("non-hex should fail")
	}
	if n, ok := parseHex("ff"); !ok || n != 255 {
		t.Fatalf("parseHex(ff) = %d ok=%v", n, ok)
	}
}

func TestSavePersistentRoundTrip(t *testing.T) {
	ch, _ := buildCacheNoPruner(t)
	ch.cacheCount = 3
	ch.cacheSize = 15
	ch.savePersistent()
	if _, err := os.Stat(ch.persistentPath()); err != nil {
		t.Fatal("persistent file should exist")
	}
	// reload into a fresh handler
	ch2 := &CacheHandler{
		client:            ch.client,
		settings:          ch.settings,
		stats:             NewStats(),
		lru:               make([]uint16, lruCacheSize),
		staticRangeOldest: make(map[string]int64),
	}
	if !ch2.loadPersistent() {
		t.Fatal("loadPersistent should succeed")
	}
	if ch2.cacheCount != 3 || ch2.cacheSize != 15 {
		t.Fatalf("round trip count=%d size=%d", ch2.cacheCount, ch2.cacheSize)
	}
	// corrupt -> load fails
	os.WriteFile(ch2.persistentPath(), []byte("garbage"), 0o644)
	if ch2.loadPersistent() {
		t.Fatal("corrupt persistent should fail to load")
	}
}

// --- startupCacheCleanup branches (the 30s-wait branch is intentionally skipped) ---

func TestStartupCacheCleanupRelocateAndPrune(t *testing.T) {
	ch, s := buildCacheNoPruner(t)
	s.StaticRangeCount = 100 // avoid the 30s warning branch
	s.StaticRanges = map[string]bool{"abcd": true}
	ch.client = &HathClient{settings: s}

	// L1 stray non-dir file -> removed
	os.WriteFile(filepath.Join(s.CacheDir, "strayfile"), []byte("x"), 0o644)
	// empty L1 dir -> removed
	os.MkdirAll(filepath.Join(s.CacheDir, "zz"), 0o755)
	// valid static-range file placed directly at L1 (wrong depth) -> relocated
	os.MkdirAll(filepath.Join(s.CacheDir, "ab"), 0o755)
	good := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-5-jpg")
	os.WriteFile(filepath.Join(s.CacheDir, "ab", good.Fileid()), []byte("data"), 0o644)
	// invalid fileid at L1 -> removed
	os.WriteFile(filepath.Join(s.CacheDir, "ab", "notafile"), []byte("x"), 0o644)
	// non-static-range fileid (valid 40-char hash, prefix not assigned) -> removed
	nonstatic := ParseHVFile("ffff0123456789abcdef0123456789abcdef0123-5-jpg")
	os.WriteFile(filepath.Join(s.CacheDir, "ab", nonstatic.Fileid()), []byte("x"), 0o644)

	ch.startupCacheCleanup()

	if _, err := os.Stat(filepath.Join(s.CacheDir, "strayfile")); !os.IsNotExist(err) {
		t.Fatal("stray L1 file should be removed")
	}
	if _, err := os.Stat(filepath.Join(s.CacheDir, "zz")); !os.IsNotExist(err) {
		t.Fatal("empty L1 dir should be removed")
	}
	if _, err := os.Stat(filepath.Join(s.CacheDir, "ab", "notafile")); !os.IsNotExist(err) {
		t.Fatal("invalid fileid should be removed")
	}
	if _, err := os.Stat(filepath.Join(s.CacheDir, "ab", nonstatic.Fileid())); !os.IsNotExist(err) {
		t.Fatal("non-static-range file should be removed")
	}
	// good file relocated into its proper range dir
	if _, err := os.Stat(ch.LocalPath(good)); err != nil {
		t.Fatalf("good file should be relocated to %s: %v", ch.LocalPath(good), err)
	}
}

// --- cycle(): StillAlive (counter=0) + scheduled %30 block (counter=1) ---

func TestCycleStillAliveAndScheduled(t *testing.T) {
	m, s, rpc := newMockRPC(t)
	c := NewHathClient(s, NewStats())
	c.rpc = rpc
	ch, _ := buildCache(t)
	c.cache = ch
	// non-expired cert so the %30 branch does not hit dieErr
	c.cert = &CertManager{settings: s, expiry: time.Now().Add(48 * time.Hour)}
	c.server = &HTTPServer{cert: c.cert, settings: s}

	// counter=0 -> StillAlive branch; client must not be suspended afterwards
	c.cycle()
	if c.IsSuspended() {
		t.Fatal("cycle with no suspension should not leave client suspended")
	}
	// counter=1 -> scheduled %30 block (serverTimeDelta/CertExpired guards false)
	c.counter = 1
	c.cycle()
	_ = m
}
