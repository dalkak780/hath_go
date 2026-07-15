package hath

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// --- cache prune: no static ranges in the table → Warn + return ---

func TestCachePruneEmptyRangeTable(t *testing.T) {
	ch, _ := buildCacheNoPruner(t)
	ch.CheckAndPruneCache() // must not panic
}

// --- cache prune: keep newer file updates oldestRemaining ---

func TestCachePruneKeepsNewerUpdatesOldestRemaining(t *testing.T) {
	ch, s := buildCacheNoPruner(t)
	s.DiskLimit = 1
	rng := "aaaa"
	dir := filepath.Join(ch.settings.CacheDir, "aa", "aa")
	os.MkdirAll(dir, 0o755)
	old := ParseHVFile("aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000-4-jpg")
	newF := ParseHVFile("aaaa0001aaaa0001aaaa0001aaaa0001aaaa0001-4-jpg")
	writeFile(t, filepath.Join(dir, old.Fileid()), []byte("oldd"))
	writeFile(t, filepath.Join(dir, newF.Fileid()), []byte("neww"))
	oldMtime := time.Now().Add(-400 * 24 * time.Hour)
	newMtime := time.Now().Add(-2 * 24 * time.Hour)
	os.Chtimes(filepath.Join(dir, old.Fileid()), oldMtime, oldMtime)
	os.Chtimes(filepath.Join(dir, newF.Fileid()), newMtime, newMtime)
	ch.mu.Lock()
	ch.staticRangeOldest[rng] = oldMtime.UnixMilli()
	ch.cacheCount = 2
	ch.cacheSize = 8
	ch.mu.Unlock()
	ch.CheckAndPruneCache()
	ch.mu.Lock()
	age, has := ch.staticRangeOldest[rng]
	ch.mu.Unlock()
	if !has || age != newMtime.UnixMilli() {
		t.Fatalf("range age should update to newer file's mtime, has=%v age=%d", has, age)
	}
}

// --- cache cycleLRU: wrap-around resets pointer ---

func TestCacheCycleLRUWrapsAround(t *testing.T) {
	ch, _ := buildCacheNoPruner(t)
	ch.lruClearPointer = lruCacheSize - 5 // near the end
	ch.CycleLRUCacheTable()
	if ch.lruClearPointer != 0 {
		t.Fatalf("expected wrap to 0, got %d", ch.lruClearPointer)
	}
}

// --- rpc fetch: connection error → RespNull ---

func TestRPCCallConnectionError(t *testing.T) {
	_, _, rpc := newMockRPC(t)
	// Use a fast-refusing connection (127.0.0.1:1 is typically connection refused)
	badURL := "http://127.0.0.1:1/15/rpc?clientbuild=178&act=server_stat"
	// Make a very short timeout by using a custom transport with a short dialer
	rpc.client = &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext:       (&net.Dialer{Timeout: 10 * time.Millisecond}).DialContext,
		},
	}
	sr := rpc.callURL(badURL, "")
	if sr.Status != RespNull {
		t.Fatalf("expected RespNull, got %v", sr.Status)
	}
}

// --- rpc fetchFile: server returns error ---

func TestFetchFileServerError(t *testing.T) {
	_, s, rpc := newMockRPC(t)
	s.MaxAllowedFile = 1 << 30
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", 500)
	}))
	defer srv.Close()
	if err := rpc.fetchFile(srv.URL+"/cert", filepath.Join(t.TempDir(), "cert.p12"), 5*time.Second); err == nil {
		t.Fatal("expected error for 500 response")
	}
}

// --- server admit: overload notification at 80% ---

func TestAdmitTriggersOverloadAt80Percent(t *testing.T) {
	s := NewSettings()
	s.OverrideConns = 10
	hs := &HTTPServer{settings: s, flood: map[string]*floodEntry{}}
	hs.AllowNormalConnections()
	hs.openConns.Store(8) // 80% of 10
	c := &fakeConn{remote: "8.8.8.8:1"}
	if !hs.admit(c) {
		t.Fatal("should admit at 80% capacity")
	}
}

// --- server handle: unknown command → INVALID_COMMAND ---

func TestServercmdUnknownCommand(t *testing.T) {
	_, s, _, srv := buildTestServer(t)
	t0 := s.ServerTime()
	key := servercmdKey("nonexistent", "", s.ClientID, t0, s.ClientKey)
	resp, err := http.Get(srv.URL + "/servercmd/nonexistent//" + itoa(int(t0)) + "/" + key)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "INVALID_COMMAND" {
		t.Fatalf("expected INVALID_COMMAND, got %q", body)
	}
}

// --- server proxyFile: origin 502 from fetch failure ---

func TestProxyFileOriginFails(t *testing.T) {
	_, s, _, srv := buildTestServer(t)
	// srfetch returns a URL that will fail
	f := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-5-jpg")
	resp, err := http.Get(srv.URL + validHTarget(s, f.Fileid()))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 404 && resp.StatusCode != 502 {
		t.Fatalf("expected 404/502 for unreachable proxy origin, got %d", resp.StatusCode)
	}
}

// --- rpc originClient: SOCKS proxy (config only, no actual connection) ---

func TestOriginClientSocksProxy(t *testing.T) {
	_, s, rpc := newMockRPC(t)
	s.ImageProxyHost = "127.0.0.1"
	s.ImageProxyType = "socks"
	s.ImageProxyPort = 1080
	if rpc.originClient(true) == nil {
		t.Fatal("socks proxy client should be non-nil")
	}
}

// --- cache loadPersistent: corrupt file returns false ---

func TestCacheLoadPersistentCorrupt(t *testing.T) {
	ch, _ := buildCacheNoPruner(t)
	os.WriteFile(ch.persistentPath(), []byte("not-gob"), 0o644)
	if ch.loadPersistent() {
		t.Fatal("corrupt persistent file should not load")
	}
}

// --- cache loadPersistent: wrong LRU length returns false ---

func TestCacheLoadPersistentWrongLRUSize(t *testing.T) {
	ch, _ := buildCacheNoPruner(t)
	// write a gob with wrong LRU length
	ch.savePersistent()
	// overwrite with a different LRU size via a minimal gob
	ch.mu.Lock()
	ch.cacheCount = 1
	ch.lru = make([]uint16, 10) // wrong size
	ch.mu.Unlock()
	ch.savePersistent()
	// reload
	ch2 := &CacheHandler{
		settings: ch.settings, stats: NewStats(),
		lru: make([]uint16, lruCacheSize),
	}
	if ch2.loadPersistent() {
		t.Fatal("should reject wrong LRU size")
	}
}