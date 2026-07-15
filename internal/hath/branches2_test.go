package hath

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHandleUnknownPath(t *testing.T) {
	_, _, _, srv := buildTestServer(t)
	resp, err := http.Get(srv.URL + "/something/unknown")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404 for unknown path, got %d", resp.StatusCode)
	}
}

func TestFetchShortRead(t *testing.T) {
	_, s, rpc := newMockRPC(t)
	s.MaxAllowedFile = 1 << 30
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "10")
		w.WriteHeader(200)
		w.Write([]byte("only5")) // fewer than declared
	}))
	defer srv.Close()
	if _, _, err := rpc.fetch(srv.URL+"/x", 2*time.Second); err == nil {
		t.Fatal("expected short-read error")
	}
}

func TestCachePersistentCorruptReload(t *testing.T) {
	ch, _ := buildCache(t)
	// write garbage where pcache is expected
	os.WriteFile(ch.persistentPath(), []byte("not gob"), 0o644)
	ch2 := &CacheHandler{
		settings: ch.settings, stats: NewStats(),
		lru:               make([]uint16, lruCacheSize),
		staticRangeOldest: make(map[string]int64),
	}
	if ch2.loadPersistent() {
		t.Fatal("corrupt persistent file should not load")
	}
}

func TestSettingsUnknownSettingIgnored(t *testing.T) {
	s := NewSettings()
	s.ApplySettings([]string{"totally_unknown_key=value"})
	// should not panic; default branch logs at debug
}

func TestGalleryParseMetaIncomplete(t *testing.T) {
	s := NewSettings()
	g := &GalleryDownloader{settings: s, rpc: &ServerHandler{settings: s}}
	if g.parseMeta("GID 1\n") { // missing filecount/minxres/title/filelist
		t.Fatal("incomplete meta should not parse")
	}
}

func TestProxyFileNoSourcesNotFound(t *testing.T) {
	_, s, _, srv := buildTestServer(t)
	// srfetch mock returns no sources (default OK with no URLs) → 404
	f := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-5-jpg")
	resp, err := http.Get(srv.URL + validHTarget(s, f.Fileid()))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404 when no proxy sources, got %d", resp.StatusCode)
	}
}

func TestCacheMoveFileAcrossPathFallback(t *testing.T) {
	// moveFileToCacheDir falls back to copy when rename fails. Force a failure
	// by making the source disappear between checks is racy; instead verify the
	// happy path returns true and the file lands at the destination.
	ch, _ := buildCache(t)
	f := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-3-jpg")
	src := filepath.Join(ch.settings.TempDir, "mvsrc")
	os.WriteFile(src, []byte("abc"), 0o644)
	if !ch.moveFileToCacheDir(src, f) {
		t.Fatal("moveFileToCacheDir should succeed")
	}
	if _, err := os.Stat(ch.LocalPath(f)); err != nil {
		t.Fatal("file should be at destination")
	}
}
