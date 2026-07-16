package hath

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFatalShutdownPersistsCacheOnce(t *testing.T) {
	ch, _ := buildCacheNoPruner(t)
	c := &HathClient{settings: ch.settings, stats: ch.stats, cache: ch}
	activeClient.Store(c)
	t.Cleanup(func() { activeClient.CompareAndSwap(c, nil) })

	shutdownActiveClient()
	shutdownActiveClient()
	if !c.IsShuttingDown() {
		t.Fatal("fatal shutdown did not mark client stopped")
	}
	if _, err := os.Stat(ch.persistentPath()); err != nil {
		t.Fatalf("fatal shutdown did not persist cache: %v", err)
	}
}

func TestConcurrentCacheMissUsesOneBackendFetch(t *testing.T) {
	content := []byte("coalesced-proxy")
	fileid := sha1HexOf(content) + "-" + strconv.Itoa(len(content)) + "-jpg"
	var originCalls atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		originCalls.Add(1)
		time.Sleep(50 * time.Millisecond)
		w.Header().Set("Content-Length", strconv.Itoa(len(content)))
		_, _ = w.Write(content)
	}))
	defer origin.Close()

	m, s, rpc := newMockRPC(t)
	s.SetServerTime(1_700_000_000)
	s.MaxAllowedFile = 1 << 30
	dir := t.TempDir()
	s.CacheDir, s.TempDir, s.DataDir = filepath.Join(dir, "cache"), filepath.Join(dir, "tmp"), filepath.Join(dir, "data")
	for _, d := range []string{s.CacheDir, s.TempDir, s.DataDir} {
		_ = os.MkdirAll(d, 0o755)
	}
	client := NewHathClient(s, NewStats())
	client.rpc = rpc
	cache, err := NewCacheHandler(client)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cache.pruner.stop)
	client.cache = cache
	hs := NewHTTPServer(s, cache, rpc, client.stats, &CertManager{settings: s}, client)
	hs.AllowNormalConnections()
	srv := httptest.NewServer(http.HandlerFunc(hs.handle))
	defer srv.Close()
	m.setResponse(ActStaticRangeFetch, "OK\n"+origin.URL+"/h/x\n")

	const requests = 8
	var wg sync.WaitGroup
	errs := make(chan error, requests)
	for range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Get(srv.URL + validHTarget(s, fileid))
			if err == nil {
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					err = errors.New(resp.Status)
				} else if body, readErr := io.ReadAll(resp.Body); readErr != nil {
					err = readErr
				} else if !bytes.Equal(body, content) {
					err = errors.New("unexpected response body")
				}
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := originCalls.Load(); got != 1 {
		t.Fatalf("backend fetches = %d, want 1", got)
	}
}

func TestOriginClientIsReused(t *testing.T) {
	_, s, rpc := newMockRPC(t)
	if first, second := rpc.originClient(false), rpc.originClient(false); first != second {
		t.Fatal("direct origin client was recreated")
	}

	s.ImageProxyHost = "127.0.0.1"
	s.ImageProxyType = "http"
	s.ImageProxyPort = 8080
	first := rpc.originClient(true)
	if second := rpc.originClient(true); first != second {
		t.Fatal("proxied origin client was recreated without a settings change")
	}
	s.ImageProxyPort = 8081
	if changed := rpc.originClient(true); changed == first {
		t.Fatal("proxied origin client was retained after a settings change")
	}
}

func TestInterruptedServeIsNotCountedComplete(t *testing.T) {
	ch, s := buildCacheNoPruner(t)
	s.DisableFileVerify = true
	content := []byte("hello")
	f := ParseHVFile(sha1HexOf(content) + "-5-jpg")
	path := ch.LocalPath(f)
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	_ = os.WriteFile(path, content, 0o644)
	stats := NewStats()
	hs := &HTTPServer{settings: s, cache: ch, stats: stats}
	w := &failingResponseWriter{header: make(http.Header)}
	r := httptest.NewRequest(http.MethodGet, "/h/test", nil)
	hs.serveCached(w, r, f)
	stats.mu.Lock()
	filesSent := stats.filesSent
	stats.mu.Unlock()
	if filesSent != 0 {
		t.Fatalf("interrupted response counted as complete: %d", filesSent)
	}
}

type failingResponseWriter struct{ header http.Header }

func (w *failingResponseWriter) Header() http.Header       { return w.header }
func (w *failingResponseWriter) WriteHeader(int)           {}
func (w *failingResponseWriter) Write([]byte) (int, error) { return 0, errors.New("client closed") }

func TestRotatingFileBoundsBackups(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log_all")
	r, err := newRotatingFile(path, 8, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range [][]byte{[]byte("12345678"), []byte("abcdefgh"), []byte("ABCDEFGH")} {
		if _, err := r.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{path, path + ".1", path + ".2"} {
		b, err := os.ReadFile(name)
		if err != nil || len(b) != 8 {
			t.Fatalf("rotation file %s: len=%d err=%v", name, len(b), err)
		}
	}
	if bytes.Equal(mustRead(t, path), mustRead(t, path+".1")) {
		t.Fatal("active log and backup unexpectedly match")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
