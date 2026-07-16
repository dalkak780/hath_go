package hath

import (
	"crypto/sha1"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
)

// originFileServer serves fixed content with an explicit Content-Length, like a
// real H@H origin node.
func originFileServer(t *testing.T, content []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(content)))
		w.Write(content)
	}))
}

func sha1HexOf(b []byte) string {
	h := sha1.Sum(b)
	return hex.EncodeToString(h[:])
}

// TestProxyFileServesAndCaches: an uncached /h request is proxied from an origin
// (mock srfetch returns the origin URL), verified, served, and imported.
func TestProxyFileServesAndCaches(t *testing.T) {
	content := []byte("hello-proxy")
	hash := sha1HexOf(content)
	fileid := hash + "-" + strconv.Itoa(len(content)) + "-jpg"

	origin := originFileServer(t, content)
	defer origin.Close()

	m, s, rpc := newMockRPC(t)
	s.SetServerTime(1_700_000_000)
	s.MaxAllowedFile = 1 << 30
	dir := t.TempDir()
	s.CacheDir = filepath.Join(dir, "cache")
	s.TempDir = filepath.Join(dir, "tmp")
	s.DataDir = filepath.Join(dir, "data")
	for _, d := range []string{s.CacheDir, s.TempDir, s.DataDir} {
		os.MkdirAll(d, 0o755)
	}
	client := NewHathClient(s, NewStats())
	client.rpc = rpc
	cache, err := NewCacheHandler(client)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cache.pruner.stop() })
	client.cache = cache
	hs := NewHTTPServer(s, cache, rpc, client.stats, &CertManager{settings: s}, client)
	hs.AllowNormalConnections()
	srv := httptest.NewServer(http.HandlerFunc(hs.handle))
	defer srv.Close()

	// mock srfetch returns the origin URL for this file
	m.setResponse(ActStaticRangeFetch, "OK\n"+origin.URL+"/h/x\n")

	resp, err := http.Get(srv.URL + validHTarget(s, fileid))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 from proxy, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != string(content) {
		t.Fatalf("proxy body mismatch: %q", body)
	}
	// the verified file should now be cached
	f := ParseHVFile(fileid)
	if f == nil {
		t.Fatal("fileid parse failed")
	}
	if _, ok := cache.Lookup(fileid); !ok {
		t.Fatal("proxied file should be imported to cache")
	}
}

func TestProxyFileUsesConfiguredImageProxy(t *testing.T) {
	content := []byte("through-image-proxy")
	fileid := sha1HexOf(content) + "-" + strconv.Itoa(len(content)) + "-jpg"
	var proxyUsed atomic.Bool
	imageProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyUsed.Store(true)
		if r.URL.Host != "origin.invalid" {
			t.Errorf("proxy received host %q", r.URL.Host)
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(content)))
		_, _ = w.Write(content)
	}))
	defer imageProxy.Close()
	proxyURL, _ := url.Parse(imageProxy.URL)
	proxyPort, _ := strconv.Atoi(proxyURL.Port())

	m, s, rpc := newMockRPC(t)
	s.SetServerTime(1_700_000_000)
	s.MaxAllowedFile = 1 << 30
	s.ImageProxyType = "http"
	s.ImageProxyHost = proxyURL.Hostname()
	s.ImageProxyPort = proxyPort
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
	m.setResponse(ActStaticRangeFetch, "OK\nhttp://origin.invalid/h/x\n")

	resp, err := http.Get(srv.URL + validHTarget(s, fileid))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != string(content) || !proxyUsed.Load() {
		t.Fatalf("image proxy parity failed: status=%d body=%q proxyUsed=%v", resp.StatusCode, body, proxyUsed.Load())
	}
}

// TestProxyFileCorruptRejected: if the origin serves wrong content, the proxy
// must NOT serve it (SHA-1 mismatch) and must not cache it.
func TestProxyFileCorruptRejected(t *testing.T) {
	hash := sha1HexOf([]byte("expected")) // expect this hash
	fileid := hash + "-8-jpg"
	origin := originFileServer(t, []byte("WRONG!!!")) // 8 bytes but wrong hash
	defer origin.Close()

	m, s, rpc := newMockRPC(t)
	s.SetServerTime(1_700_000_000)
	s.MaxAllowedFile = 1 << 30
	dir := t.TempDir()
	s.CacheDir = filepath.Join(dir, "cache")
	s.TempDir = filepath.Join(dir, "tmp")
	s.DataDir = filepath.Join(dir, "data")
	for _, d := range []string{s.CacheDir, s.TempDir, s.DataDir} {
		os.MkdirAll(d, 0o755)
	}
	client := NewHathClient(s, NewStats())
	client.rpc = rpc
	cache, _ := NewCacheHandler(client)
	t.Cleanup(func() { cache.pruner.stop() })
	client.cache = cache
	hs := NewHTTPServer(s, cache, rpc, client.stats, &CertManager{settings: s}, client)
	hs.AllowNormalConnections()
	srv := httptest.NewServer(http.HandlerFunc(hs.handle))
	defer srv.Close()
	m.setResponse(ActStaticRangeFetch, "OK\n"+origin.URL+"/h/x\n")

	resp, err := http.Get(srv.URL + validHTarget(s, fileid))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 502 {
		t.Fatalf("expected 502 for corrupt origin, got %d", resp.StatusCode)
	}
	if _, ok := cache.Lookup(fileid); ok {
		t.Fatal("corrupt file must not be cached")
	}
}
