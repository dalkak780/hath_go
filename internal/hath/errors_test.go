package hath

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	sslmate "software.sslmate.com/src/go-pkcs12"
)

// --- rpc fetch / download error branches ---

func chunkedServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		if f, ok := w.(http.Flusher); ok {
			w.Write([]byte("x"))
			f.Flush()
		}
	}))
}

func TestFetchMissingContentLength(t *testing.T) {
	_, s, rpc := newMockRPC(t)
	s.MaxAllowedFile = 1 << 30
	srv := chunkedServer(t)
	defer srv.Close()
	if _, _, err := rpc.fetch(srv.URL+"/x", 5*time.Second); err == nil {
		t.Fatal("expected error for missing Content-Length")
	}
}

func TestFetchOversize(t *testing.T) {
	_, s, rpc := newMockRPC(t)
	s.MaxAllowedFile = 10
	srv := originFileServer(t, []byte("this is way too long for the limit"))
	defer srv.Close()
	if _, _, err := rpc.fetch(srv.URL+"/x", 5*time.Second); err == nil {
		t.Fatal("expected error for oversize response")
	}
}

func TestDownloadToFileNoContentLength(t *testing.T) {
	_, s, rpc := newMockRPC(t)
	s.MaxAllowedFile = 1 << 30
	srv := chunkedServer(t)
	defer srv.Close()
	dir := t.TempDir()
	if _, err := rpc.DownloadToFile(srv.URL+"/x", filepath.Join(dir, "o"), 5*time.Second, false, false, nil, ""); err == nil {
		t.Fatal("expected error for missing Content-Length")
	}
}

func TestDownloadToFileOversize(t *testing.T) {
	_, s, rpc := newMockRPC(t)
	s.MaxAllowedFile = 5
	srv := originFileServer(t, []byte("1234567890"))
	defer srv.Close()
	dir := t.TempDir()
	if _, err := rpc.DownloadToFile(srv.URL+"/x", filepath.Join(dir, "o"), 5*time.Second, false, false, nil, ""); err == nil {
		t.Fatal("expected error for oversize download")
	}
}

// --- cert LoadOrRefresh failure branches ---

func TestCertLoadOrRefreshEmptyCert(t *testing.T) {
	m, s, rpc := newMockRPC(t)
	m.certBytes = nil
	s.DataDir = t.TempDir()
	cm := &CertManager{settings: s}
	if err := cm.LoadOrRefresh(rpc); err == nil {
		t.Fatal("expected error for empty cert")
	}
}

func TestCertLoadOrRefreshBadP12(t *testing.T) {
	m, s, rpc := newMockRPC(t)
	m.certBytes = []byte("not a valid p12")
	s.DataDir = t.TempDir()
	cm := &CertManager{settings: s}
	if err := cm.LoadOrRefresh(rpc); err == nil {
		t.Fatal("expected error for bad p12")
	}
}

func TestCertLoadOrRefreshExpired(t *testing.T) {
	leaf, key := genCertWithNotAfter(t, time.Now().Add(-2*time.Hour))
	p12, err := sslmate.LegacyRC2.Encode(key, leaf, nil, testClientKey)
	if err != nil {
		t.Fatal(err)
	}
	m, s, rpc := newMockRPC(t)
	m.certBytes = p12
	s.DataDir = t.TempDir()
	cm := &CertManager{settings: s}
	if err := cm.LoadOrRefresh(rpc); err == nil {
		t.Fatal("expected error for expired cert")
	}
}

// --- gallery download failure ---

func TestGalleryFileDownloadFailure(t *testing.T) {
	m, s, rpc := newMockRPC(t)
	s.MaxAllowedFile = 1 << 30
	s.DownloadDir = t.TempDir()
	failSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", 404)
	}))
	defer failSrv.Close()
	m.setResponse(ActDownloaderFetch, "OK\n"+failSrv.URL+"/f\n")

	g := &GalleryDownloader{settings: s, rpc: rpc, stats: NewStats(), todir: s.DownloadDir}
	gf := &galleryFile{page: 1, fileindex: 0, xres: "org", filetype: "jpg", filename: "test"}
	if gf.download(g) != dlFailed {
		t.Fatal("expected dlFailed for unreachable origin")
	}
	if len(g.failures) != 1 {
		t.Fatalf("expected 1 recorded failure, got %d", len(g.failures))
	}
}

// --- server handle bad-request branches ---

func TestServerHandleMalformedH(t *testing.T) {
	_, _, _, srv := buildTestServer(t)
	resp, err := http.Get(srv.URL + "/h/onlyfileid")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestServerHandleSpeedtestBadSize(t *testing.T) {
	_, _, _, srv := buildTestServer(t)
	resp, err := http.Get(srv.URL + "/t/notanumber/1/k")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestServerHandleServercmdUnauthorizedIP(t *testing.T) {
	s := NewSettings()
	s.ClientID = testClientID
	s.ClientKey = testClientKey
	s.mu.Lock()
	s.rpcServers = []net.IP{net.ParseIP("10.0.0.99")}
	s.mu.Unlock()
	dir := t.TempDir()
	s.CacheDir = filepath.Join(dir, "cache")
	s.TempDir = filepath.Join(dir, "tmp")
	for _, d := range []string{s.CacheDir, s.TempDir} {
		os.MkdirAll(d, 0o755)
	}
	c := &HathClient{settings: s, stats: NewStats()}
	c.rpc = &ServerHandler{settings: s}
	cache, _ := NewCacheHandler(c)
	t.Cleanup(func() { cache.pruner.stop() })
	hs := NewHTTPServer(s, cache, c.rpc, c.stats, &CertManager{settings: s}, c)
	hs.AllowNormalConnections()
	srv := httptest.NewServer(http.HandlerFunc(hs.handle))
	defer srv.Close()
	t0 := s.ServerTime()
	key := servercmdKey("still_alive", "", s.ClientID, t0, s.ClientKey)
	resp, err := http.Get(srv.URL + "/servercmd/still_alive//" + strconv.FormatInt(t0, 10) + "/" + key)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403 from unauthorized IP, got %d", resp.StatusCode)
	}
}

// --- helpers error branches ---

func TestWalkRangeDirsMissingRoot(t *testing.T) {
	if err := walkRangeDirs(filepath.Join(t.TempDir(), "nope"), func(string, string, []os.DirEntry) {}); err == nil {
		t.Fatal("expected error for missing root")
	}
}

func TestValidateFileSHAMissing(t *testing.T) {
	if validateFileSHA1(filepath.Join(t.TempDir(), "missing"), "x") {
		t.Fatal("missing file should not validate")
	}
}

// --- cache: deleting the last file in a range removes the dir entry ---

func TestCacheDeleteLastFileRemovesRange(t *testing.T) {
	ch, _ := buildCache(t)
	f := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-5-jpg")
	src := filepath.Join(ch.settings.TempDir, "src")
	os.WriteFile(src, []byte("hello"), 0o644)
	ch.ImportFileToCache(src, f)
	ch.DeleteFileFromCache(f)
	ch.mu.Lock()
	_, hasRange := ch.staticRangeOldest[f.StaticRange()]
	ch.mu.Unlock()
	if hasRange {
		t.Fatal("empty range should be removed from staticRangeOldest")
	}
}

func TestPrunerSetCheckFrequencyNil(t *testing.T) {
	var p *CachePruner
	p.setCheckFrequency(10) // must not panic on nil receiver
}
