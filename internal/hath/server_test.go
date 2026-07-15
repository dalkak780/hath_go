package hath

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// buildTestServer wires an HTTPServer against temp dirs + a mock RPC, returning
// the server, settings, cache, and a (non-TLS) httptest server running handle.
func buildTestServer(t *testing.T) (*HTTPServer, *Settings, *CacheHandler, *httptest.Server) {
	t.Helper()
	m, s, rpc := newMockRPC(t)
	s.SetServerTime(1_700_000_000)
	dir := t.TempDir()
	s.CacheDir = filepath.Join(dir, "cache")
	s.TempDir = filepath.Join(dir, "tmp")
	s.DataDir = filepath.Join(dir, "data")
	s.MaxAllowedFile = 1 << 30
	for _, d := range []string{s.CacheDir, s.TempDir, s.DataDir} {
		os.MkdirAll(d, 0o755)
	}

	client := NewHathClient(s, NewStats())
	client.rpc = rpc
	cache, err := NewCacheHandler(client)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cache.pruner != nil {
			cache.pruner.stop()
		}
	})
	client.cache = cache
	hs := NewHTTPServer(s, cache, rpc, client.stats, &CertManager{settings: s}, client)
	hs.AllowNormalConnections()
	srv := httptest.NewServer(http.HandlerFunc(hs.handle))
	t.Cleanup(srv.Close)
	_ = m
	return hs, s, cache, srv
}

func writeCacheFile(t *testing.T, cache *CacheHandler, f *HVFile, content []byte) {
	t.Helper()
	if int64(len(content)) != f.Size {
		t.Fatalf("content length %d != file size %d", len(content), f.Size)
	}
	path := cache.LocalPath(f)
	os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
}

func validHTarget(s *Settings, fileid string) string {
	t := s.ServerTime()
	key := keystampHash(t, fileid, s.ClientKey)
	return "/h/" + fileid + "/fileindex=1;xres=org;keystamp=" + strconv.FormatInt(t, 10) + "-" + key + "/img.jpg"
}

func TestHCachedServe(t *testing.T) {
	_, s, cache, srv := buildTestServer(t)
	f := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-5-jpg")
	writeCacheFile(t, cache, f, []byte("hello"))
	resp, err := http.Get(srv.URL + validHTarget(s, f.Fileid()))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Content-Type") != "image/jpeg" {
		t.Fatalf("wrong content-type: %q", resp.Header.Get("Content-Type"))
	}
	if resp.Header.Get("Cache-Control") != "public, max-age=31536000" {
		t.Fatalf("wrong cache-control: %q", resp.Header.Get("Cache-Control"))
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello" {
		t.Fatalf("wrong body: %q", body)
	}
}

func TestHBadKeystampForbidden(t *testing.T) {
	_, s, cache, srv := buildTestServer(t)
	f := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-5-jpg")
	writeCacheFile(t, cache, f, []byte("hello"))
	// tampered keystamp key
	target := "/h/" + f.Fileid() + "/fileindex=1;xres=org;keystamp=" + strconv.FormatInt(s.ServerTime(), 10) + "-deadbeef/img.jpg"
	resp, err := http.Get(srv.URL + target)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403 for bad keystamp, got %d", resp.StatusCode)
	}
}

func TestHExpiredKeystampForbidden(t *testing.T) {
	_, _, cache, srv := buildTestServer(t)
	f := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-5-jpg")
	writeCacheFile(t, cache, f, []byte("hello"))
	// keystamp time far outside the 900s tolerance
	old := int64(1_000_000_000)
	key := keystampHash(old, f.Fileid(), testClientKey)
	target := "/h/" + f.Fileid() + "/fileindex=1;xres=org;keystamp=" + strconv.FormatInt(old, 10) + "-" + key + "/img.jpg"
	resp, err := http.Get(srv.URL + target)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403 for expired keystamp, got %d", resp.StatusCode)
	}
}

func TestHNotCachedNotFound(t *testing.T) {
	_, s, _, srv := buildTestServer(t)
	// file not in cache; mock srfetch returns no sources → 404/502
	f := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-5-jpg")
	resp, err := http.Get(srv.URL + validHTarget(s, f.Fileid()))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 404 && resp.StatusCode != 502 {
		t.Fatalf("expected 404/502 for uncached, got %d", resp.StatusCode)
	}
}

func TestServercmdValid(t *testing.T) {
	_, s, _, srv := buildTestServer(t)
	t0 := s.ServerTime()
	cmd := "still_alive"
	add := ""
	key := servercmdKey(cmd, add, s.ClientID, t0, s.ClientKey)
	target := "/servercmd/" + cmd + "/" + add + "/" + strconv.FormatInt(t0, 10) + "/" + key
	resp, err := http.Get(srv.URL + target)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "I feel FANTASTIC and I'm still alive" {
		t.Fatalf("unexpected body: %q", body)
	}
}

func TestServercmdBadKeyForbidden(t *testing.T) {
	_, s, _, srv := buildTestServer(t)
	t0 := s.ServerTime()
	target := "/servercmd/refresh_settings//x/" + strconv.FormatInt(t0, 10) + "/boguskey"
	_ = s
	resp, err := http.Get(srv.URL + target)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestSpeedtestEndpoint(t *testing.T) {
	_, s, _, srv := buildTestServer(t)
	t0 := s.ServerTime()
	size := "1024"
	key := speedtestKey(size, t0, s.ClientID, s.ClientKey)
	target := "/t/" + size + "/" + strconv.FormatInt(t0, 10) + "/" + key
	resp, err := http.Get(srv.URL + target)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 1024 {
		t.Fatalf("expected 1024 bytes, got %d", len(body))
	}
}

func TestSpeedtestBadKeyForbidden(t *testing.T) {
	_, s, _, srv := buildTestServer(t)
	t0 := s.ServerTime()
	target := "/t/1024/" + strconv.FormatInt(t0, 10) + "/wrongkey"
	resp, err := http.Get(srv.URL + target)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestFaviconAndRobots(t *testing.T) {
	_, _, _, srv := buildTestServer(t)
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noRedirect.Get(srv.URL + "/favicon.ico")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 301 {
		t.Fatalf("favicon should 301, got %d", resp.StatusCode)
	}
	resp2, err := http.Get(srv.URL + "/robots.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Fatalf("robots should 200, got %d", resp2.StatusCode)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	_, _, _, srv := buildTestServer(t)
	resp, err := http.Post(srv.URL+"/robots.txt", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 405 {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

// --- unit tests for gating helpers ---

func TestFloodAllow(t *testing.T) {
	hs := &HTTPServer{settings: NewSettings(), flood: map[string]*floodEntry{}}
	for i := 0; i < 10; i++ {
		if !hs.floodAllow("1.2.3.4") {
			t.Fatalf("should allow first 10, blocked at %d", i+1)
		}
	}
	if hs.floodAllow("1.2.3.4") {
		t.Fatal("11th connection should be flood-blocked")
	}
	// a different IP is independent
	if !hs.floodAllow("5.6.7.8") {
		t.Fatal("different IP should not be blocked")
	}
}

func TestIsLocal(t *testing.T) {
	hs := &HTTPServer{settings: NewSettings()}
	cases := map[string]bool{
		"127.0.0.1": true, "10.1.2.3": true, "192.168.1.1": true,
		"172.16.0.1": true, "169.254.1.1": true, "::1": true,
		"8.8.8.8": false, "1.2.3.4": false,
	}
	for ip, want := range cases {
		if got := hs.isLocal(ip); got != want {
			t.Errorf("isLocal(%q) = %v, want %v", ip, got, want)
		}
	}
}

func TestAdmitDuringStartup(t *testing.T) {
	hs := &HTTPServer{settings: NewSettings()} // allowNormal false
	c := &fakeConn{remote: "8.8.8.8:1"}
	if hs.admit(c) {
		t.Fatal("non-rpc/non-local should be rejected before allowNormal")
	}
	hs.AllowNormalConnections()
	hs.settings.DisableFloodControl = true
	if !hs.admit(c) {
		t.Fatal("should admit after allowNormal with flood control off")
	}
}

func TestAdmitRPCServerBypass(t *testing.T) {
	s := NewSettings()
	s.mu.Lock()
	s.rpcServers = []net.IP{net.ParseIP("127.0.0.1")}
	s.mu.Unlock()
	hs := &HTTPServer{settings: s} // allowNormal false
	c := &fakeConn{remote: "127.0.0.1:1"}
	if !hs.admit(c) {
		t.Fatal("rpc server should bypass startup gating")
	}
}

func TestParseAdditional(t *testing.T) {
	m := parseAdditional("fileindex=5;xres=org;keystamp=1-abc")
	if m["fileindex"] != "5" || m["xres"] != "org" || m["keystamp"] != "1-abc" {
		t.Fatalf("parseAdditional wrong: %v", m)
	}
}

// fakeConn is a minimal net.Conn for admit() tests.
type fakeConn struct{ remote string }

func (c *fakeConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *fakeConn) Write([]byte) (int, error)        { return 0, io.EOF }
func (c *fakeConn) Close() error                     { return nil }
func (c *fakeConn) LocalAddr() net.Addr              { return nil }
func (c *fakeConn) RemoteAddr() net.Addr {
	host, port, _ := net.SplitHostPort(c.remote)
	p, _ := strconv.Atoi(port)
	return &net.TCPAddr{IP: net.ParseIP(host), Port: p}
}
func (c *fakeConn) SetDeadline(t time.Time) error        { return nil }
func (c *fakeConn) SetReadDeadline(t time.Time) error    { return nil }
func (c *fakeConn) SetWriteDeadline(t time.Time) error   { return nil }
