package hath

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	sslmate "software.sslmate.com/src/go-pkcs12"
)

func TestOriginClientVariants(t *testing.T) {
	_, s, rpc := newMockRPC(t)
	// no proxy
	if rpc.originClient(false) == nil {
		t.Fatal("originClient should be non-nil")
	}
	// http proxy
	s.ImageProxyHost = "127.0.0.1"
	s.ImageProxyType = "http"
	s.ImageProxyPort = 8080
	if rpc.originClient(true) == nil {
		t.Fatal("http proxy client should be non-nil")
	}
	// socks proxy
	s.ImageProxyType = "socks"
	s.ImageProxyPort = 1080
	if rpc.originClient(true) == nil {
		t.Fatal("socks proxy client should be non-nil")
	}
}

func TestDownloadToFileSuccessAndErrors(t *testing.T) {
	_, s, rpc := newMockRPC(t)
	s.MaxAllowedFile = 1 << 30
	content := []byte("dl-content")
	origin := originFileServer(t, content)
	defer origin.Close()

	dir := t.TempDir()
	dest := filepath.Join(dir, "out")
	n, err := rpc.DownloadToFile(origin.URL+"/f", dest, 5*time.Second, false, false, nil, "")
	if err != nil {
		t.Fatalf("download failed: %v", err)
	}
	if n != int64(len(content)) {
		t.Fatalf("downloaded %d bytes, want %d", n, len(content))
	}
	b, _ := os.ReadFile(dest)
	if string(b) != string(content) {
		t.Fatalf("content mismatch: %q", b)
	}

	// bad URL → error
	if _, err := rpc.DownloadToFile("http://127.0.0.1:1/nope", dest, 500*time.Millisecond, false, false, nil, ""); err == nil {
		t.Fatal("expected error for bad URL")
	}
}

func TestSettingsApplyRemainingBranches(t *testing.T) {
	s := NewSettings()
	s.ApplySettings([]string{
		"image_proxy_type=http",
		"image_proxy_host=proxy.example",
		"image_proxy_port=3128",
		"cache_dir=/c",
		"temp_dir=/t",
		"log_dir=/l",
		"download_dir=/d",
		"data_dir=/dd",
		"verify_cache=true",
		"use_less_memory=true",
		"disable_bwm=true",
		"disable_download_bwm=true",
		"disable_file_verification=true",
		"disable_ip_origin_check=true",
		"disable_logging=true",
		"flush_logs=true",
		"max_allowed_filesize=123",
		"max_filename_length=200",
		"skip_free_space_check=true",
		"cur_client_build=999",
		"rescan_cache=true",
		"static_range_count=7",
		"filesystem_blocksize=2048",
		"diskremaining_bytes=1000",
		"host=5.6.7.8",
	})
	if s.ImageProxyHost != "proxy.example" || s.ImageProxyPort != 3128 || s.ImageProxyType != "http" {
		t.Fatalf("image proxy not applied: %+v", s)
	}
	if s.CacheDir != "/c" || s.DownloadDir != "/d" || s.DataDir != "/dd" {
		t.Fatal("dir settings not applied")
	}
	if !s.VerifyCache || !s.UseLessMemory || !s.DisableBWM || !s.DisableDownloadBWM {
		t.Fatal("flag settings not applied")
	}
	if !s.DisableFileVerify || !s.DisableIPOriginCheck || !s.DisableLogs || !s.FlushLogs {
		t.Fatal("flag settings not applied (2)")
	}
	if s.MaxAllowedFile != 123 || s.MaxFilenameLen != 200 || s.SkipFreeSpaceCheck != true {
		t.Fatal("limit settings not applied")
	}
	if !s.WarnNewClient || !s.RescanCache || s.StaticRangeCount != 7 {
		t.Fatal("misc settings not applied")
	}
}

func TestSettingsMinClientBuildTooOld(t *testing.T) {
	s := NewSettings()
	old := fatalError
	defer func() { fatalError = old }()
	fatalError = func(string) { panic("too old") }
	func() {
		defer func() { recover() }()
		s.ApplySettings([]string{"min_client_build=9999"})
	}()
}

// TestThreadedProxyTestCommand: servercmd threaded_proxy_test fetches from a /t
// origin and reports OK:<n>-<ms>.
func TestThreadedProxyTestCommand(t *testing.T) {
	_, s, _, srv := buildTestServer(t)
	// origin /t server that serves `size` bytes for any /t/... request
	tSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		size, _ := strconv.Atoi(parts[2])
		w.Header().Set("Content-Length", strconv.Itoa(size))
		w.WriteHeader(200)
		io.CopyN(w, zeroReader{}, int64(size))
	}))
	defer tSrv.Close()
	tPort := portOf(tSrv.URL)

	t0 := s.ServerTime()
	add := fmt.Sprintf("hostname=127.0.0.1;protocol=http;port=%d;testsize=512;testcount=3;testtime=%d;testkey=k", tPort, t0)
	key := servercmdKey("threaded_proxy_test", add, s.ClientID, t0, s.ClientKey)
	target := "/servercmd/threaded_proxy_test/" + add + "/" + strconv.FormatInt(t0, 10) + "/" + key
	resp, err := http.Get(srv.URL + target)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.HasPrefix(string(body), "OK:") {
		t.Fatalf("expected OK:n-ms, got %q (status %d)", body, resp.StatusCode)
	}
}

// TestPrunerLoopPrunes: an over-limit cache is pruned by the pruner goroutine.
func TestPrunerLoopPrunes(t *testing.T) {
	ch, s := buildCache(t)
	s.DiskLimit = 1
	f := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-5-jpg")
	src := filepath.Join(ch.settings.TempDir, "src")
	os.WriteFile(src, []byte("hello"), 0o644)
	ch.ImportFileToCache(src, f)
	old := time.Now().Add(-400 * 24 * time.Hour)
	os.Chtimes(ch.LocalPath(f), old, old)
	ch.mu.Lock()
	ch.staticRangeOldest[f.StaticRange()] = old.UnixMilli()
	ch.mu.Unlock()
	// pruner is already running (started by NewCacheHandler); wait for it to prune
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if ch.CacheCount() == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("pruner did not prune over-limit cache, count=%d", ch.CacheCount())
}

func TestClientResumeBranch(t *testing.T) {
	m, s, rpc := newMockRPC(t)
	m.setResponse(ActClientResume, "OK\n")
	c := NewHathClient(s, NewStats())
	c.rpc = rpc
	ch, _ := buildCache(t)
	c.cache = ch
	c.server = &HTTPServer{cert: &CertManager{settings: s}, settings: s}
	// a past suspend time triggers the resume branch in cycle()
	c.suspendedUntil = time.Now().Add(-time.Hour)
	c.cycle()
	if !c.suspendedUntil.IsZero() {
		t.Fatal("cycle should clear a past suspend time")
	}
}

func TestRefreshCerts(t *testing.T) {
	leaf, key := genCert(t)
	p12, err := sslmate.LegacyRC2.Encode(key, leaf, nil, testClientKey)
	if err != nil {
		t.Fatalf("encode p12: %v", err)
	}
	m, s, rpc := newMockRPC(t)
	dir := t.TempDir()
	s.CacheDir = filepath.Join(dir, "cache")
	s.TempDir = filepath.Join(dir, "tmp")
	s.DataDir = filepath.Join(dir, "data")
	s.LogDir = filepath.Join(dir, "log")
	s.MaxAllowedFile = 1 << 30
	s.DiskLimit = 100_000_000
	s.ClientPort = 0 // bind ephemeral
	for _, d := range []string{s.CacheDir, s.TempDir, s.DataDir, s.LogDir} {
		os.MkdirAll(d, 0o755)
	}
	m.certBytes = p12
	m.setResponse(ActClientSuspend, "OK\n")
	m.setResponse(ActStillAlive, "OK\n")

	c := NewHathClient(s, NewStats())
	c.rpc = rpc
	cm := &CertManager{settings: s}
	if err := cm.LoadOrRefresh(c.rpc); err != nil {
		t.Fatalf("load cert: %v", err)
	}
	c.cert = cm
	c.server = NewHTTPServer(s, nil, c.rpc, c.stats, cm, c)

	done := make(chan struct{})
	go func() {
		defer func() { recover(); close(done) }()
		c.refreshCerts()
	}()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("refreshCerts did not complete")
	}
	if c.server != nil {
		c.server.Shutdown()
	}
}

// helpers

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { for i := range p { p[i] = 0 }; return len(p), nil }

func portOf(u string) int {
	_, p, _ := splitHP(u)
	n, _ := strconv.Atoi(p)
	return n
}
func splitHP(u string) (string, string, error) {
	i := strings.Index(u, "://") + 3
	return splitOnce(u[i:], ":")
}
func splitOnce(s, sep string) (string, string, error) {
	i := strings.Index(s, sep)
	if i < 0 {
		return s, "", nil
	}
	return s[:i], s[i+1:], nil
}

