package hath

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	sslmate "software.sslmate.com/src/go-pkcs12"
)

// freePort reserves and returns an unused TCP port.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// TestClientRunEndToEnd brings up the full client against a mock RPC with a real
// PKCS#12 cert, verifies the TLS edge server answers, then shuts down cleanly.
// This exercises Run, startServer, server.Start (TLS), cycle, stillAlive, and
// doShutdown — the lifecycle paths unit tests can't reach in isolation.
func TestClientRunEndToEnd(t *testing.T) {
	port := freePort(t)
	leaf, key := genCert(t)
	p12, err := sslmate.LegacyRC2.Encode(key, leaf, nil, testClientKey)
	if err != nil {
		t.Fatalf("encode p12: %v", err)
	}

	m, s, _ := newMockRPC(t)
	dir := t.TempDir()
	s.CacheDir = filepath.Join(dir, "cache")
	s.TempDir = filepath.Join(dir, "tmp")
	s.DataDir = filepath.Join(dir, "data")
	s.LogDir = filepath.Join(dir, "log")
	s.DownloadDir = filepath.Join(dir, "dl")
	s.MaxAllowedFile = 1 << 30
	s.DiskLimit = 100_000_000
	for _, d := range []string{s.CacheDir, s.TempDir, s.DataDir, s.LogDir, s.DownloadDir} {
		os.MkdirAll(d, 0o755)
	}
	m.certBytes = p12
	m.setResponse(ActClientLogin, fmt.Sprintf("OK\nport=%d\nthrottle_bytes=1000000\ndisklimit_bytes=100000000\nstatic_range_count=0\nhost=127.0.0.1\n", port))
	m.setResponse(ActClientStart, "OK\n")
	m.setResponse(ActClientSettings, "OK\n")
	m.setResponse(ActStillAlive, "OK\n")
	m.setResponse(ActClientStop, "OK\n")

	client := NewHathClient(s, NewStats())
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- client.Run(ctx) }()

	// poll the TLS edge until it answers (or timeout)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	cli := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	var ok bool
	for i := 0; i < 60; i++ {
		resp, err := cli.Get("https://" + addr + "/robots.txt")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				ok = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ok {
		cancel()
		t.Fatal("TLS edge server never answered")
	}

	// exercise a /h request path (uncached → 404/502 since mock srfetch is empty)
	f := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-5-jpg")
	resp, err := cli.Get("https://" + addr + validHTarget(s, f.Fileid()))
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode != 404 && resp.StatusCode != 502 {
			t.Errorf("uncached /h expected 404/502, got %d", resp.StatusCode)
		}
	}

	cancel()
	select {
	case <-runDone:
	case <-time.After(10 * time.Second):
		t.Fatal("client did not shut down within 10s")
	}
}
