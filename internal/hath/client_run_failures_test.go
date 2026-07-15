package hath

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sslmate "software.sslmate.com/src/go-pkcs12"
)

func baseRunClient(t *testing.T) (*HathClient, *mockRPC, *Settings, string) {
	t.Helper()
	port := freePort(t)
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
	m.setResponse(ActClientLogin, fmt.Sprintf("OK\nport=%d\nthrottle_bytes=1000000\ndisklimit_bytes=100000000\nstatic_range_count=0\nhost=127.0.0.1\n", port))
	m.setResponse(ActClientStart, "OK\n")
	m.setResponse(ActClientSettings, "OK\n")
	m.setResponse(ActStillAlive, "OK\n")
	m.setResponse(ActClientStop, "OK\n")
	c := NewHathClient(s, NewStats())
	return c, m, s, dir
}

// runUntilReturn invokes Run in a goroutine and returns its error (or fails on timeout).
func runUntilReturn(t *testing.T, c *HathClient) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- c.Run(context.Background()) }()
	select {
	case err := <-done:
		return err
	case <-time.After(8 * time.Second):
		t.Fatal("Run did not return in time")
		return nil
	}
}

func TestRunFailsOnEmptyCacheWithRanges(t *testing.T) {
	c, m, s, _ := baseRunClient(t)
	// override: many static ranges, empty cache → NewCacheHandler error
	m.setResponse(ActClientLogin, "OK\nport=1\nthrottle_bytes=1000000\ndisklimit_bytes=100000000\nstatic_range_count=30\nhost=127.0.0.1\n")
	_ = s
	err := runUntilReturn(t, c)
	if err == nil {
		t.Fatal("expected Run to fail on empty cache with assigned ranges")
	}
}

func TestRunFailsOnCertFetch(t *testing.T) {
	c, m, _, _ := baseRunClient(t)
	m.certBytes = nil // get_cert yields nothing → startServer fails
	err := runUntilReturn(t, c)
	if err == nil {
		t.Fatal("expected Run to fail when the cert cannot be fetched")
	}
}

func TestRunFailsOnNotifyStart(t *testing.T) {
	c, m, _, _ := baseRunClient(t)
	leaf, key := genCert(t)
	p12, err := sslmate.LegacyRC2.Encode(key, leaf, nil, testClientKey)
	if err != nil {
		t.Fatal(err)
	}
	m.certBytes = p12
	m.setResponse(ActClientStart, "FAIL_CONNECT_TEST\n")
	err = runUntilReturn(t, c)
	if err == nil || (err != nil && !containsStr(err.Error(), "startup notification")) {
		t.Fatalf("expected startup-notification failure, got %v", err)
	}
}

func TestNewCacheHandlerInsufficientDisk(t *testing.T) {
	s := NewSettings()
	s.ClientID = testClientID
	s.ClientKey = testClientKey
	dir := t.TempDir()
	s.CacheDir = filepath.Join(dir, "cache")
	s.TempDir = filepath.Join(dir, "tmp")
	s.DataDir = filepath.Join(dir, "data")
	s.DiskLimit = 1 << 40 // absurdly large → free space insufficient
	os.MkdirAll(s.CacheDir, 0o755)
	os.MkdirAll(s.TempDir, 0o755)
	os.MkdirAll(s.DataDir, 0o755)
	c := &HathClient{settings: s, stats: NewStats()}
	if _, err := NewCacheHandler(c); err == nil {
		t.Fatal("expected insufficient-disk error")
	}
}

func TestNewCacheHandlerTmpNonFile(t *testing.T) {
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
	// a subdirectory in tmp → exercises the non-file warn branch
	os.MkdirAll(filepath.Join(s.TempDir, "subdir"), 0o755)
	c := &HathClient{settings: s, stats: NewStats()}
	ch, err := NewCacheHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	ch.pruner.stop()
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && strings.Contains(s, sub)
}
