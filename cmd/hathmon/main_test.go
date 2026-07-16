package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseKB(t *testing.T) {
	if got := parseKB("123 kB"); got != 123*1024 {
		t.Fatalf("parseKB = %d", got)
	}
}

func TestCaptureCPUProfileUsesPprofProfileEndpoint(t *testing.T) {
	requested := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = r.URL.Path
		_, _ = w.Write([]byte("profile"))
	}))
	defer server.Close()
	dir := t.TempDir()
	cfg := config{dir: dir, pprofURL: server.URL, cpuDuration: time.Second}
	now := time.Now()
	captureProfile(cfg, "cpu", now, 2*time.Second)
	if requested != "/debug/pprof/profile" {
		t.Fatalf("requested %q", requested)
	}
	if _, err := os.Stat(filepath.Join(dir, "cpu-"+now.Format("20060102-150405")+".pprof")); err != nil {
		t.Fatal(err)
	}
}

func TestAppendAndPrune(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	if err := appendSample(dir, sample{Time: now, RSSBytes: 123}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "metrics-"+now.Format("20060102")+".jsonl")
	old := now.Add(-48 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	prune(dir, now.Add(-24*time.Hour))
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("old metric file was not pruned: %v", err)
	}
}
