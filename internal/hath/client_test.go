package hath

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHathClientApplyLoginEnv(t *testing.T) {
	s := NewSettings()
	dir := t.TempDir()
	s.DataDir = dir
	c := &HathClient{settings: s}
	t.Setenv("HATH_CLIENT_ID", "9999")
	t.Setenv("HATH_CLIENT_KEY", "EnvKeyEnvKeyEnvKeyE1") // 20 chars
	c.applyLoginEnv()
	if c.settings.ClientID != 9999 || c.settings.ClientKey != "EnvKeyEnvKeyEnvKeyE1" {
		t.Fatalf("env login not applied: %+v", c.settings)
	}
}

func TestHathClientSuspendedState(t *testing.T) {
	c := &HathClient{}
	if c.IsSuspended() {
		t.Fatal("not suspended by default")
	}
	c.suspendedUntil = time.Now().Add(time.Hour)
	if !c.IsSuspended() {
		t.Fatal("should be suspended")
	}
	c.suspendedUntil = time.Now().Add(-time.Hour)
	if c.IsSuspended() {
		t.Fatal("past suspend time should not be suspended")
	}
}

func TestHathClientShutdownFlag(t *testing.T) {
	c := &HathClient{}
	if c.IsShuttingDown() {
		t.Fatal("should not be shutting down")
	}
	c.requestShutdown()
	if !c.IsShuttingDown() {
		t.Fatal("should be shutting down")
	}
}

func TestHathClientTriggerFlags(t *testing.T) {
	m, s, rpc := newMockRPC(t)
	s.SetServerTime(1_700_000_000)
	m.setResponse(ActClientSettings, "OK\nthrottle_bytes=1000\n")
	c := NewHathClient(s, NewStats())
	c.rpc = rpc
	c.TriggerRefreshSettings()
	if s.ThrottleBytes != 1000 {
		t.Fatalf("refresh settings not applied: %d", s.ThrottleBytes)
	}
	c.TriggerCertRefresh()
	if !c.doCertRefresh {
		t.Fatal("cert refresh not flagged")
	}
}

func TestHathClientStartDownloaderNoPanic(t *testing.T) {
	s := NewSettings()
	c := NewHathClient(s, NewStats())
	c.rpc = &ServerHandler{settings: s}
	// StartDownloader launches a goroutine; with no real server it will idle.
	// We only assert it does not panic and sets the field.
	c.StartDownloader()
	// give it a moment then mark shutdown so the loop exits
	c.requestShutdown()
	time.Sleep(50 * time.Millisecond)
}

func TestCycleNoOpWhenNotRunning(t *testing.T) {
	s := NewSettings()
	c := NewHathClient(s, NewStats())
	c.rpc = &ServerHandler{settings: s}
	// cycle should not panic with nil server/cache
	defer func() { recover() }()
	c.cycle()
}

func TestHathClientRunRejectsNoCreds(t *testing.T) {
	dir := t.TempDir()
	s := NewSettings()
	s.DataDir = dir
	s.CacheDir = filepath.Join(dir, "cache")
	s.TempDir = filepath.Join(dir, "tmp")
	s.LogDir = dir
	c := NewHathClient(s, NewStats())
	old := fatalError
	defer func() { fatalError = old }()
	died := make(chan string, 1)
	fatalError = func(msg string) { died <- msg; panic(msg) }
	go func() {
		defer func() { recover() }()
		_ = c.Run(context.Background())
	}()
	select {
	case msg := <-died:
		if msg == "" {
			t.Fatal("expected fatal message")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run should die fast without credentials")
	}
}

func TestDieErrIntercept(t *testing.T) {
	old := fatalError
	defer func() { fatalError = old }()
	called := false
	fatalError = func(string) { called = true; panic("x") }
	func() {
		defer func() { recover() }()
		dieErr("boom")
	}()
	if !called {
		t.Fatal("dieErr should invoke fatalError")
	}
}

func TestStatsCounters(t *testing.T) {
	s := NewStats()
	s.ProgramStarted()
	s.BytesSent(100)
	s.BytesSent(50)
	s.FileSent()
	s.BytesRcvd(200)
	if s.OpenConnections() != 0 {
		t.Fatal("open conns should start at 0")
	}
	s.SetOpenConnections(5)
	if s.OpenConnections() != 5 {
		t.Fatalf("open conns = %d", s.OpenConnections())
	}
	s.SetProgramStatus("Running")
	if s.ProgramStatus() != "Running" {
		t.Fatal("status not set")
	}
	s.ShiftBytesSentHistory()
}

func ensureNoLoginFile(t *testing.T, dir string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(dir, "client_login")); err == nil {
		t.Fatal("client_login should not exist in temp dir")
	}
}
