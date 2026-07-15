package hath

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestApplySettingsCore(t *testing.T) {
	s := NewSettings()
	s.ApplySettings([]string{
		"port=12345",
		"throttle_bytes=5000000",
		"disklimit_bytes=1000000000",
		"filesystem_blocksize=8192",
		"max_connections=100",
		"static_ranges=abcd;ef01;bad",
		"static_range_count=2",
		"use_less_memory=true",
		"disable_flood_control=true",
	})
	if s.ClientPort != 12345 || s.ThrottleBytes != 5000000 || s.DiskLimit != 1e9 {
		t.Fatal("core settings not applied")
	}
	if s.FSBlockSize != 8192 || s.OverrideConns != 100 || s.StaticRangeCount != 2 {
		t.Fatal("limit/static settings not applied")
	}
	if !s.UseLessMemory || !s.DisableFloodControl {
		t.Fatal("flags not applied")
	}
	// "bad" is only 3 chars → ignored; abcd & ef01 accepted
	if !s.IsStaticRange("abcd0000-1-jpg") || !s.IsStaticRange("ef010000-1-jpg") {
		t.Fatalf("static ranges wrong: %v", s.StaticRanges)
	}
	if s.IsStaticRange("ffff0000-1-jpg") {
		t.Fatal("unassigned range should not be static")
	}
}

func TestFilesystemBlocksizeClamped(t *testing.T) {
	s := NewSettings()
	s.ApplySettings([]string{"filesystem_blocksize=999999"})
	if s.FSBlockSize != 4096 {
		t.Fatalf("insane blocksize should clamp to 4096, got %d", s.FSBlockSize)
	}
}

func TestDiskLimitOnlyGrows(t *testing.T) {
	s := NewSettings()
	s.DiskLimit = 1000
	s.ApplySettings([]string{"disklimit_bytes=500"})
	if s.DiskLimit != 1000 {
		t.Fatal("disk limit must not shrink until restart")
	}
}

func TestParseArgs(t *testing.T) {
	s := NewSettings()
	s.ParseArgs([]string{"--cache-dir=/c", "--use-less-memory", "--bogus=1"})
	if s.CacheDir != "/c" || !s.UseLessMemory {
		t.Fatal("args not applied")
	}
}

func TestLoginRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := NewSettings()
	s.DataDir = dir
	s.ClientID = 5555
	s.ClientKey = "KeyKeyKeyKeyKeyKeyKK" // 20 chars
	if !s.LoginValid() {
		t.Fatal("login should be valid")
	}
	if err := s.SaveLogin(); err != nil {
		t.Fatal(err)
	}
	s2 := NewSettings()
	s2.DataDir = dir
	if err := s2.LoadLogin(); err != nil {
		t.Fatal(err)
	}
	if s2.ClientID != 5555 || s2.ClientKey != s.ClientKey {
		t.Fatal("login round-trip mismatch")
	}
}

func TestLoginValidity(t *testing.T) {
	s := NewSettings()
	if s.LoginValid() {
		t.Fatal("zero id should be invalid")
	}
	s.ClientID = 1
	s.ClientKey = "short"
	if s.LoginValid() {
		t.Fatal("short key invalid")
	}
	s.ClientKey = "has space here 12345" // contains space → invalid
	if s.LoginValid() {
		t.Fatal("non-alphanumeric key invalid")
	}
}

func TestMaxConnections(t *testing.T) {
	s := NewSettings()
	if s.MaxConnections() != 20 { // no throttle → base
		t.Fatalf("base conns = %d", s.MaxConnections())
	}
	s.ThrottleBytes = 5000000
	if got := s.MaxConnections(); got != 20+480 { // min(480, 500)=480
		t.Fatalf("throttle conns = %d", got)
	}
	s.OverrideConns = 42
	if s.MaxConnections() != 42 {
		t.Fatal("override not honored")
	}
}

func TestRPCServerFailover(t *testing.T) {
	s := NewSettings()
	s.mu.Lock()
	s.rpcServers = []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")}
	s.mu.Unlock()
	host := s.RPCServerHost()
	if host != "10.0.0.1" && host != "10.0.0.2" {
		t.Fatalf("unexpected host %q", host)
	}
	if !s.IsValidRPCServer(net.ParseIP("10.0.0.1")) {
		t.Fatal("should validate known rpc server")
	}
	if s.IsValidRPCServer(net.ParseIP("8.8.8.8")) {
		t.Fatal("should reject unknown ip")
	}
	s.MarkRPCServerFailure(host)
	// after failure, current cleared → reselect should avoid the failed one sometimes
	got := s.RPCServerHost()
	if got == "" {
		t.Fatal("should still pick a host after failure")
	}
	s.ClearRPCServerFailure()
}

func TestRPCServerHostDefault(t *testing.T) {
	s := NewSettings()
	if got := s.RPCServerHost(); got != ClientRPCHost {
		t.Fatalf("no servers → default host, got %q", got)
	}
}

func TestIsValidRPCServerBypass(t *testing.T) {
	s := NewSettings()
	s.DisableIPOriginCheck = true
	if !s.IsValidRPCServer(net.ParseIP("1.1.1.1")) {
		t.Fatal("ip-origin check disabled should allow all")
	}
}

func TestServerTimeDelta(t *testing.T) {
	s := NewSettings()
	s.SetServerTime(2_000_000_000)
	if s.ServerTime() < 1_999_999_900 || s.ServerTime() > 2_000_000_100 {
		t.Fatalf("server time not near 2e9: %d", s.ServerTime())
	}
}

func TestInitDirs(t *testing.T) {
	dir := t.TempDir()
	s := NewSettings()
	s.DataDir = filepath.Join(dir, "data")
	s.CacheDir = filepath.Join(dir, "cache")
	s.LogDir = filepath.Join(dir, "log")
	s.TempDir = filepath.Join(dir, "tmp")
	s.DownloadDir = filepath.Join(dir, "dl")
	if err := s.InitDirs(); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{s.DataDir, s.CacheDir, s.LogDir, s.TempDir, s.DownloadDir} {
		if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
			t.Fatalf("dir not created: %s", d)
		}
	}
}
