package hath

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- Settings branches ---

func TestInitDirsBadParent(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "file")
	os.WriteFile(f, []byte("x"), 0o644)
	s := NewSettings()
	s.DataDir = filepath.Join(f, "sub") // parent is a file → MkdirAll fails
	if err := s.InitDirs(); err == nil {
		t.Fatal("expected InitDirs error when parent is a file")
	}
}

func TestParseArgsInvalidAndValid(t *testing.T) {
	s := NewSettings()
	s.ParseArgs([]string{"notaflag", "--cache-dir=/c", "--use-less-memory"})
	if s.CacheDir != "/c" || !s.UseLessMemory {
		t.Fatal("valid args not applied")
	}
	// the no-prefix branch was exercised by "notaflag" (Warn, continue)
}

func TestApplySettingsEmptyAndNoEquals(t *testing.T) {
	s := NewSettings()
	s.ApplySettings([]string{"", "noequals", "cache_dir=/x"})
	if s.CacheDir != "/x" {
		t.Fatal("key=val not applied")
	}
}

func TestIsStaticRangeNilAndShort(t *testing.T) {
	s := NewSettings() // StaticRanges nil
	if s.IsStaticRange("abcd0000-1-jpg") {
		t.Fatal("nil ranges → not static")
	}
	s.StaticRanges = map[string]bool{}
	if s.IsStaticRange("ab") { // len < 4
		t.Fatal("short fileid → not static")
	}
}

func TestSetRPCServersClearsCurrentOnMiss(t *testing.T) {
	s := NewSettings()
	s.mu.Lock()
	s.rpcServerCurrent = "1.2.3.4"
	s.mu.Unlock()
	s.setRPCServers("5.6.7.8;notanip") // current not in new set → cleared; invalid skipped
	s.mu.Lock()
	cur := s.rpcServerCurrent
	s.mu.Unlock()
	if cur != "" {
		t.Fatalf("current should be cleared, got %q", cur)
	}
}

func TestRPCServerHostAllPaths(t *testing.T) {
	s := NewSettings()
	// 0 servers → default host (no rpcServerCurrent, no servers)
	if got := s.RPCServerHost(); got != ClientRPCHost {
		t.Fatalf("0 servers → default, got %q", got)
	}
	// 1 server
	s.mu.Lock()
	s.rpcServers = []net.IP{net.ParseIP("9.9.9.9")}
	s.mu.Unlock()
	if got := s.RPCServerHost(); got != "9.9.9.9" {
		t.Fatalf("1 server → it, got %q", got)
	}
	// 2 servers: many calls to exercise both scan directions + last-fail skip
	s.mu.Lock()
	s.rpcServers = []net.IP{net.ParseIP("9.9.9.9"), net.ParseIP("8.8.8.8")}
	s.mu.Unlock()
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		seen[s.RPCServerHost()] = true
		s.MarkRPCServerFailure("9.9.9.9")
		s.RPCServerHost() // reselect, avoiding last failed
		s.ClearRPCServerFailure()
	}
	if !seen["9.9.9.9"] || !seen["8.8.8.8"] {
		t.Fatalf("expected both servers chosen, seen=%v", seen)
	}
}

// --- Helpers ---

func TestWalkRangeDirsErrorAndStructure(t *testing.T) {
	// error: root does not exist
	if err := walkRangeDirs(filepath.Join(t.TempDir(), "nope"), func(string, string, []os.DirEntry) {}); err == nil {
		t.Fatal("expected error for missing root")
	}
	// structure: file at root (skipped), subdir with file (skipped), subdir/subdir with file (visited)
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "afile"), []byte("x"), 0o644)
	l1 := filepath.Join(root, "aa")
	os.MkdirAll(l1, 0o755)
	os.WriteFile(filepath.Join(l1, "notdir"), []byte("x"), 0o644)
	l2 := filepath.Join(l1, "bb")
	os.MkdirAll(l2, 0o755)
	os.WriteFile(filepath.Join(l2, "file1.bin"), []byte("hello"), 0o644)
	visited := 0
	if err := walkRangeDirs(root, func(l1n, l2n string, files []os.DirEntry) {
		visited++
		if l1n != "aa" || l2n != "bb" || len(files) != 1 {
			t.Fatalf("unexpected visit %s/%s files=%d", l1n, l2n, len(files))
		}
	}); err != nil {
		t.Fatal(err)
	}
	if visited != 1 {
		t.Fatalf("expected 1 visit, got %d", visited)
	}
}

func TestValidateFileSHA1AllPaths(t *testing.T) {
	// open error
	if validateFileSHA1(filepath.Join(t.TempDir(), "missing"), "abc") {
		t.Fatal("missing file should be invalid")
	}
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	// mismatch
	if validateFileSHA1(p, "deadbeef") {
		t.Fatal("wrong hash should be invalid")
	}
	// match (sha1 of "data")
	if !validateFileSHA1(p, sha1Hex("data")) {
		t.Fatal("correct hash should validate")
	}
}

func TestDiskFreeErrorAndOk(t *testing.T) {
	if got := diskFree(filepath.Join(t.TempDir(), "missing")); got != 1<<63-1 {
		t.Fatalf("error path should return effectively-unlimited, got %d", got)
	}
	if got := diskFree(t.TempDir()); got <= 0 {
		t.Fatalf("should report free bytes, got %d", got)
	}
}

// --- Cert error branches ---

func TestCertLoadOrRefreshGetError(t *testing.T) {
	m, s, rpc := newMockRPC(t)
	m.certBytes = nil // get_cert yields nothing → fetchFile fails
	cm := &CertManager{settings: s}
	if err := cm.LoadOrRefresh(rpc); err == nil {
		t.Fatal("expected error when cert cannot be fetched")
	}
}

// --- Gallery branches ---

func TestGallerySetTitleLongTruncate(t *testing.T) {
	s := NewSettings()
	s.DownloadDir = t.TempDir()
	s.MaxFilenameLen = 20
	g := &GalleryDownloader{settings: s, rpc: &ServerHandler{settings: s}}
	g.gid = 42
	g.minxres = "org"
	g.setTitle(strings.Repeat("A", 200)) // forces rune + byte truncation
	if g.todir == "" || g.title == "" {
		t.Fatal("setTitle did not set dir/title")
	}
	if len([]byte(g.title)) > 255 {
		t.Fatal("title exceeded 255 bytes")
	}
}

func TestGallerySetTitleTraversalGuardCovered(t *testing.T) {
	s := NewSettings()
	s.DownloadDir = t.TempDir()
	s.MaxFilenameLen = 125
	g := &GalleryDownloader{settings: s, rpc: &ServerHandler{settings: s}}
	g.gid = 7
	g.minxres = "1600"
	g.setTitle("Normal Title")
	if !strings.HasPrefix(g.todir, s.DownloadDir) {
		t.Fatalf("todir should be under download dir, got %q", g.todir)
	}
}

func TestGalleryParseMetaRejectMissing(t *testing.T) {
	s := NewSettings()
	s.DownloadDir = t.TempDir()
	g := &GalleryDownloader{settings: s, rpc: &ServerHandler{settings: s}}
	// MINXRES invalid → parseMeta returns false (covers the bad-minxres reject)
	if g.parseMeta("GID 1\nFILECOUNT 1\nMINXRES bad\nTITLE T\nFILELIST\nINFORMATION\n") {
		t.Fatal("invalid minxres should fail")
	}
	// valid parse with INFORMATION text
	g2 := &GalleryDownloader{settings: s, rpc: &ServerHandler{settings: s}}
	g2.gid = 1
	g2.minxres = "org"
	if !g2.parseMeta("GID 5\nFILECOUNT 1\nMINXRES org\nTITLE G\nFILELIST\n1 0 org abcdefghijklmnopqrstuvwxyz0123456789abcd jpg p\nINFORMATION\ninfo text\n") {
		t.Fatal("valid metadata should parse")
	}
	if g2.gid != 5 || len(g2.files) != 1 || strings.TrimRight(g2.info, "\n") != "info text" {
		t.Fatalf("parsed fields wrong: %+v", g2)
	}
}

func TestGalleryFetchMetaInvalidAndEmpty(t *testing.T) {
	m, s, rpc := newMockRPC(t)
	m.setResponse("fetchqueue", "NO_PENDING_DOWNLOADS\n")
	g := &GalleryDownloader{settings: s, rpc: rpc}
	if g.fetchMeta() {
		t.Fatal("NO_PENDING_DOWNLOADS → false")
	}
	m.setResponse("fetchqueue", "INVALID_REQUEST\n")
	if g.fetchMeta() {
		t.Fatal("INVALID_REQUEST → false")
	}
}

func TestGalleryParseAndReset(t *testing.T) {
	s := NewSettings()
	s.DownloadDir = t.TempDir()
	g := &GalleryDownloader{settings: s, rpc: &ServerHandler{settings: s}}
	gf := parseGalleryFile("1 2 org abcdefghijklmnopqrstuvwxyz0123456789abcd jpg p.jpg")
	if gf == nil || gf.page != 1 || gf.fileindex != 2 || gf.filetype != "jpg" {
		t.Fatalf("parseGalleryFile wrong: %+v", gf)
	}
	if parseGalleryFile("1 2 org x") != nil {
		t.Fatal("malformed line should be nil")
	}
	gu := parseGalleryFile("1 2 org unknown jpg p")
	if gu == nil || gu.sha1 != "" {
		t.Fatal("unknown sha1 should become empty")
	}
	g.gid = 1
	g.title = "t"
	g.reset()
	if g.gid != 0 || g.title != "" || g.files != nil {
		t.Fatal("reset did not clear state")
	}
}
