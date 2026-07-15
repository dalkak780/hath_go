package hath

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestGalleryUnicodeTitleByteCap reproduces the Java-on-ZFS failure mode: a
// long multi-byte (CJK) title must not overflow the 255-byte filesystem name
// limit (which made Java hit ENAMETOOLONG and fall back to an ASCII name).
// Go sizes by runes but now enforces the byte cap, preserving the unicode name.
func TestGalleryUnicodeTitleByteCap(t *testing.T) {
	s := NewSettings()
	s.DownloadDir = t.TempDir()
	s.MaxFilenameLen = 125
	g := &GalleryDownloader{settings: s, gid: 5, minxres: "org"}

	long := ""
	for i := 0; i < 200; i++ {
		long += "東"
	}
	g.setTitle(long)

	base := filepath.Base(g.todir)
	if got := len([]byte(base)); got > 255 {
		t.Fatalf("dir name is %d bytes, exceeds the 255-byte filesystem limit: %q", got, base)
	}
	// unicode must be preserved — NOT dropped to the ASCII "5" fallback
	if base == "5" {
		t.Fatalf("unicode title was dropped to the ASCII fallback name: %q", base)
	}
	if !containsRune(base, '東') {
		t.Fatalf("unicode runes were not preserved in %q", base)
	}
}

// TestGalleryUnicodeTitleShort keeps a short unicode title verbatim (parity
// with Java for titles that already fit).
func TestGalleryUnicodeTitleShort(t *testing.T) {
	s := NewSettings()
	s.DownloadDir = t.TempDir()
	s.MaxFilenameLen = 125
	g := &GalleryDownloader{settings: s, gid: 7, minxres: "org"}
	g.setTitle("東方Project_日本語タイトル")
	if got, want := filepath.Base(g.todir), "東方Project_日本語タイトル [7]"; got != want {
		t.Fatalf("short unicode title mangled: got %q want %q", got, want)
	}
}

// TestGalleryUnicodeDownload drives a full gallery download with a unicode
// title and a unicode image filename, asserting the files land on disk with
// the correct unicode names (Go writes native UTF-8, so ZFS utf8only accepts).
func TestGalleryUnicodeDownload(t *testing.T) {
	content := []byte("unicode-gallery-bytes")
	hash := sha1HexOf(content)
	origin := originFileServer(t, content)
	defer origin.Close()

	m, s, rpc := newMockRPC(t)
	dir := t.TempDir()
	s.CacheDir = filepath.Join(dir, "cache")
	s.TempDir = filepath.Join(dir, "tmp")
	s.DataDir = filepath.Join(dir, "data")
	s.LogDir = filepath.Join(dir, "log")
	s.DownloadDir = filepath.Join(dir, "dl")
	s.MaxFilenameLen = 125
	s.MaxAllowedFile = 1 << 30
	s.DisableDownloadBWM = true
	s.SkipFreeSpaceCheck = true
	for _, d := range []string{s.CacheDir, s.TempDir, s.DataDir, s.LogDir, s.DownloadDir} {
		os.MkdirAll(d, 0o755)
	}

	title := "東方Project_日本語タイトル"
	file := "桜の画像"
	m.setResponse("fetchqueue", "OK\nGID 7\nFILECOUNT 1\nMINXRES org\nTITLE "+title+"\nFILELIST\n1 0 org "+hash+" jpg "+file+"\nINFORMATION\ninfo\n")
	m.setResponse(ActDownloaderFetch, "OK\n"+origin.URL+"/file\n")

	client := NewHathClient(s, NewStats())
	client.rpc = rpc
	cache, _ := NewCacheHandler(client)
	t.Cleanup(func() { cache.pruner.stop() })
	client.cache = cache

	client.StartDownloader()

	gdir := filepath.Join(s.DownloadDir, title+" [7]")
	dest := filepath.Join(gdir, file+".jpg")
	deadline := time.Now().Add(5 * time.Second)
	found := false
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(dest); err == nil && string(b) == string(content) {
			found = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !found {
		ents, _ := os.ReadDir(s.DownloadDir)
		names := make([]string, 0, len(ents))
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Fatalf("unicode gallery file not created at %s; download dir contains: %v", dest, names)
	}
	client.shutdown = true
	time.Sleep(100 * time.Millisecond)
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}
