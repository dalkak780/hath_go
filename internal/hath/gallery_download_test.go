package hath

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestGalleryDownloadLoop: the downloader polls fetchqueue, parses metadata,
// fetches each file from a server-suggested origin, verifies SHA-1, and writes
// it to the download dir.
func TestGalleryDownloadLoop(t *testing.T) {
	content := []byte("gallery-bytes")
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

	m.setResponse("fetchqueue", "OK\nGID 5\nFILECOUNT 1\nMINXRES org\nTITLE GalleryOne\nFILELIST\n1 0 org "+hash+" jpg test\nINFORMATION\nsome info\n")
	m.setResponse(ActDownloaderFetch, "OK\n"+origin.URL+"/file\n")

	client := NewHathClient(s, NewStats())
	client.rpc = rpc
	// cache is needed by the client shutdown path; build it
	cache, _ := NewCacheHandler(client)
	t.Cleanup(func() { cache.pruner.stop() })
	client.cache = cache

	client.StartDownloader()

	gdir := filepath.Join(s.DownloadDir, "GalleryOne [5]")
	dest := filepath.Join(gdir, "test.jpg")
	info := filepath.Join(gdir, "galleryinfo.txt")
	deadline := time.Now().Add(5 * time.Second)
	var found bool
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(dest); err == nil && string(b) == string(content) {
			// wait for finalize to write galleryinfo.txt (happens after the post-download sleep)
			if _, err := os.Stat(info); err == nil {
				found = true
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !found {
		t.Fatalf("gallery not fully downloaded (file+galleryinfo) at %s", dest)
	}
	// stop the downloader loop
	client.requestShutdown()
	time.Sleep(100 * time.Millisecond)
}
