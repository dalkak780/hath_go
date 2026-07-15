package hath

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestGalleryFinalizeFailure(t *testing.T) {
	g := &GalleryDownloader{settings: NewSettings(), title: "x"}
	// failure branch: should warn and not panic
	g.finalize(false)
	if g.pending {
		t.Fatal("finalize should clear pending")
	}
}

func TestGalleryFinalizeWriteError(t *testing.T) {
	s := NewSettings()
	s.DownloadDir = t.TempDir()
	ro := filepath.Join(s.DownloadDir, "ro")
	os.MkdirAll(ro, 0o755)
	os.Chmod(ro, 0o500)
	defer os.Chmod(ro, 0o755)
	g := &GalleryDownloader{settings: s, title: "x", todir: filepath.Join(ro, "sub")}
	// todir parent is read-only -> galleryinfo.txt write fails -> warn path
	g.finalize(true)
}

func TestGalleryDownloadAlreadyExists(t *testing.T) {
	s := NewSettings()
	s.DownloadDir = t.TempDir()
	g := &GalleryDownloader{settings: s, todir: s.DownloadDir, stats: NewStats()}
	content := []byte("already-here")
	sha := sha1HexOf(content)
	gf := &galleryFile{fileindex: 0, xres: "org", sha1: sha, filetype: "jpg", filename: "f"}
	dest := gf.path(g)
	os.WriteFile(dest, content, 0o644)
	if st := gf.download(g); st != dlAlready {
		t.Fatalf("expected dlAlready, got %d", st)
	}
}

func TestGalleryDownloadCorrupt(t *testing.T) {
	// origin serves WRONG bytes; gf.sha1 is the hash of the expected content,
	// so the post-download SHA-1 check must fail and mark dlFailed.
	wrong := []byte("this is not the content")
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(wrong)
	}))
	defer origin.Close()

	m, s, rpc := newMockRPC(t)
	s.MaxAllowedFile = 1 << 30
	good := []byte("the real content")
	sha := sha1HexOf(good)
	m.setResponse(ActDownloaderFetch, "OK\n"+origin.URL+"/f\n")

	g := &GalleryDownloader{settings: s, rpc: rpc, todir: s.DownloadDir, stats: NewStats()}
	gf := &galleryFile{page: 1, fileindex: 0, xres: "org", sha1: sha, filetype: "jpg", filename: "f"}
	if st := gf.download(g); st != dlFailed {
		t.Fatalf("expected dlFailed for corrupt download, got %d", st)
	}
}

func TestGalleryFetchMetaNoPending(t *testing.T) {
	m, s, rpc := newMockRPC(t)
	m.setResponse("fetchqueue", "NO_PENDING_DOWNLOADS\n")
	g := &GalleryDownloader{settings: s, rpc: rpc}
	if g.fetchMeta() {
		t.Fatal("NO_PENDING_DOWNLOADS should yield false")
	}
	m.setResponse("fetchqueue", "INVALID_REQUEST\n")
	if g.fetchMeta() {
		t.Fatal("INVALID_REQUEST should yield false")
	}
}

func TestGalleryFetchMetaReportsFailures(t *testing.T) {
	m, s, rpc := newMockRPC(t)
	m.setResponse("fetchqueue", "OK\nGID 7\nFILECOUNT 1\nMINXRES org\nTITLE G\nFILELIST\n1 0 org abcdefghijklmnopqrstuvwxyz0123456789abcd jpg p\nINFORMATION\n")
	g := &GalleryDownloader{settings: s, rpc: rpc}
	g.marked = true
	g.failures = []string{"h-0-org"}
	if !g.fetchMeta() {
		t.Fatal("fetchMeta should succeed and report prior failures")
	}
}

func TestGallerySetTitleTraversalGuard(t *testing.T) {
	s := NewSettings()
	s.DownloadDir = t.TempDir()
	g := &GalleryDownloader{settings: s, rpc: &ServerHandler{settings: s}}
	g.minxres = "org"
	// ".." survives sanitization and produces a path outside DownloadDir,
	// exercising the traversal guard (dir is reset to a safe fallback).
	g.setTitle("..")
	if filepath.Dir(g.todir) != s.DownloadDir {
		t.Fatalf("traversal guard should keep todir under DownloadDir: %q", g.todir)
	}
}
