package hath

import (
	"path/filepath"
	"testing"
)

func TestGallerySetTitleTinyMaxLen(t *testing.T) {
	s := NewSettings()
	s.DownloadDir = t.TempDir()
	s.MaxFilenameLen = 3 // postfix " [1]" (len 5) already exceeds the budget
	g := &GalleryDownloader{settings: s, rpc: &ServerHandler{settings: s}}
	g.gid = 1
	g.minxres = "org"
	g.setTitle("A very long title that overflows the tiny max length budget by a lot")
	if g.todir == "" || g.title == "" {
		t.Fatal("setTitle should still produce a dir/title")
	}
	// the rune/byte caps must keep the name within limits
	if len([]byte(g.title)) > 255 {
		t.Fatal("title exceeded 255 bytes")
	}
}

func TestGallerySetTitleTraversalGuardEscape(t *testing.T) {
	s := NewSettings()
	s.DownloadDir = t.TempDir()
	s.MaxFilenameLen = 125
	g := &GalleryDownloader{settings: s, rpc: &ServerHandler{settings: s}}
	g.gid = 1
	g.minxres = "org"
	// a title that would resolve outside the download dir → fallback to gid dir
	g.setTitle("../../escape")
	if filepath.Dir(g.todir) != s.DownloadDir {
		t.Fatalf("todir parent must be the download dir, got %q", g.todir)
	}
}
