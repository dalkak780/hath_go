package hath

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGalleryParseMeta(t *testing.T) {
	s := NewSettings()
	s.ClientID = testClientID
	s.MaxFilenameLen = 125
	g := &GalleryDownloader{settings: s, rpc: &ServerHandler{settings: s}}
	meta := "GID 4242\nFILECOUNT 2\nMINXRES org\nTITLE Test Gallery\nFILELIST\n1 0 org aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa jpg page1\n2 1 org unknown png page two\nINFORMATION\nsome info line\n"
	if !g.parseMeta(meta) {
		t.Fatal("parseMeta should succeed")
	}
	if g.gid != 4242 || g.filecount != 2 || g.minxres != "org" {
		t.Fatalf("header wrong: %+v", g)
	}
	if g.title != "Test Gallery" {
		t.Fatalf("title wrong: %q", g.title)
	}
	if len(g.files) != 2 {
		t.Fatalf("expected 2 files, got %d", len(g.files))
	}
	if g.files[0].page != 1 || g.files[0].filetype != "jpg" || g.files[0].sha1 != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("file1 wrong: %+v", g.files[0])
	}
	if g.files[1].sha1 != "" {
		t.Fatalf("unknown hash should be empty: %q", g.files[1].sha1)
	}
	if !strings.HasSuffix(g.todir, " [4242]") {
		t.Fatalf("todir postfix wrong: %q", g.todir)
	}
	if !strings.HasPrefix(g.todir, s.DownloadDir) {
		t.Fatalf("todir must be under download dir: %q", g.todir)
	}
	if !strings.Contains(g.info, "some info line") {
		t.Fatalf("information not captured: %q", g.info)
	}
}

func TestGalleryTitleSanitization(t *testing.T) {
	s := NewSettings()
	s.MaxFilenameLen = 125
	g := &GalleryDownloader{settings: s, rpc: &ServerHandler{settings: s}}
	// forbidden chars stripped, whitespace collapsed
	g.minxres = "780"
	meta := "GID 9\nFILECOUNT 1\nMINXRES 780\nTITLE a*b<c>d:e|f?g  hi\nFILELIST\n1 0 780 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa jpg x\nINFORMATION\n"
	if !g.parseMeta(meta) {
		t.Fatal("parseMeta failed")
	}
	if g.title != "abcdefg hi" {
		t.Fatalf("title not sanitized: %q", g.title)
	}
	if !strings.HasSuffix(g.todir, " [9-780x]") {
		t.Fatalf("xres postfix wrong: %q", g.todir)
	}
}

func TestGalleryTitleTruncation(t *testing.T) {
	s := NewSettings()
	s.MaxFilenameLen = 20 // very short to force truncation
	s.DownloadDir = t.TempDir()
	g := &GalleryDownloader{settings: s, rpc: &ServerHandler{settings: s}}
	long := strings.Repeat("A", 50)
	meta := "GID 1\nFILECOUNT 1\nMINXRES org\nTITLE " + long + "\nFILELIST\n1 0 org aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa jpg x\nINFORMATION\n"
	if !g.parseMeta(meta) {
		t.Fatal("parseMeta failed")
	}
	name := filepath.Base(g.todir)
	if len([]rune(name)) > s.MaxFilenameLen {
		t.Fatalf("truncated dir name too long: %q (%d runes)", name, len([]rune(name)))
	}
	if !strings.Contains(name, "...") {
		t.Fatalf("expected truncation marker: %q", name)
	}
}

func TestGalleryParseMetaRejectsBadMinxres(t *testing.T) {
	s := NewSettings()
	g := &GalleryDownloader{settings: s, rpc: &ServerHandler{settings: s}}
	meta := "GID 1\nFILECOUNT 1\nMINXRES EVIL\nTITLE x\nFILELIST\n1 0 org aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa jpg x\nINFORMATION\n"
	if g.parseMeta(meta) {
		t.Fatal("should reject invalid minxres")
	}
}

func TestGalleryFileParse(t *testing.T) {
	gf := parseGalleryFile("3 12 780 abcdef jpg my file name")
	if gf == nil || gf.page != 3 || gf.fileindex != 12 || gf.xres != "780" ||
		gf.sha1 != "abcdef" || gf.filetype != "jpg" || gf.filename != "my file name" {
		t.Fatalf("unexpected: %+v", gf)
	}
	if parseGalleryFile("bad") != nil {
		t.Fatal("should reject malformed file line")
	}
}

func TestGalleryLogFailureDedup(t *testing.T) {
	g := &GalleryDownloader{}
	g.logFailure("host", "1", "org")
	g.logFailure("host", "1", "org") // dup
	g.logFailure("host", "2", "org")
	if len(g.failures) != 2 {
		t.Fatalf("expected 2 distinct failures, got %d", len(g.failures))
	}
}

func TestGalleryDownloadDirLowSpace(t *testing.T) {
	s := NewSettings()
	s.SkipFreeSpaceCheck = true
	g := &GalleryDownloader{settings: s}
	if g.downloadDirLowSpace() {
		t.Fatal("skip check → never low space")
	}
}

func TestValidateFileSHA1(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	os.WriteFile(p, []byte("hello"), 0o644)
	if !validateFileSHA1(p, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d") {
		t.Fatal("sha1 mismatch for hello")
	}
	if validateFileSHA1(p, "0000000000000000000000000000000000000000") {
		t.Fatal("wrong hash should not validate")
	}
}
