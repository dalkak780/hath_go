package hath

import (
	"crypto/sha1"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// TestExternalJavaCacheFixture is packaged as a standalone test binary for
// validating a copied Java cache. It never mutates HATH_JAVA_CACHE_FIXTURE.
func TestExternalJavaCacheFixture(t *testing.T) {
	source := os.Getenv("HATH_JAVA_CACHE_FIXTURE")
	if source == "" {
		t.Skip("set HATH_JAVA_CACHE_FIXTURE to a copied Java cache")
	}
	source, err := filepath.Abs(source)
	if err != nil {
		t.Fatal(err)
	}
	type sample struct {
		source string
		file   *HVFile
		info   fs.FileInfo
	}
	var samples []sample
	err = filepath.WalkDir(source, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		f := ParseHVFile(d.Name())
		if f == nil {
			return nil
		}
		rel, err := filepath.Rel(source, path)
		if err != nil || rel != filepath.Join(f.Hash[:2], f.Hash[2:4], f.Fileid()) {
			return fmt.Errorf("invalid Java cache layout: %s", path)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Size() != f.Size {
			return fmt.Errorf("size mismatch: %s got=%d want=%d", path, info.Size(), f.Size)
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		h := sha1.New()
		_, copyErr := io.Copy(h, in)
		closeErr := in.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if fmt.Sprintf("%x", h.Sum(nil)) != f.Hash {
			return fmt.Errorf("SHA-1 mismatch: %s", path)
		}
		samples = append(samples, sample{path, f, info})
		if len(samples) == 20 {
			return fs.SkipAll
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) < 3 {
		t.Fatalf("need at least 3 valid files, found %d", len(samples))
	}

	work, err := os.MkdirTemp(filepath.Dir(source), "hath-java-cache-audit-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(work)
	cacheDir := filepath.Join(work, "cache")
	dataDir := filepath.Join(work, "data")
	for _, s := range samples {
		dst := filepath.Join(cacheDir, s.file.Hash[:2], s.file.Hash[2:4], s.file.Fileid())
		if err := os.MkdirAll(filepath.Dir(dst), 0o777); err != nil {
			t.Fatal(err)
		}
		if err := copyFile(s.source, dst); err != nil {
			t.Fatal(err)
		}
		_ = os.Chtimes(dst, s.info.ModTime(), s.info.ModTime())
	}

	newCache := func() *CacheHandler {
		s := NewSettings()
		s.CacheDir, s.DataDir, s.TempDir = cacheDir, dataDir, filepath.Join(work, "tmp")
		s.DownloadDir = filepath.Join(work, "download")
		s.SkipFreeSpaceCheck = true
		s.StaticRanges = make(map[string]bool)
		for _, sample := range samples {
			s.StaticRanges[sample.file.StaticRange()] = true
		}
		s.StaticRangeCount = len(s.StaticRanges)
		c := NewHathClient(s, NewStats())
		ch, err := NewCacheHandler(c)
		if err != nil {
			t.Fatal(err)
		}
		ch.pruner.stop()
		return ch
	}

	first := newCache()
	if got := first.CacheCount(); got != int64(len(samples)) {
		t.Fatalf("startup count=%d want=%d", got, len(samples))
	}
	first.TerminateCache() // create a deliberately stale snapshot
	removed := first.LocalPath(samples[0].file)
	if err := os.Remove(removed); err != nil {
		t.Fatal(err)
	}
	second := newCache() // crash/restart must trust the filesystem, not snapshot
	if got := second.CacheCount(); got != int64(len(samples)-1) {
		t.Fatalf("restart after deletion count=%d want=%d", got, len(samples)-1)
	}
	if err := copyFile(samples[0].source, removed); err != nil {
		t.Fatal(err)
	}
	third := newCache()
	if got := third.CacheCount(); got != int64(len(samples)) {
		t.Fatalf("restart after addition count=%d want=%d", got, len(samples))
	}
	t.Logf("PASS source=%s files=%d startup=%d after_delete=%d after_restore=%d", source, len(samples), first.CacheCount(), second.CacheCount(), third.CacheCount())
}
