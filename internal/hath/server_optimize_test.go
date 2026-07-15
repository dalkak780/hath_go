package hath

import (
	"io"
	"net/http"
	"testing"
	"time"
)

// TestHCachedServeRange: Caddy-style partial content. A Range request must
// return 206 with only the requested bytes (zero-copy sendfile still applies).
func TestHCachedServeRange(t *testing.T) {
	_, s, cache, srv := buildTestServer(t)
	f := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-5-jpg")
	writeCacheFile(t, cache, f, []byte("hello"))
	req, _ := http.NewRequest(http.MethodGet, srv.URL+validHTarget(s, f.Fileid()), nil)
	req.Header.Set("Range", "bytes=0-2")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("expected 206, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Content-Range") != "bytes 0-2/5" {
		t.Fatalf("wrong Content-Range: %q", resp.Header.Get("Content-Range"))
	}
	if resp.Header.Get("Accept-Ranges") != "bytes" {
		t.Fatalf("expected Accept-Ranges: bytes, got %q", resp.Header.Get("Accept-Ranges"))
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hel" {
		t.Fatalf("wrong range body: %q", body)
	}
}

// TestHCachedServeNotModified: conditional GET returns 304 with no body.
func TestHCachedServeNotModified(t *testing.T) {
	_, s, cache, srv := buildTestServer(t)
	f := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-5-jpg")
	writeCacheFile(t, cache, f, []byte("hello"))
	req, _ := http.NewRequest(http.MethodGet, srv.URL+validHTarget(s, f.Fileid()), nil)
	// a future date is guaranteed >= the file's Last-Modified
	req.Header.Set("If-Modified-Since", time.Now().Add(time.Hour).UTC().Format(http.TimeFormat))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("expected 304, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Fatalf("304 must have empty body, got %d bytes", len(body))
	}
}

// TestHCachedServeHead: HEAD returns headers incl. Content-Length but no body.
func TestHCachedServeHead(t *testing.T) {
	_, s, cache, srv := buildTestServer(t)
	f := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-5-jpg")
	writeCacheFile(t, cache, f, []byte("hello"))
	req, _ := http.NewRequest(http.MethodHead, srv.URL+validHTarget(s, f.Fileid()), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Content-Length") != "5" {
		t.Fatalf("expected Content-Length 5, got %q", resp.Header.Get("Content-Length"))
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Fatalf("HEAD must have empty body, got %d bytes", len(body))
	}
}

// TestHCachedServeFullGetUnchanged: a plain GET still returns the identical
// full body and headers as before the optimization.
func TestHCachedServeFullGetUnchanged(t *testing.T) {
	_, s, cache, srv := buildTestServer(t)
	f := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-5-jpg")
	writeCacheFile(t, cache, f, []byte("hello"))
	resp, err := http.Get(srv.URL + validHTarget(s, f.Fileid()))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Content-Type") != "image/jpeg" {
		t.Fatalf("wrong content-type: %q", resp.Header.Get("Content-Type"))
	}
	if resp.Header.Get("Cache-Control") != "public, max-age=31536000" {
		t.Fatalf("wrong cache-control: %q", resp.Header.Get("Cache-Control"))
	}
	if resp.Header.Get("Content-Length") != "5" {
		t.Fatalf("expected Content-Length 5, got %q", resp.Header.Get("Content-Length"))
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello" {
		t.Fatalf("wrong body: %q", body)
	}
}


