package hath

import (
	"bytes"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCachePruneMissingRangeDir(t *testing.T) {
	ch, s := buildCache(t)
	s.DiskLimit = 1
	// need at least one cached file so the prune guard (cacheCount<1) is cleared
	f := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-5-jpg")
	src := filepath.Join(ch.settings.TempDir, "src")
	os.WriteFile(src, []byte("hello"), 0o644)
	ch.ImportFileToCache(src, f)
	// register a static range whose directory does not exist, older than the real one
	ch.mu.Lock()
	ch.staticRangeOldest["9999"] = time.Now().Add(-500 * 24 * time.Hour).UnixMilli()
	ch.mu.Unlock()
	ch.CheckAndPruneCache()
	ch.mu.Lock()
	_, has := ch.staticRangeOldest["9999"]
	ch.mu.Unlock()
	if has {
		t.Fatal("missing range dir should be removed from staticRangeOldest")
	}
}

func TestTrackedConnThrottleWrite(t *testing.T) {
	s := NewSettings()
	s.ThrottleBytes = 1 << 20
	hs := &HTTPServer{settings: s, bwm: NewBandwidthMonitor(s.ThrottleBytes)}
	// a non-local, non-rpc connection → throttle=true
	tc := &trackedConn{Conn: &bufConn{}, server: hs, throttle: true}
	n, err := tc.Write([]byte("payload"))
	if err != nil || n != 7 {
		t.Fatalf("throttled write failed: n=%d err=%v", n, err)
	}
}

func TestGalleryDownloadDirLowSpaceTrue(t *testing.T) {
	s := NewSettings()
	s.SkipFreeSpaceCheck = false
	s.DiskMinRemaining = 1 << 40 // absurdly high → low space
	g := &GalleryDownloader{settings: s}
	if !g.downloadDirLowSpace() {
		t.Fatal("should report low space with huge DiskMinRemaining")
	}
}

func TestServercmdMalformedSegments(t *testing.T) {
	_, _, _, srv := buildTestServer(t)
	// /servercmd with too few segments → 403 (from authorized IP it's still
	// malformed). Request originates from 127.0.0.1 which is a seeded RPC server.
	resp, err := http.Get(srv.URL + "/servercmd/x")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403 for malformed servercmd, got %d", resp.StatusCode)
	}
}

// bufConn is a minimal in-memory net.Conn for trackedConn tests.
type bufConn struct{ buf bytes.Buffer }

func (c *bufConn) Read(p []byte) (int, error)         { return c.buf.Read(p) }
func (c *bufConn) Write(p []byte) (int, error)        { return c.buf.Write(p) }
func (c *bufConn) Close() error                        { return nil }
func (c *bufConn) LocalAddr() net.Addr                   { return addr{} }
func (c *bufConn) RemoteAddr() net.Addr                  { return addr{} }
func (c *bufConn) SetDeadline(time.Time) error         { return nil }
func (c *bufConn) SetReadDeadline(time.Time) error     { return nil }
func (c *bufConn) SetWriteDeadline(time.Time) error    { return nil }

type addr struct{}

func (addr) Network() string { return "buf" }
func (addr) String() string  { return "buf" }
