package hath

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeRT is a RoundTripper returning a crafted response, so we can drive the
// exact error branches in fetch/fetchFile/DownloadToFile without a real server.
type fakeRT struct {
	resp *http.Response
	err  error
}

func (f fakeRT) RoundTrip(*http.Request) (*http.Response, error) { return f.resp, f.err }

func newRPCWithRT(rt http.RoundTripper) *ServerHandler {
	s := NewSettings()
	s.ClientID = testClientID
	s.ClientKey = testClientKey
	s.MaxAllowedFile = 1 << 30
	return &ServerHandler{settings: s, stats: NewStats(), client: &http.Client{Transport: rt}}
}

func bodyResp(code int, clen int64, body string) *http.Response {
	return &http.Response{
		StatusCode:    code,
		Status:        http.StatusText(code),
		ContentLength: clen,
		Body:          io.NopCloser(strings.NewReader(body)),
		Header:        http.Header{},
	}
}

// --- fetch error branches ---

func TestFetchBadURL(t *testing.T) {
	h := newRPCWithRT(fakeRT{resp: bodyResp(200, 2, "OK")})
	// NewRequestWithContext fails on a malformed URL
	if _, _, err := h.fetch("://not-a-url", time.Second); err == nil {
		t.Fatal("expected error for malformed URL")
	}
}

func TestFetchShortReadV2(t *testing.T) {
	h := newRPCWithRT(fakeRT{resp: bodyResp(200, 100, "tooshort")})
	if _, _, err := h.fetch("http://example/x", time.Second); err == nil {
		t.Fatal("expected short-read error")
	}
}

// --- fetchFile error branches ---

func TestFetchFileStatusAndLimits(t *testing.T) {
	// status code not 2xx
	h := newRPCWithRT(fakeRT{resp: bodyResp(500, 2, "x")})
	if err := h.fetchFile("http://e/f", t.TempDir()+"/c.p12", time.Second); err == nil {
		t.Fatal("expected status error")
	}
	// missing Content-Length
	h = newRPCWithRT(fakeRT{resp: bodyResp(200, 0, "x")})
	if err := h.fetchFile("http://e/f", t.TempDir()+"/c.p12", time.Second); err == nil {
		t.Fatal("expected missing Content-Length error")
	}
	// exceeds MaxAllowedFile
	s := NewSettings()
	s.ClientID = testClientID
	s.ClientKey = testClientKey
	s.MaxAllowedFile = 10
	h = &ServerHandler{settings: s, stats: NewStats(), client: &http.Client{Transport: fakeRT{resp: bodyResp(200, 100, strings.Repeat("y", 100))}}}
	if err := h.fetchFile("http://e/f", t.TempDir()+"/c.p12", time.Second); err == nil {
		t.Fatal("expected max-filesize error")
	}
}

func TestFetchFileCopyError(t *testing.T) {
	// body that errors mid-read
	body := &errBody{}
	h := newRPCWithRT(fakeRT{resp: &http.Response{
		StatusCode: 200, ContentLength: 50, Body: body, Header: http.Header{},
	}})
	if err := h.fetchFile("http://e/f", t.TempDir()+"/c.p12", time.Second); err == nil {
		t.Fatal("expected io.Copy error")
	}
}

func TestFetchFileShortAndCreateError(t *testing.T) {
	// short file read
	h := newRPCWithRT(fakeRT{resp: bodyResp(200, 100, "tenbytes!!")})
	if err := h.fetchFile("http://e/f", t.TempDir()+"/c.p12", time.Second); err == nil {
		t.Fatal("expected short file-read error")
	}
	// os.Create(tmp) fails: dest dir does not exist
	h = newRPCWithRT(fakeRT{resp: bodyResp(200, 3, "abc")})
	badDest := filepath.Join(t.TempDir(), "no-such-dir", "c.p12")
	if err := h.fetchFile("http://e/f", badDest, time.Second); err == nil {
		t.Fatal("expected create-temp error")
	}
}

type errBody struct{ n int }

func (e *errBody) Read(p []byte) (int, error) {
	if e.n >= 5 {
		return 0, io.ErrClosedPipe
	}
	e.n++
	p[0] = 'x'
	return 1, nil
}
func (errBody) Close() error { return nil }

// --- callURL empty-body branch ---

func TestCallURLEmptyBody(t *testing.T) {
	h := newRPCWithRT(fakeRT{resp: bodyResp(200, 0, "")})
	sr := h.callURL("http://e/x", "")
	if sr.Status != RespNull {
		t.Fatalf("empty body → RespNull, got %v", sr.Status)
	}
}

// --- action-method null/fail + fatal branches ---

func TestRefreshServerStatFail(t *testing.T) {
	m, _, rpc := newMockRPC(t)
	m.statResp = "FAIL\n" // stat not OK
	if rpc.RefreshServerStat() {
		t.Fatal("stat FAIL → false")
	}
}

func TestLoadClientSettingsStatFails(t *testing.T) {
	m, _, rpc := newMockRPC(t)
	m.statResp = "FAIL\n" // RefreshServerStat false → dieErr
	old := fatalError
	called := false
	fatalError = func(string) { called = true; panic("statfail") }
	defer func() { fatalError = old }()
	defer func() { recover() }()
	rpc.LoadClientSettingsFromServer()
	if !called {
		t.Fatal("expected dieErr on stat failure")
	}
}

func TestLoadClientSettingsLoginNull(t *testing.T) {
	m, _, rpc := newMockRPC(t)
	m.statResp = "OK\nmin_client_build=1\nrpc_path=15/rpc?\n"
	m.setResponse(ActClientLogin, "TEMPORARILY_UNAVAILABLE\n") // RespNull
	old := fatalError
	called := false
	fatalError = func(string) { called = true; panic("loginnull") }
	defer func() { fatalError = old }()
	defer func() { recover() }()
	rpc.LoadClientSettingsFromServer()
	if !called {
		t.Fatal("expected dieErr on null login")
	}
}

func TestRefreshServerSettingsFail(t *testing.T) {
	m, _, rpc := newMockRPC(t)
	m.setResponse(ActClientSettings, "FAIL\n")
	if rpc.RefreshServerSettings() {
		t.Fatal("settings FAIL → false")
	}
}

func TestNotifyStartFatalCodes(t *testing.T) {
	for _, code := range []string{"FAIL_OTHER_CLIENT_CONNECTED", "FAIL_CID_IN_USE"} {
		m, _, rpc := newMockRPC(t)
		m.setResponse(ActClientStart, code+"\n")
		old := fatalError
		called := false
		fatalError = func(string) { called = true; panic(code) }
		func() {
			defer func() { fatalError = old }()
			defer func() { recover() }()
			rpc.NotifyStart()
		}()
		if !called {
			t.Fatalf("expected dieErr for %s", code)
		}
	}
}

func TestStillAliveNullAndTerm(t *testing.T) {
	m, _, rpc := newMockRPC(t)
	m.setResponse(ActStillAlive, "TEMPORARILY_UNAVAILABLE\n") // RespNull
	if rpc.StillAlive(false) {
		t.Fatal("null → false")
	}
	m.setResponse(ActStillAlive, "TERM_BAD_NETWORK\n") // RespFail → dieErr (matches Java wire format)
	old := fatalError
	called := false
	fatalError = func(string) { called = true; panic("term") }
	func() {
		defer func() { fatalError = old }()
		defer func() { recover() }()
		rpc.StillAlive(false)
	}()
	if !called {
		t.Fatal("expected dieErr for TERM_BAD_NETWORK")
	}
}

func TestFetchQueueError(t *testing.T) {
	h := newRPCWithRT(fakeRT{err: io.ErrUnexpectedEOF}) // fetch fails
	if h.FetchQueue("") != "" {
		t.Fatal("fetch error → empty queue")
	}
}

// --- DownloadToFile error branches ---

func TestDownloadToFileErrors(t *testing.T) {
	// NewRequestWithContext error (bad url)
	h := newRPCWithRT(fakeRT{resp: bodyResp(200, 2, "x")})
	if _, err := h.DownloadToFile("://bad", t.TempDir()+"/o", time.Second, false, false, nil, ""); err == nil {
		t.Fatal("expected bad-url error")
	}
	// status code not 2xx
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", 404)
	}))
	defer srv.Close()
	h = newRPCWithRT(fakeRT{resp: bodyResp(200, 2, "x")})
	if _, err := h.DownloadToFile(srv.URL+"/o", t.TempDir()+"/o", time.Second, false, false, nil, ""); err == nil {
		t.Fatal("expected status error")
	}
	// exceeds MaxAllowedFile
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.Write([]byte(strings.Repeat("z", 100)))
	}))
	defer big.Close()
	s := NewSettings()
	s.ClientID = testClientID
	s.ClientKey = testClientKey
	s.MaxAllowedFile = 10
	h = &ServerHandler{settings: s, stats: NewStats(), client: &http.Client{Transport: fakeRT{resp: bodyResp(200, 2, "x")}}}
	if _, err := h.DownloadToFile(big.URL+"/o", t.TempDir()+"/o", time.Second, false, false, nil, ""); err == nil {
		t.Fatal("expected max-filesize error")
	}
	// short read
	shortSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.Write([]byte("tinyshort"))
	}))
	defer shortSrv.Close()
	h = newRPCWithRT(fakeRT{resp: bodyResp(200, 2, "x")})
	if _, err := h.DownloadToFile(shortSrv.URL+"/o", t.TempDir()+"/o", time.Second, false, false, nil, ""); err == nil {
		t.Fatal("expected short-read error")
	}
}

func TestDownloadToFileLimiter(t *testing.T) {
	// limiter != nil branch: succeed with a limiter via a real origin server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "3")
		w.Write([]byte("abc"))
	}))
	defer srv.Close()
	h := newRPCWithRT(fakeRT{resp: bodyResp(200, 2, "x")})
	lim := NewBandwidthMonitor(1 << 30)
	dest := t.TempDir() + "/ok"
	if _, err := h.DownloadToFile(srv.URL+"/o", dest, time.Second, false, false, lim, ""); err != nil {
		t.Fatalf("limiter path should succeed: %v", err)
	}
	if _, err := os.Stat(dest); err != nil {
		t.Fatal("file should have been written")
	}
}
