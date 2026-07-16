package hath

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// --- handleFile validation branches ---

func TestHFileIndexXresInvalid(t *testing.T) {
	_, s, cache, srv := buildTestServer(t)
	f := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-5-jpg")
	writeCacheFile(t, cache, f, []byte("hello"))
	// empty fileindex → 404
	target := "/h/" + f.Fileid() + "/fileindex=;xres=org;keystamp=" +
		strconv.FormatInt(s.ServerTime(), 10) + "-" + keystampHash(s.ServerTime(), f.Fileid(), s.ClientKey) + "/img.jpg"
	resp, _ := http.Get(srv.URL + target)
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("empty fileindex → 404, got %d", resp.StatusCode)
	}
	// invalid xres → 404
	target = "/h/" + f.Fileid() + "/fileindex=1;xres=bad;keystamp=" +
		strconv.FormatInt(s.ServerTime(), 10) + "-" + keystampHash(s.ServerTime(), f.Fileid(), s.ClientKey) + "/img.jpg"
	resp, _ = http.Get(srv.URL + target)
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("bad xres → 404, got %d", resp.StatusCode)
	}
}

func TestHFileidInvalid(t *testing.T) {
	_, s, _, srv := buildTestServer(t)
	// short fileid that fails ParseHVFile → 404 (keystamp still valid)
	target := validHTarget(s, "abc")
	resp, err := http.Get(srv.URL + target)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("unparseable fileid → 404, got %d", resp.StatusCode)
	}
}

// --- serveCached DisableFileVerify branch ---

func TestHServeCachedNoVerify(t *testing.T) {
	_, s, cache, srv := buildTestServer(t)
	s.DisableFileVerify = true
	f := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-5-jpg")
	writeCacheFile(t, cache, f, []byte("world"))
	resp, err := http.Get(srv.URL + validHTarget(s, f.Fileid()))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 with DisableFileVerify, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "world" {
		t.Fatalf("wrong body: %q", body)
	}
}

// --- proxyFile no-source (bad gateway) branch ---

func TestHProxyWrongSize(t *testing.T) {
	_, s, cache, _ := buildTestServer(t)
	m, _, rpc := newMockRPC(t)
	f := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-5-jpg")
	// origin serves WRONG size → proxy cannot pick a source → 502
	wrong := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "999")
		w.Write([]byte("x")) // length mismatch vs declared
	}))
	defer wrong.Close()
	// point the rpc at our mock so we can inject the fetch URL
	hs := NewHTTPServer(s, cache, rpc, NewStats(), &CertManager{settings: s}, nil)
	hs.AllowNormalConnections()
	psrv := httptest.NewServer(http.HandlerFunc(hs.handle))
	defer psrv.Close()
	m.setResponse(ActStaticRangeFetch, "OK\n"+wrong.URL+"/f\n")
	target := validHTarget(s, f.Fileid())
	resp, err := http.Get(psrv.URL + target)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 404 && resp.StatusCode != 502 {
		t.Fatalf("expected 404/502 when no source matches size, got %d", resp.StatusCode)
	}
}

// --- servercmd speed_test default + bad key ---

func TestServercmdSpeedTestDefault(t *testing.T) {
	_, s, _, srv := buildTestServer(t)
	t0 := s.ServerTime()
	cmd := "speed_test"
	key := servercmdKey(cmd, "", s.ClientID, t0, s.ClientKey)
	target := "/servercmd/" + cmd + "//" + strconv.FormatInt(t0, 10) + "/" + key
	resp, err := http.Get(srv.URL + target)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("speed_test command → 200 (empty default), got %d", resp.StatusCode)
	}
}

// --- speedtest malformed branches ---

func TestSpeedtestMalformed(t *testing.T) {
	_, s, _, srv := buildTestServer(t)
	t0 := s.ServerTime()
	// too few segments → 400
	resp, _ := http.Get(srv.URL + "/t/1024/" + strconv.FormatInt(t0, 10))
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("len<5 → 400, got %d", resp.StatusCode)
	}
	// non-numeric size → 400
	key := speedtestKey("zzz", t0, s.ClientID, s.ClientKey)
	resp, _ = http.Get(srv.URL + "/t/zzz/" + strconv.FormatInt(t0, 10) + "/" + key)
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("bad size → 400, got %d", resp.StatusCode)
	}
}

// --- parseAdditional short-kv skip ---

func TestParseAdditionalShortKv(t *testing.T) {
	m := parseAdditional("ab;k=v;=x")
	if _, ok := m["ab"]; ok {
		t.Fatal("len<3 kv should be skipped")
	}
	if m["k"] != "v" {
		t.Fatalf("valid kv lost: %v", m)
	}
	if _, ok := m[""]; ok {
		t.Fatal("empty key should be skipped")
	}
}

// --- runThreadedProxyTest default protocol ---

func TestThreadedProxyTestDefaultProtocol(t *testing.T) {
	hs := &HTTPServer{settings: NewSettings()}
	rec := httptest.NewRecorder()
	// no protocol field → defaults to http; the fetch will fail (bad host) but
	// the default-protocol branch is exercised and OK:<n>-<ms> is still written.
	hs.runThreadedProxyTest(rec, "hostname=badhost.invalid;port=1;testsize=1024;testcount=1;testtime=1;testkey=k")
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}
