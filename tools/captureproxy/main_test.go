package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

// TestCaptureProxyForwardsAndLogs: a request through the proxy reaches the
// origin (client gets the real response) AND a JSON record is written.
func TestCaptureProxyForwardsAndLogs(t *testing.T) {
	// origin serves a known body with Content-Length
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Origin", "yes")
		body := "OK\nserver_time=1700000000\nhost=1.2.3.4\n"
		w.Header().Set("Content-Length", itoa(len(body)))
		io.WriteString(w, body)
	}))
	defer origin.Close()

	var logBuf bytes.Buffer
	proxy := httptest.NewServer(newCaptureHandler(&logBuf, "", nil))
	defer proxy.Close()

	// issue a request THROUGH the proxy (absolute URI form)
	target := strings.Replace(origin.URL, "127.0.0.1", "localhost", 1) + "/15/rpc?clientbuild=178&act=server_stat"
	req, _ := http.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("User-Agent", "Hentai@Home 1.6.5")
	// tell http.Client to use our proxy
	client := &http.Client{Transport: &http.Transport{Proxy: func(*http.Request) (*url.URL, error) {
		return url.Parse(proxy.URL)
	}}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// client must receive the REAL response (forwarding works)
	if resp.StatusCode != 200 || resp.Header.Get("X-Origin") != "yes" {
		t.Fatalf("proxy did not forward origin response: status=%d hdr=%q", resp.StatusCode, resp.Header.Get("X-Origin"))
	}
	b, _ := io.ReadAll(resp.Body)
	if !strings.HasPrefix(string(b), "OK\nserver_time=1700000000") {
		t.Fatalf("client got wrong body: %q", b)
	}

	// exactly one JSON record must be logged, capturing the request + response
	dec := json.NewDecoder(&logBuf)
	var rec record
	if err := dec.Decode(&rec); err != nil {
		t.Fatalf("no record logged: %v", err)
	}
	if rec.Method != "GET" || !strings.Contains(rec.URL, "act=server_stat") {
		t.Fatalf("bad record url/method: %+v", rec)
	}
	if rec.Status != 200 || !strings.Contains(rec.RespBody, "server_time=1700000000") {
		t.Fatalf("bad record response: status=%d body=%q", rec.Status, rec.RespBody)
	}
	if dec.More() {
		t.Fatal("expected exactly one record")
	}
}

// TestCaptureProxyHostFilterSkipsLogging: a non-matching host is still forwarded
// but not logged.
func TestCaptureProxyHostFilterSkipsLogging(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello")
	}))
	defer origin.Close()

	var logBuf bytes.Buffer
	proxy := httptest.NewServer(newCaptureHandler(&logBuf, "rpc.hentaiathome.net", nil))
	defer proxy.Close()

	client := &http.Client{Transport: &http.Transport{Proxy: func(*http.Request) (*url.URL, error) {
		return url.Parse(proxy.URL)
	}}}
	resp, err := client.Get(origin.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "hello" {
		t.Fatalf("forwarding broken under filter: %q", b)
	}
	if logBuf.Len() != 0 {
		t.Fatalf("non-matching host should not be logged, got: %s", logBuf.String())
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// ensure os import is used (kept for parity with potential future flags)
var _ = os.O_CREATE
