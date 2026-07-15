package hath

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Test credentials (same as the pinned SHA-1 vectors in rpc_test.go).
const (
	testClientID  = 1234
	testClientKey = "abcdefghijklmnopqrst"
)

// capturedReq records one inbound RPC request the mock observed.
type capturedReq struct {
	Act     string
	Add     string
	CID     string
	ActTime string
	ActKey  string
	Build   string
	Path    string
	RawQ    string
}

// mockRPC is an httptest-based stand-in for the H@H RPC server. It validates
// every authenticated request by recomputing the expected actkey from the
// request's own params — so a test fails loudly if the Go client builds the
// URL or signature wrong (the exact failure mode that locks accounts).
type mockRPC struct {
	srv *httptest.Server

	mu          sync.Mutex
	requests    []capturedReq
	responses   map[string]string // act -> full response body (incl. leading line)
	statResp    string
	keyExpired  bool // return KEY_EXPIRED once on next authed call
	certBytes   []byte
	certPath    string // URL path treated as cert
	failStat    bool
	closed      bool
}

func newMockRPC(t *testing.T) (*mockRPC, *Settings, *ServerHandler) {
	t.Helper()
	m := &mockRPC{
		responses: map[string]string{},
		statResp:  "OK\nmin_client_build=1\nrpc_path=15/rpc?\n",
	}
	m.srv = httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.close)

	// Wire a Settings that points the client at the test server.
	s := NewSettings()
	s.ClientID = testClientID
	s.ClientKey = testClientKey
	u, _ := url.Parse(m.srv.URL)
	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)
	s.RPCPath = "15/rpc?"
	s.RPCServerPort = port
	s.mu.Lock()
	s.rpcServers = []net.IP{net.ParseIP(host)}
	s.rpcServerCurrent = host
	s.mu.Unlock()
	// keep stat pointing back at the test server so re-applied settings stick
	m.statResp = "OK\nmin_client_build=1\nrpc_path=15/rpc?\nrpc_server_ip=" + host + "\nrpc_server_port=" + portStr + "\nserver_time=1700000000\n"

	stats := NewStats()
	rpc := NewServerHandler(s, stats)
	return m, s, rpc
}

func (m *mockRPC) close() {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	m.srv.Close()
}

func (m *mockRPC) handle(w http.ResponseWriter, r *http.Request) {
	q := strictQuery(r.URL.RawQuery)
	act := q["act"]
	m.mu.Lock()
	m.requests = append(m.requests, capturedReq{
		Act: act, Add: q["add"], CID: q["cid"],
		ActTime: q["acttime"], ActKey: q["actkey"],
		Build: q["clientbuild"], Path: r.URL.Path, RawQ: r.URL.RawQuery,
	})
	keyExpired := m.keyExpired
	if keyExpired {
		m.keyExpired = false
	}
	m.mu.Unlock()

	switch act {
	case ActServerStat:
		if m.failStat {
			w.WriteHeader(500)
			return
		}
		io.WriteString(w, m.statResp)
		return
	case ActGetCertificate:
		// cert is fetched as a binary file; emit configured bytes
		w.Header().Set("Content-Length", strconv.Itoa(len(m.certBytes)))
		w.Write(m.certBytes)
		return
	}

	// Authenticated action: verify the actkey matches an independent recompute.
	add := q["add"]
	cid, _ := strconv.Atoi(q["cid"])
	acttime, _ := strconv.ParseInt(q["acttime"], 10, 64)
	sentKey := q["actkey"]
	if keyExpired {
		io.WriteString(w, "KEY_EXPIRED\n")
		return
	}
	expected := actkey(act, add, cid, acttime, testClientKey)
	if sentKey != expected {
		// A real server would start locking the account here.
		io.WriteString(w, "FAIL_BAD_ACTKEY\n")
		return
	}

	m.mu.Lock()
	resp, ok := m.responses[act]
	m.mu.Unlock()
	if !ok {
		resp = "OK\n"
	}
	io.WriteString(w, resp)
}

// strictQuery parses a URL raw query splitting ONLY on '&', preserving ';'
// inside values. This matches how the H@H server (Java servlet) parses the
// query — ';' is a literal character within the add= field, not a separator.
// (Go's url.ParseQuery wrongly splits on ';' too, so we don't use it here.)
func strictQuery(rawq string) map[string]string {
	out := map[string]string{}
	for _, pair := range strings.Split(rawq, "&") {
		k, v, _ := strings.Cut(pair, "=")
		out[k] = v
	}
	return out
}
func (m *mockRPC) captured() []capturedReq {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]capturedReq, len(m.requests))
	copy(out, m.requests)
	return out
}

// setResponse configures the body returned for an authenticated act.
func (m *mockRPC) setResponse(act, body string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responses[act] = body
}
