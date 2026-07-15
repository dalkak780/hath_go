package hath

import (
	"strings"
	"testing"
	"time"
)

// TestAuthFormulas pins the exact pre-image and output of every authentication
// token against SHA-1 vectors computed independently with shasum(1). If any of
// these break, the client would send malformed RPC payloads → account lockout.
func TestAuthFormulas(t *testing.T) {
	const (
		cid = testClientID
		key = testClientKey
	)
	cases := []struct{ name, got, want string }{
		{"actkey",
			actkey("client_login", "", cid, 1700000000, key),
			"41515df11cefbe0d3012a07782e2d6777f7f650a"},
		{"keystamp",
			keystampHash(1700000500, "abcdef0123456789abcdef0123456789abcdef01-12345-jpg", key),
			"855071598e"},
		{"servercmd",
			servercmdKey("still_alive", "", cid, 1700000000, key),
			"4774887af07e1257ed2c1d03a67acda9f2f86ff7"},
		{"speedtest",
			speedtestKey("1000000", 1700000000, cid, key),
			"6f8659dc2e594965122d1f66d7490ceccbdcdedb"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: got %q want %q", c.name, c.got, c.want)
		}
	}
}

func TestHVFileParse(t *testing.T) {
	simple := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-12345-jpg")
	if simple == nil || simple.Hash != "abcdef0123456789abcdef0123456789abcdef01" ||
		simple.Size != 12345 || simple.Type != "jpg" || simple.StaticRange() != "abcd" ||
		simple.Fileid() != "abcdef0123456789abcdef0123456789abcdef01-12345-jpg" ||
		simple.Mime() != "image/jpeg" {
		t.Fatalf("unexpected simple parse: %+v", simple)
	}
	resized := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-12345-640-480-png")
	if resized == nil || resized.Xres != 640 || resized.Yres != 480 || resized.Type != "png" {
		t.Fatalf("unexpected resized parse: %+v", resized)
	}
	if ParseHVFile("nope") != nil {
		t.Fatal("expected nil for invalid fileid")
	}
}

// --- mock-based RPC action tests ---

func TestServerStatIsUnauthenticated(t *testing.T) {
	m, _, rpc := newMockRPC(t)
	if !rpc.RefreshServerStat() {
		t.Fatal("server_stat should succeed")
	}
	reqs := m.captured()
	if len(reqs) != 1 || reqs[0].Act != ActServerStat {
		t.Fatalf("expected one server_stat request, got %+v", reqs)
	}
	// server_stat carries no cid/acttime/actkey
	if reqs[0].CID != "" || reqs[0].ActTime != "" || reqs[0].ActKey != "" {
		t.Fatalf("server_stat must be unauthenticated: %+v", reqs[0])
	}
	if reqs[0].Build != "178" {
		t.Errorf("clientbuild mismatch: %q", reqs[0].Build)
	}
}

func TestClientLoginAppliesSettings(t *testing.T) {
	m, s, rpc := newMockRPC(t)
	m.setResponse(ActClientLogin, "OK\nport=12345\nthrottle_bytes=1000000\ndisklimit_bytes=5000000000\nstatic_range_count=42\nhost=1.2.3.4\n")
	rpc.LoadClientSettingsFromServer()
	if !rpc.LoginValidated() {
		t.Fatal("login should be validated")
	}
	if s.ClientPort != 12345 || s.ThrottleBytes != 1000000 || s.DiskLimit != 5000000000 {
		t.Fatalf("settings not applied: port=%d throttle=%d", s.ClientPort, s.ThrottleBytes)
	}
}

func TestClientLoginAuthFailureDies(t *testing.T) {
	m, _, rpc := newMockRPC(t)
	m.setResponse(ActClientLogin, "FAIL_AUTH\n")
	old := fatalError
	defer func() { fatalError = old }()
	fatalError = func(msg string) { panic(msg) }
	done := make(chan struct{})
	go func() {
		defer func() { recover(); close(done) }()
		rpc.LoadClientSettingsFromServer()
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("login loop did not terminate on auth failure")
	}
	if rpc.LoginValidated() {
		t.Fatal("login must not validate on FAIL_AUTH")
	}
	_ = m
}

func TestRefreshServerSettings(t *testing.T) {
	m, s, rpc := newMockRPC(t)
	m.setResponse(ActClientSettings, "OK\nthrottle_bytes=2000000\n")
	if !rpc.RefreshServerSettings() {
		t.Fatal("refresh should succeed")
	}
	if s.ThrottleBytes != 2000000 {
		t.Fatalf("throttle not applied: %d", s.ThrottleBytes)
	}
}

func TestNotifyStartOK(t *testing.T) {
	m, _, rpc := newMockRPC(t)
	m.setResponse(ActClientStart, "OK\n")
	if !rpc.NotifyStart() {
		t.Fatal("notifyStart should succeed on OK")
	}
}

func TestNotifyStartConnectTestFail(t *testing.T) {
	m, _, rpc := newMockRPC(t)
	m.setResponse(ActClientStart, "FAIL_CONNECT_TEST\n")
	if rpc.NotifyStart() {
		t.Fatal("notifyStart should fail on FAIL_CONNECT_TEST")
	}
}

func TestSimpleNotifications(t *testing.T) {
	m, _, rpc := newMockRPC(t)
	for _, act := range []string{ActClientSuspend, ActClientResume, ActClientStop} {
		m.setResponse(act, "OK\n")
	}
	if !rpc.NotifySuspend() || !rpc.NotifyResume() || !rpc.NotifyStop() {
		t.Fatal("simple notifications should succeed")
	}
}

func TestStillAlive(t *testing.T) {
	m, _, rpc := newMockRPC(t)
	if !rpc.StillAlive(false) {
		t.Fatal("stillAlive should succeed")
	}
	m.setResponse(ActStillAlive, "SOME_FAIL\n")
	if rpc.StillAlive(false) {
		t.Fatal("stillAlive should fail on FAIL")
	}
}

func TestGetBlacklist(t *testing.T) {
	m, _, rpc := newMockRPC(t)
	m.setResponse(ActGetBlacklist, "OK\nabc-100-jpg\ndef-200-png\n")
	bl := rpc.GetBlacklist(100)
	if len(bl) != 2 || bl[0] != "abc-100-jpg" {
		t.Fatalf("unexpected blacklist: %v", bl)
	}
}

func TestStaticRangeFetchURL(t *testing.T) {
	m, _, rpc := newMockRPC(t)
	m.setResponse(ActStaticRangeFetch, "OK\nhttp://node1/h/x\nhttp://node2/h/y\n")
	urls := rpc.GetStaticRangeFetchURL("5", "org", "abcdef-100-jpg")
	if len(urls) != 2 || urls[0] != "http://node1/h/x" {
		t.Fatalf("unexpected urls: %v", urls)
	}
	// verify the add field carried fileindex;xres;fileid
	reqs := m.captured()
	if !strings.Contains(reqs[0].Add, "5;org;abcdef-100-jpg") {
		t.Fatalf("srfetch add mismatch: %q", reqs[0].Add)
	}
}

func TestDownloaderFetchURL(t *testing.T) {
	m, _, rpc := newMockRPC(t)
	m.setResponse(ActDownloaderFetch, "OK\nhttp://img/file\n")
	u := rpc.GetDownloaderFetchURL(99, 3, 7, "org", 1)
	if u != "http://img/file" {
		t.Fatalf("unexpected dl url: %q", u)
	}
}

func TestReportDownloaderFailures(t *testing.T) {
	m, _, rpc := newMockRPC(t)
	m.setResponse(ActDownloaderFailRep, "OK\n")
	rpc.ReportDownloaderFailures(nil)         // no-op
	rpc.ReportDownloaderFailures(make([]string, 60)) // too many → no-op
	rpc.ReportDownloaderFailures([]string{"a", "b", "c"})
	reqs := m.captured()
	if len(reqs) != 1 || !strings.Contains(reqs[0].Add, "a;b;c") {
		t.Fatalf("dlfails should be reported once with joined adds: %+v", reqs)
	}
}

func TestOverloadThrottle(t *testing.T) {
	m, _, rpc := newMockRPC(t)
	m.setResponse(ActOverload, "OK\n")
	if !rpc.NotifyOverload() {
		t.Fatal("first overload should be sent")
	}
	if rpc.NotifyOverload() {
		t.Fatal("second overload within 30s must be suppressed")
	}
}

func TestKeyExpiredRetry(t *testing.T) {
	m, _, rpc := newMockRPC(t)
	m.setResponse(ActClientSettings, "OK\nthrottle_bytes=3000000\n")
	m.keyExpired = true
	if !rpc.RefreshServerSettings() {
		t.Fatal("should recover via KEY_EXPIRED retry")
	}
	reqs := m.captured()
	// expect: one authed settings call (KEY_EXPIRED), one server_stat refresh,
	// one authed retry (OK).
	authed := 0
	for _, r := range reqs {
		if r.Act == ActClientSettings {
			authed++
		}
	}
	if authed != 2 {
		t.Fatalf("expected 2 settings calls (initial + retry), got %d", authed)
	}
}

func TestFetchQueueEndpoint(t *testing.T) {
	m, s, rpc := newMockRPC(t)
	m.setResponse("fetchqueue", "OK\nGID 1\n") // act registered under fetchqueue
	// the mock validates actkey for act="fetchqueue"
	body := rpc.FetchQueue("1;org")
	if body == "" || !strings.HasPrefix(body, "OK") {
		t.Fatalf("fetchqueue body: %q", body)
	}
	reqs := m.captured()
	if reqs[0].Act != "fetchqueue" || reqs[0].Path != "/15/dl" {
		t.Fatalf("fetchqueue must hit /15/dl: %+v", reqs[0])
	}
	_ = s
}
