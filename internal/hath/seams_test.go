package hath

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestWatchSignalsCancelsOnSignal(t *testing.T) {
	sigCh := make(chan os.Signal, 1)
	ctx, cancel := watchSignals(sigCh, context.Background())
	defer cancel()
	sigCh <- os.Signal(nil) // any receive triggers cancel
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("watchSignals should cancel on sigCh receive")
	}
}

func TestWatchSignalsCancelsOnParentCancel(t *testing.T) {
	sigCh := make(chan os.Signal, 1)
	parent, pcancel := context.WithCancel(context.Background())
	ctx, cancel := watchSignals(sigCh, parent)
	defer cancel()
	pcancel()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("watchSignals should cancel when parent cancels")
	}
}

func TestStartBindFailure(t *testing.T) {
	// an invalid port cannot bind → Start returns immediately with an error
	s := NewSettings()
	s.ClientPort = -1
	hs := &HTTPServer{settings: s, cert: &CertManager{settings: s}}
	if err := hs.Start(); err == nil {
		t.Fatal("expected bind error for invalid port")
	}
}

func TestUnexpectedListenerDeathIsReported(t *testing.T) {
	leaf, key := genCert(t)
	s := NewSettings()
	s.ClientPort = 0
	hs := &HTTPServer{
		settings: s,
		cert:     &CertManager{settings: s, cert: tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key}},
		flood:    make(map[string]*floodEntry),
	}
	if err := hs.Start(); err != nil {
		t.Fatal(err)
	}
	if err := hs.listener.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-hs.Done():
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("unexpected termination not reported: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("listener death was not reported")
	}
}

func TestAdmitMaxConnectionsExceeded(t *testing.T) {
	s := NewSettings()
	s.OverrideConns = 2 // tiny limit
	hs := &HTTPServer{settings: s, flood: map[string]*floodEntry{}}
	hs.AllowNormalConnections()
	hs.openConns.Store(5) // already over limit
	c := &fakeConn{remote: "8.8.8.8:1"}
	if hs.admit(c) {
		t.Fatal("should reject when open connections exceed max")
	}
}

func TestAdmitFloodRejectsBlockedIP(t *testing.T) {
	s := NewSettings()
	s.OverrideConns = 1000
	hs := &HTTPServer{settings: s, flood: map[string]*floodEntry{}}
	hs.AllowNormalConnections()
	hs.flood["9.9.9.9"] = &floodEntry{blockedUntil: time.Now().Add(time.Minute)}
	c := &fakeConn{remote: "9.9.9.9:1"}
	if hs.admit(c) {
		t.Fatal("should reject a flood-blocked IP")
	}
}

func TestPruneFloodControlRemovesStale(t *testing.T) {
	hs := &HTTPServer{settings: NewSettings(), flood: map[string]*floodEntry{}}
	hs.flood["1.1.1.1"] = &floodEntry{last: time.Now().Add(-2 * time.Minute)}
	hs.PruneFloodControl()
	if _, ok := hs.flood["1.1.1.1"]; ok {
		t.Fatal("stale flood entry should be pruned")
	}
}

func TestServerHandleSpeedtestHead(t *testing.T) {
	// HEAD on /t returns headers without body
	_, s, _, srv := buildTestServer(t)
	t0 := s.ServerTime()
	size := "256"
	key := speedtestKey(size, t0, s.ClientID, s.ClientKey)
	req, _ := http.NewRequest(http.MethodHead, srv.URL+"/t/"+size+"/"+strconv.FormatInt(t0, 10)+"/"+key, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestHCachedHeadRequest(t *testing.T) {
	_, s, cache, srv := buildTestServer(t)
	f := ParseHVFile("abcdef0123456789abcdef0123456789abcdef01-5-jpg")
	writeCacheFile(t, cache, f, []byte("hello"))
	req, _ := http.NewRequest(http.MethodHead, srv.URL+validHTarget(s, f.Fileid()), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}
