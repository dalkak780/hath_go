package hath

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"
)

// TestCapturedJavaRPCReplay pins the non-secret wire properties extracted
// from rpc_capture.jsonl. IDs, keys, hosts, IPs, signatures, and payload bytes
// are deliberately excluded from this committed replay.
func TestCapturedJavaRPCReplay(t *testing.T) {
	wantActions := []string{
		ActServerStat,
		ActClientLogin,
		ActGetCertificate,
		ActClientStart,
		ActClientSettings,
	}
	var (
		mu      sync.Mutex
		actions []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); got != "Hentai@Home 1.6.5" {
			t.Errorf("User-Agent = %q", got)
		}
		if got := r.Header.Get("Accept"); got != "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2" {
			t.Errorf("Accept = %q", got)
		}
		if got := r.Header.Get("Connection"); got != "close" {
			t.Errorf("Connection = %q", got)
		}
		mu.Lock()
		actions = append(actions, r.URL.Query().Get("act"))
		mu.Unlock()
		body := "OK\n"
		if r.URL.Query().Get("act") == ActServerStat {
			// The capture contains this blank line before the settings.
			body = "OK\n\nmin_client_build=178\n"
		}
		w.Header().Set("Content-Length", itoa(len(body)))
		w.Write([]byte(body))
	}))
	defer srv.Close()

	s := NewSettings()
	s.MaxAllowedFile = 1 << 20
	h := NewServerHandler(s, NewStats())
	for _, act := range wantActions {
		rawurl := srv.URL + "/?act=" + act
		if _, _, err := h.fetch(rawurl, time.Second); err != nil {
			t.Fatalf("replay %s: %v", act, err)
		}
	}
	if !reflect.DeepEqual(actions, wantActions) {
		t.Fatalf("startup actions = %v, want %v", actions, wantActions)
	}
}
