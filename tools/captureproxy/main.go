// Command captureproxy is a forward HTTP proxy that logs every request/response
// pair, in the clear, to a JSONL file. The H@H RPC is plain HTTP, so routing the
// official Java client through this proxy captures the exact wire format
// (request line, query string, actkey) and the real server response bodies —
// the ground truth for validating the Go client's RPC.
//
// Each JSONL record is one request/response pair. Binary bodies (e.g. the
// get_cert PKCS#12) are base64-encoded under body_b64.
//
// NOTE: captures contain your real client id and actkeys (derived from your
// client key via SHA-1 — the key itself is never transmitted). Do not commit
// raw captures; redact before sharing.
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type record struct {
	Ts         time.Time   `json:"ts"`
	Method     string      `json:"method"`
	URL        string      `json:"url"`
	ReqHeader  http.Header `json:"req_header"`
	ReqBody    string      `json:"req_body,omitempty"`
	Status     int         `json:"status"`
	RespHeader http.Header `json:"resp_header"`
	RespBody   string      `json:"resp_body,omitempty"`
	BodyB64    string      `json:"body_b64,omitempty"`
	Err        string      `json:"err,omitempty"`
}

const maxLogBody = 1 << 20 // 1 MiB cap on captured bodies

// newCaptureHandler builds the proxy handler. out receives one JSON record per
// request. hostFilter, if non-empty, skips logging for URLs whose host does not
// contain it (still forwarded). transport is used for upstream (defaults to
// http.DefaultTransport when nil).
func newCaptureHandler(out io.Writer, hostFilter string, transport http.RoundTripper) http.Handler {
	if transport == nil {
		transport = http.DefaultTransport
	}
	var mu sync.Mutex
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log := hostFilter == "" || strings.Contains(r.URL.Host, hostFilter)

		// buffer request body so it can be both forwarded and recorded
		var reqBody []byte
		if r.Body != nil {
			reqBody, _ = io.ReadAll(io.LimitReader(r.Body, maxLogBody))
			r.Body.Close()
			r.Body = io.NopCloser(strings.NewReader(string(reqBody)))
		}

		resp, err := transport.RoundTrip(r)
		rec := record{Ts: time.Now(), Method: r.Method, URL: r.URL.String(), ReqHeader: r.Header.Clone(), ReqBody: string(reqBody)}
		if err != nil {
			rec.Err = err.Error()
			if log {
				mu.Lock()
				enc.Encode(rec)
				mu.Unlock()
			}
			http.Error(w, "proxy error: "+err.Error(), http.StatusBadGateway)
			return
		}

		// forward headers + status to the real client
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)

		// tee the body: client gets it live, we keep a copy
		var buf strings.Builder
		_, _ = io.Copy(io.MultiWriter(w, &captureSink{&buf}), resp.Body)
		resp.Body.Close()

		if log {
			rec.Status = resp.StatusCode
			rec.RespHeader = resp.Header.Clone()
			body := buf.String()
			if isText(resp.Header.Get("Content-Type")) && len(body) <= maxLogBody {
				rec.RespBody = body
			} else {
				rec.BodyB64 = base64.StdEncoding.EncodeToString([]byte(body))
			}
			mu.Lock()
			enc.Encode(rec)
			mu.Unlock()
		}
	})
}

func isText(ct string) bool {
	return strings.Contains(ct, "text") || strings.Contains(ct, "json")
}

// captureSink is an io.Writer backed by a strings.Builder.
type captureSink struct{ b *strings.Builder }

func (s *captureSink) Write(p []byte) (int, error) { return s.b.Write(p) }

func main() {
	var (
		outPath string
		host    string
		addr    string
	)
	flag.StringVar(&outPath, "out", "rpc_capture.jsonl", "output JSONL path")
	flag.StringVar(&host, "host", "", "only log requests whose URL host contains this substring (others are still forwarded)")
	flag.StringVar(&addr, "listen", ":8888", "listen address")
	flag.Parse()

	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		log.Fatal("open out: ", err)
	}
	defer f.Close()

	log.Printf("capture proxy listening on %s, logging to %s", addr, outPath)
	log.Fatal(http.ListenAndServe(addr, newCaptureHandler(f, host, nil)))
}
