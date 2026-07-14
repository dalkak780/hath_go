// Command captureproxy is a forward HTTP proxy that logs every request and its
// response, in the clear, to a JSONL file. Because the H@H RPC is plain HTTP,
// running the official Java client through this proxy captures the exact wire
// format (request line, headers, query string, actkey) and the real server
// response bodies — the ground truth for building/validating the Go client's
// RPC mock.
//
// Usage against a live Java client:
//
//	go run ./tools/captureproxy -listen :8888 -out rpc_capture.jsonl
//
// then start the Java client with the JVM pointed at the proxy:
//
//	java -Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=8888 -jar HentaiAtHome.jar
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
	"sync"
	"time"
)

type record struct {
	Ts        time.Time      `json:"ts"`
	Method    string         `json:"method"`
	URL       string         `json:"url"`
	ReqHeader http.Header    `json:"req_header"`
	ReqBody   string         `json:"req_body,omitempty"`
	Status    int            `json:"status"`
	RespHeader http.Header   `json:"resp_header"`
	RespBody  string         `json:"resp_body,omitempty"`
	BodyB64   string         `json:"body_b64,omitempty"`
	Err       string         `json:"err,omitempty"`
}

var (
	outPath string
	host    string
	mu      sync.Mutex
	maxLog  = 64 * 1024 // cap text body logging; full binary via base64
)

func main() {
	flag.StringVar(&outPath, "out", "rpc_capture.jsonl", "output JSONL path")
	flag.StringVar(&host, "host", "", "only log requests whose URL host contains this substring")
	flag.Parse()

	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := record{Method: r.Method, URL: r.URL.String(), ReqHeader: r.Header.Clone()}
		rec.Ts = time.Now()

		if host != "" && !contains(r.URL.Host, host) {
			// pass through without logging
			roundTrip(w, r, nil)
			return
		}

		// read request body (usually empty for GET RPC)
		if r.Body != nil {
			rb, _ := io.ReadAll(io.LimitReader(r.Body, int64(maxLog)))
			r.Body.Close()
			r.Body = io.NopCloser(newBytesReader(rb))
			rec.ReqBody = string(rb)
		}

		captured := &captureWriter{header: w.Header()}
		status := roundTrip(captured, r, nil)
		rec.Status = status
		rec.RespHeader = captured.header.Clone()
		if len(captured.body) <= maxLog && isText(captured.header.Get("Content-Type")) {
			rec.RespBody = string(captured.body)
		} else {
			rec.BodyB64 = base64.StdEncoding.EncodeToString(captured.body)
		}

		writeRecord(rec)
	})

	log.Println("capture proxy listening, routing to", outPath)
	log.Fatal(http.ListenAndServe(getAddr(), proxy))
}

// roundTrip forwards the request through the default transport and writes the
// response back to w. Returns the status code.
func roundTrip(w http.ResponseWriter, r *http.Request, _ any) int {
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, "proxy error: "+err.Error(), http.StatusBadGateway)
		return http.StatusBadGateway
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
	return resp.StatusCode
}

type captureWriter struct {
	header http.Header
	body   []byte
}

func (c *captureWriter) Header() http.Header {
	if c.header == nil {
		c.header = http.Header{}
	}
	return c.header
}
func (c *captureWriter) WriteHeader(int)        {}
func (c *captureWriter) Write(p []byte) (int, error) {
	c.body = append(c.body, p...)
	return len(p), nil
}

func writeRecord(rec record) {
	mu.Lock()
	defer mu.Unlock()
	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		log.Println("open out:", err)
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(rec)
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && indexOf(s, sub) >= 0
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
func isText(ct string) bool {
	return contains(ct, "text") || contains(ct, "application/octet-stream") == false && ct != ""
}
func getAddr() string {
	if a := os.Getenv("CAP_LISTEN"); a != "" {
		return a
	}
	return ":8888"
}

// tiny bytes reader to avoid pulling "bytes" for one call
type bytesReader struct {
	b []byte
	i int
}

func newBytesReader(b []byte) *bytesReader { return &bytesReader{b: b} }
func (r *bytesReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}
