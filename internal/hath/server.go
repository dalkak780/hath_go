package hath

// HTTPServer is the TLS edge server. It replaces the original hand-rolled TCP
// HTTP parser with net/http, while preserving the H@H request-routing and
// authentication semantics:
//
//	/h/{fileid}/{additional}/{filename}   cached file (keystamp-gated)
//	/servercmd/{cmd}/{add}/{time}/{key}    server command (RPC-IP + HMAC)
//	/t/{size}/{time}/{key}                 speed test
//
// Flood control, max-connection gating, and bandwidth throttling are applied
// in a listener wrapper before requests reach the mux.

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	fileIndexRe = regexp.MustCompile(`^\d+$`)
	xresRe      = regexp.MustCompile(`^(org|\d+)$`)
	localNetRe  = regexp.MustCompile(`(?i)^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.|::1|0:0:0:0:0:0:0:1|fc|fd)`)
)

// HTTPServer serves cached content over TLS.
type HTTPServer struct {
	settings *Settings
	cache    *CacheHandler
	rpc      *ServerHandler
	stats    *Stats
	cert     *CertManager
	client   *HathClient // for refresh_settings / refresh_certs commands
	bwm      *BandwidthMonitor

	allowNormal atomic.Bool
	openConns   atomic.Int64

	httpServer *http.Server
	listener   net.Listener
	serveDone  chan error

	floodMu sync.Mutex
	flood   map[string]*floodEntry
	proxyMu sync.Mutex
	proxies map[string]*proxyFlight
}

// AllowNormalConnections permits non-RPC, non-local clients after the startup
// connectivity test succeeds.
func (h *HTTPServer) AllowNormalConnections() { h.allowNormal.Store(true) }

type floodEntry struct {
	count        int
	last         time.Time
	blockedUntil time.Time
}

type proxyFlight struct {
	done   chan struct{}
	cached bool
}

// NewHTTPServer constructs the edge server.
func NewHTTPServer(s *Settings, cache *CacheHandler, rpc *ServerHandler, stats *Stats, cert *CertManager, client *HathClient) *HTTPServer {
	hs := &HTTPServer{
		settings: s,
		cache:    cache,
		rpc:      rpc,
		stats:    stats,
		cert:     cert,
		client:   client,
		flood:    make(map[string]*floodEntry),
		proxies:  make(map[string]*proxyFlight),
	}
	if !s.DisableBWM {
		hs.bwm = NewBandwidthMonitor(s.ThrottleBytes)
	}
	return hs
}

// Start binds synchronously, then begins serving. A successful return proves
// the port is owned before the client sends client_start.
func (h *HTTPServer) Start() error {
	addr := ":" + strconv.Itoa(h.settings.ClientPort)
	raw, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	h.listener = tls.NewListener(raw, h.cert.TLSConfig())
	Info("internal HTTP server listening", "port", h.settings.ClientPort)

	h.httpServer = &http.Server{
		Handler:           http.HandlerFunc(h.handle),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       time.Second,
		MaxHeaderBytes:    10000,
	}
	h.serveDone = make(chan error, 1)
	go func() { h.serveDone <- h.httpServer.Serve(&gatingListener{Listener: h.listener, server: h}) }()
	return nil
}

// Done reports listener termination. Any error other than http.ErrServerClosed
// is fatal after startup because the node is no longer serving.
func (h *HTTPServer) Done() <-chan error { return h.serveDone }

// Shutdown stops accepting new connections and waits for active handlers.
func (h *HTTPServer) Shutdown() {
	if h.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		if err := h.httpServer.Shutdown(ctx); err != nil {
			_ = h.httpServer.Close()
		}
	}
}

// CertExpired exposes the cert manager's check.
func (h *HTTPServer) CertExpired() bool { return h.cert.IsExpired() }

// --- listener gating: flood control, max-conns, bypass rules ---

type gatingListener struct {
	net.Listener
	server *HTTPServer
}

func (l *gatingListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if !l.server.admit(c) {
			c.Close()
			continue
		}
		if tc, ok := c.(*tls.Conn); ok {
			// Java applies IP admission before TLS, then the session performs the
			// handshake. Force it here before counting the connection.
			_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
			if err := tc.Handshake(); err != nil {
				c.Close()
				continue
			}
			_ = tc.SetDeadline(time.Time{})
		}
		host := stripV6(ipOf(c.RemoteAddr().String()))
		open := l.server.openConns.Add(1)
		if l.server.stats != nil {
			l.server.stats.SetOpenConnections(int(open))
		}
		return &trackedConn{Conn: c, server: l.server, throttle: !l.server.isLocal(host), counted: true}, nil
	}
}

// admit applies the original accept-time policy. Returns false to reject.
func (h *HTTPServer) admit(c net.Conn) bool {
	host := stripV6(ipOf(c.RemoteAddr().String()))
	local := h.isLocal(host)
	rpc := h.settings.IsValidRPCServer(net.ParseIP(host))

	if !rpc && !h.allowNormal.Load() {
		Warn("rejecting connection during startup", "ip", host)
		return false
	}
	if !rpc && !local {
		max := h.settings.MaxConnections()
		open := h.openConns.Load()
		if open > int64(max) {
			Warn("exceeded max incoming connections", "max", max)
			return false
		}
		if open > int64(float64(max)*0.8) {
			go h.rpc.NotifyOverload()
		}
		if !h.settings.DisableFloodControl && !h.floodAllow(host) {
			return false
		}
	}
	return true
}

func (h *HTTPServer) floodAllow(host string) bool {
	h.floodMu.Lock()
	defer h.floodMu.Unlock()
	e, ok := h.flood[host]
	if !ok {
		e = &floodEntry{}
		h.flood[host] = e
	}
	now := time.Now()
	if e.blockedUntil.After(now) {
		return false
	}
	elapsed := int(now.Sub(e.last).Seconds())
	e.count = max(0, e.count-elapsed) + 1
	e.last = now
	if e.count > 10 {
		e.blockedUntil = now.Add(60 * time.Second)
		Warn("flood control activated", "ip", host, "block", "60s")
		return false
	}
	return true
}

// PruneFloodControl drops stale entries (called periodically from the main loop).
func (h *HTTPServer) PruneFloodControl() {
	h.floodMu.Lock()
	defer h.floodMu.Unlock()
	cutoff := time.Now().Add(-60 * time.Second)
	for k, e := range h.flood {
		if e.last.Before(cutoff) {
			delete(h.flood, k)
		}
	}
}

func (h *HTTPServer) isLocal(host string) bool {
	if h.settings.ClientHost != "" && stripV6(h.settings.ClientHost) == host {
		return true
	}
	return localNetRe.MatchString(host)
}

// trackedConn counts open connections and throttles outbound writes for
// non-local traffic.
type trackedConn struct {
	net.Conn
	server    *HTTPServer
	throttle  bool
	counted   bool
	closeOnce sync.Once
}

func (t *trackedConn) Write(p []byte) (int, error) {
	if t.throttle && t.server.bwm != nil {
		t.server.bwm.WaitForQuota(len(p))
	}
	n, err := t.Conn.Write(p)
	if t.server.stats != nil {
		t.server.stats.BytesSent(int64(n))
	}
	return n, err
}

func (t *trackedConn) Read(b []byte) (int, error) {
	if !t.counted {
		t.counted = true
		open := t.server.openConns.Add(1)
		if t.server.stats != nil {
			t.server.stats.SetOpenConnections(int(open))
		}
	}
	return t.Conn.Read(b)
}

func (t *trackedConn) Close() error {
	t.closeOnce.Do(func() {
		if t.counted {
			open := t.server.openConns.Add(-1)
			if t.server.stats != nil {
				t.server.stats.SetOpenConnections(int(open))
			}
		}
	})
	return t.Conn.Close()
}

// --- request handling ---

func (h *HTTPServer) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "Genetic Lifeform and Distributed Open Server "+ClientVer)
	w.Header().Set("Connection", "close")
	r.Close = true
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET,HEAD")
		h.empty(w, http.StatusMethodNotAllowed)
		return
	}

	// Faithful path parsing: raw request-target, strip absolute-URI prefix,
	// decode only %3d, split on '/'.
	target := strings.TrimSpace(r.RequestURI)
	if i := strings.Index(strings.ToLower(target), "://"); i >= 0 {
		if slash := strings.IndexByte(target[i+3:], '/'); slash >= 0 {
			target = target[i+3+slash:]
		}
	}
	target = strings.ReplaceAll(target, "%3d", "=")
	segments := strings.Split(target, "/")

	if len(segments) < 2 || segments[0] != "" {
		h.empty(w, http.StatusNotFound)
		return
	}

	switch segments[1] {
	case "h":
		h.handleFile(w, r, segments)
	case "servercmd":
		h.handleServerCmd(w, r, segments)
	case "t":
		h.handleSpeedtest(w, r, segments)
	default:
		if len(segments) == 2 && segments[1] == "favicon.ico" {
			w.Header().Set("Location", "https://e-hentai.org/favicon.ico")
			w.Header().Set("Content-Type", "text/html; charset=ISO-8859-1")
			w.WriteHeader(http.StatusMovedPermanently)
			return
		}
		if len(segments) == 2 && segments[1] == "robots.txt" {
			w.Header().Set("Content-Type", "text/plain; charset=ISO-8859-1")
			w.Header().Set("Cache-Control", "public, max-age=31536000")
			w.Header().Set("Content-Length", "25")
			w.Write([]byte("User-agent: *\nDisallow: /"))
			return
		}
		h.empty(w, http.StatusNotFound)
	}
}

// handleFile serves /h/{fileid}/{additional}/{filename}.
func (h *HTTPServer) handleFile(w http.ResponseWriter, r *http.Request, seg []string) {
	if len(seg) < 4 {
		h.empty(w, http.StatusBadRequest)
		return
	}
	fileid := seg[2]
	additional := parseAdditional(seg[3])

	keystampRejected := true
	if ks, ok := additional["keystamp"]; ok {
		kp := strings.SplitN(ks, "-", 2)
		if len(kp) == 2 {
			if kt, err := strconv.ParseInt(kp[0], 10, 64); err == nil {
				if abs64(h.settings.ServerTime()-kt) < keystampTolerance {
					if strings.EqualFold(kp[1], keystampHash(kt, fileid, h.settings.ClientKey)) {
						keystampRejected = false
					}
				}
			}
		}
	}
	if keystampRejected {
		h.empty(w, http.StatusForbidden)
		return
	}

	fileindex := additional["fileindex"]
	xres := additional["xres"]
	if fileindex == "" || xres == "" || !fileIndexRe.MatchString(fileindex) || !xresRe.MatchString(xres) {
		h.empty(w, http.StatusNotFound)
		return
	}

	hvf, onDisk := h.cache.Lookup(fileid)
	if hvf == nil {
		h.empty(w, http.StatusNotFound)
		return
	}
	if onDisk {
		h.serveCached(w, r, hvf)
		return
	}
	h.proxyFileCoalesced(w, r, hvf, fileindex, xres, fileid)
}

func (h *HTTPServer) serveCached(w http.ResponseWriter, r *http.Request, hvf *HVFile) {
	started := time.Now()
	path := h.cache.LocalPath(hvf)
	f, err := os.Open(path)
	if err != nil {
		h.empty(w, http.StatusInternalServerError)
		return
	}
	defer f.Close()

	// Best-effort integrity re-check (unchanged behavior): a recently-accessed
	// file is verified in the background; corrupt files are purged.
	if !h.settings.DisableFileVerify {
		if h.cache.MarkRecentlyAccessed(hvf) && !h.cache.IsFileVerificationOnCooldown() {
			go func() {
				defer func() {
					if r := recover(); r != nil {
						Error("cache verify panicked; skipping", "fileid", hvf.Fileid(), "err", r)
					}
				}()
				if h.cache.DeleteIfCorrupt(hvf) {
					Warn("corrupt cached file; deleting", "fileid", hvf.Fileid())
				}
			}()
		} else {
			h.cache.MarkRecentlyAccessed(hvf)
		}
	} else {
		h.cache.MarkRecentlyAccessed(hvf)
	}

	w.Header().Set("Content-Type", hvf.Mime())
	w.Header().Set("Cache-Control", "public, max-age=31536000")
	w.Header().Set("Content-Length", strconv.FormatInt(hvf.Size, 10))
	w.WriteHeader(http.StatusOK)
	var sent int64
	var writeErr error
	if r.Method == http.MethodHead {
		h.stats.FileSent()
	} else {
		sent, writeErr = io.CopyN(w, f, hvf.Size)
		if writeErr == nil {
			h.stats.FileSent()
		}
	}
	if writeErr != nil {
		Debug("serve interrupted", "bytes", sent, "expected", hvf.Size, "duration", time.Since(started).String(), "path", r.RequestURI, "err", writeErr)
		return
	}
	Info("served", "code", 200, "bytes", sent, "expected", hvf.Size, "duration", time.Since(started).String(), "path", r.RequestURI)
}

// proxyFile fetches a missing file from a server-suggested origin, streams it
// to the client, and caches the verified result. When the origin is another
// H@H node it is authenticated with the Hath-Request header.
func (h *HTTPServer) proxyFileCoalesced(w http.ResponseWriter, r *http.Request, hvf *HVFile, fileindex, xres, fileid string) {
	h.proxyMu.Lock()
	if h.proxies == nil {
		h.proxies = make(map[string]*proxyFlight)
	}
	if flight := h.proxies[fileid]; flight != nil {
		h.proxyMu.Unlock()
		select {
		case <-flight.done:
			if cached, ok := h.cache.Lookup(fileid); flight.cached && ok {
				h.serveCached(w, r, cached)
				return
			}
			h.empty(w, http.StatusBadGateway)
		case <-r.Context().Done():
		}
		return
	}
	flight := &proxyFlight{done: make(chan struct{})}
	h.proxies[fileid] = flight
	h.proxyMu.Unlock()

	defer func() {
		h.proxyMu.Lock()
		delete(h.proxies, fileid)
		close(flight.done)
		h.proxyMu.Unlock()
	}()
	flight.cached = h.proxyFile(w, r, hvf, fileindex, xres, fileid)
}

func (h *HTTPServer) proxyFile(w http.ResponseWriter, r *http.Request, hvf *HVFile, fileindex, xres, fileid string) bool {
	started := time.Now()
	sources := h.rpc.GetStaticRangeFetchURL(fileindex, xres, fileid)
	if len(sources) == 0 {
		h.empty(w, http.StatusNotFound)
		return false
	}
	// fetch to a temp file first so we can verify SHA-1 before serving+importing
	tmp, err := os.CreateTemp(h.settings.TempDir, "proxyfile_")
	if err != nil {
		h.empty(w, http.StatusBadGateway)
		return false
	}
	tmpPath := tmp.Name()
	tmp.Close()

	// try sources in order until one yields the right length
	var n int64
	var chosen string
	for _, src := range sources {
		got, err := h.rpc.DownloadToFile(src, tmpPath, 60*time.Second, true, true, nil, fileid)
		if err == nil && got == hvf.Size {
			n = got
			chosen = src
			break
		}
	}
	if chosen == "" {
		os.Remove(tmpPath)
		h.empty(w, http.StatusBadGateway)
		return false
	}

	// verify integrity before exposing to the client
	if !validateFileSHA1(tmpPath, hvf.Hash) {
		os.Remove(tmpPath)
		Warn("proxy download corrupt; not serving", "fileid", fileid)
		h.empty(w, http.StatusBadGateway)
		return false
	}

	f, err := os.Open(tmpPath)
	if err != nil {
		h.empty(w, http.StatusInternalServerError)
		return false
	}
	defer f.Close()

	w.Header().Set("Content-Type", hvf.Mime())
	w.Header().Set("Cache-Control", "public, max-age=31536000")
	w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
	w.WriteHeader(http.StatusOK)
	var sent int64
	var writeErr error
	if r.Method == http.MethodHead {
		h.stats.FileSent()
	} else {
		sent, writeErr = io.CopyN(w, f, n)
		if writeErr == nil {
			h.stats.FileSent()
		}
	}
	// import verified copy into the cache (best-effort)
	cached := h.cache.ImportFileToCache(tmpPath, hvf)
	if cached {
		Debug("proxy file imported to cache", "fileid", fileid)
	} else {
		os.Remove(tmpPath)
	}
	_ = chosen
	if writeErr != nil {
		Debug("proxy response interrupted", "bytes", sent, "expected", n, "duration", time.Since(started).String(), "path", r.RequestURI, "err", writeErr)
		return cached
	}
	Info("proxied", "code", 200, "bytes", sent, "expected", n, "duration", time.Since(started).String(), "path", r.RequestURI)
	return cached
}

// handleServerCmd serves /servercmd/{cmd}/{add}/{time}/{key}.
func (h *HTTPServer) handleServerCmd(w http.ResponseWriter, r *http.Request, seg []string) {
	if !h.settings.IsValidRPCServer(net.ParseIP(ipOf(r.RemoteAddr))) {
		h.empty(w, http.StatusForbidden)
		return
	}
	if len(seg) < 6 {
		h.empty(w, http.StatusForbidden)
		return
	}
	rawCmd := seg[2]
	cmd := strings.ToLower(rawCmd)
	add := seg[3]
	t, err := strconv.ParseInt(seg[4], 10, 64)
	if err != nil {
		h.empty(w, http.StatusForbidden)
		return
	}
	key := seg[5]
	if abs64(h.settings.ServerTime()-t) > MaxKeyTimeDrift ||
		!strings.EqualFold(servercmdKey(rawCmd, add, h.settings.ClientID, t, h.settings.ClientKey), key) {
		Debug("servercmd bad/expired key")
		h.empty(w, http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=ISO-8859-1")
	switch cmd {
	case "still_alive":
		h.writeText(w, "I feel FANTASTIC and I'm still alive")
	case "refresh_settings":
		if h.client != nil {
			h.client.TriggerRefreshSettings()
		}
	case "refresh_certs":
		if h.client != nil {
			h.client.TriggerCertRefresh()
		}
	case "start_downloader":
		if h.client != nil {
			h.client.StartDownloader()
		}
	case "threaded_proxy_test":
		w.Header().Set("Cache-Control", "public, max-age=31536000")
		h.runThreadedProxyTest(w, add)
	case "speed_test":
		size := int64(1000000)
		if v := parseAdditional(add)["testsize"]; v != "" {
			var err error
			size, err = strconv.ParseInt(v, 10, 32)
			if err != nil {
				h.writeText(w, "INVALID_COMMAND")
				return
			}
		}
		h.writeSpeedtest(w, r, size)
	default:
		h.writeText(w, "INVALID_COMMAND")
	}
}

// handleSpeedtest serves /t/{size}/{time}/{key}.
func (h *HTTPServer) handleSpeedtest(w http.ResponseWriter, r *http.Request, seg []string) {
	if len(seg) < 5 {
		h.empty(w, http.StatusBadRequest)
		return
	}
	size, err := strconv.ParseInt(seg[2], 10, 64)
	if err != nil {
		h.empty(w, http.StatusBadRequest)
		return
	}
	t, err := strconv.ParseInt(seg[3], 10, 64)
	if err != nil {
		h.empty(w, http.StatusBadRequest)
		return
	}
	if abs64(h.settings.ServerTime()-t) > MaxKeyTimeDrift ||
		speedtestKey(seg[2], t, h.settings.ClientID, h.settings.ClientKey) != seg[4] {
		h.empty(w, http.StatusForbidden)
		return
	}
	h.writeSpeedtest(w, r, size)
}

func (h *HTTPServer) writeSpeedtest(w http.ResponseWriter, r *http.Request, size int64) {
	if h.stats != nil {
		h.stats.SetProgramStatus("Running speed tests...")
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	if size > 0 {
		w.Header().Set("Cache-Control", "public, max-age=31536000")
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	}
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	buf := make([]byte, 8192)
	var written int64
	for written < size {
		n := int64(len(buf))
		if size-written < n {
			n = size - written
		}
		rand.Read(buf[:n])
		wn, _ := w.Write(buf[:n])
		if wn <= 0 {
			break
		}
		written += int64(wn)
	}
}

func (h *HTTPServer) empty(w http.ResponseWriter, code int) {
	w.Header().Set("Content-Type", "text/html; charset=ISO-8859-1")
	body := []byte(fmt.Sprintf("An error has occurred. (%d)", code))
	w.Header().Set("Cache-Control", "public, max-age=31536000")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

func (h *HTTPServer) writeText(w http.ResponseWriter, body string) {
	if body != "" {
		w.Header().Set("Cache-Control", "public, max-age=31536000")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	}
	_, _ = io.WriteString(w, body)
}

// parseAdditional splits a ";k=v;k=v" string into a map.
func parseAdditional(s string) map[string]string {
	out := map[string]string{}
	for _, kv := range strings.Split(strings.TrimSpace(s), ";") {
		if len(kv) < 3 {
			continue
		}
		if k, v, ok := strings.Cut(strings.TrimSpace(kv), "="); ok {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

func ipOf(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func stripV6(s string) string { return strings.ReplaceAll(s, "::ffff:", "") }

func abs64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// runThreadedProxyTest runs N concurrent /t fetches against another H@H node and
// reports success count + total time. Matches the original OK:<n>-<ms> format.
func (h *HTTPServer) runThreadedProxyTest(w http.ResponseWriter, add string) {
	a := parseAdditional(add)
	hostname := a["hostname"]
	protocol := a["protocol"]
	if protocol == "" {
		protocol = "http"
	}
	port := a["port"]
	testsize := a["testsize"]
	testcount := atoi(a["testcount"])
	testtime := a["testtime"]
	testkey := a["testkey"]

	client := &http.Client{Timeout: 60 * time.Second}
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		success int
		total   int64
	)
	for i := 0; i < testcount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					Error("threaded proxy test panicked", "err", r)
				}
			}()
			url := fmt.Sprintf("%s://%s:%s/t/%s/%s/%s/%d", protocol, hostname, port, testsize, testtime, testkey, randInt31())
			start := time.Now()
			req, err := http.NewRequest(http.MethodGet, url, nil)
			if err != nil {
				return
			}
			setJavaRequestHeaders(req)
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			n, readErr := io.Copy(io.Discard, resp.Body)
			if readErr == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 && n == resp.ContentLength && resp.ContentLength >= parseLen(testsize) {
				mu.Lock()
				success++
				total += time.Since(start).Milliseconds()
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	Debug("ran threaded proxy test", "hostname", hostname, "success", success, "totalMs", total)
	h.writeText(w, fmt.Sprintf("OK:%d-%d", success, total))
}

func randInt31() int64 {
	var b [4]byte
	rand.Read(b[:])
	return int64(uint32(b[0])<<24|uint32(b[1])<<16|uint32(b[2])<<8|uint32(b[3])) & 0x7fffffff
}

func parseLen(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}
