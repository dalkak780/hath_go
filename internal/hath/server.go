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
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	fileIndexRe = regexp.MustCompile(`^\d+$`)
	xresRe      = regexp.MustCompile(`^org|\d+$`)
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

	floodMu sync.Mutex
	flood   map[string]*floodEntry
}

type floodEntry struct {
	count        int
	last         time.Time
	blockedUntil time.Time
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
	}
	if !s.DisableBWM {
		hs.bwm = NewBandwidthMonitor(s.ThrottleBytes)
	}
	return hs
}

// AllowNormalConnections permits non-RPC, non-local clients (after the startup
// connectivity test passes).
func (h *HTTPServer) AllowNormalConnections() { h.allowNormal.Store(true) }

// Start binds the TLS listener and begins serving. Blocks until Shutdown.
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
	}
	return h.httpServer.Serve(&gatingListener{Listener: h.listener, server: h})
}

// Shutdown stops accepting new connections and closes in-flight handlers.
func (h *HTTPServer) Shutdown() {
	if h.httpServer != nil {
		h.httpServer.Close()
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
		if tc, ok := c.(*tls.Conn); ok {
			// force the handshake so RemoteAddr/IP classification is stable and
			// bad clients fail early, before we count them.
			_ = tc.Handshake()
		}
		if l.server.admit(c) {
			return &trackedConn{Conn: c, server: l.server}, nil
		}
		c.Close()
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
	if h.settings.ClientHost != "" && h.settings.ClientHost == host {
		return true
	}
	return localNetRe.MatchString(host)
}

// trackedConn counts open connections and throttles outbound writes for
// non-local traffic.
type trackedConn struct {
	net.Conn
	server *HTTPServer
	throttle bool
	counted bool
}

func (t *trackedConn) Write(p []byte) (int, error) {
	if t.throttle && t.server.bwm != nil {
		t.server.bwm.WaitForQuota(len(p))
	}
	return t.Conn.Write(p)
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
	if t.counted {
		open := t.server.openConns.Add(-1)
		if t.server.stats != nil {
			t.server.stats.SetOpenConnections(int(open))
		}
	}
	return t.Conn.Close()
}

// --- request handling ---

func (h *HTTPServer) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET,HEAD")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
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
			w.WriteHeader(http.StatusMovedPermanently)
			return
		}
		if len(segments) == 2 && segments[1] == "robots.txt" {
			w.Header().Set("Content-Type", "text/plain")
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
					if kp[1] == keystampHash(kt, fileid, h.settings.ClientKey) {
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
	h.proxyFile(w, r, hvf, fileindex, xres, fileid)
}

func (h *HTTPServer) serveCached(w http.ResponseWriter, r *http.Request, hvf *HVFile) {
	path := h.cache.LocalPath(hvf)
	f, err := os.Open(path)
	if err != nil {
		h.empty(w, http.StatusInternalServerError)
		return
	}
	defer f.Close()

	if !h.settings.DisableFileVerify && h.cache.MarkRecentlyAccessed(hvf) && !h.cache.IsFileVerificationOnCooldown() {
		go func() {
			if !h.cache.VerifyFile(hvf) {
				Warn("corrupt cached file; deleting", "fileid", hvf.Fileid())
				h.cache.DeleteFileFromCache(hvf)
			}
		}()
	} else {
		h.cache.MarkRecentlyAccessed(hvf)
	}

	w.Header().Set("Content-Type", hvf.Mime())
	w.Header().Set("Cache-Control", "public, max-age=31536000")
	w.Header().Set("Content-Length", strconv.FormatInt(hvf.Size, 10))
	w.WriteHeader(http.StatusOK)
	h.stats.FileSent()
	if r.Method != http.MethodHead {
		io.Copy(w, f)
	}
	Info("served", "code", 200, "bytes", hvf.Size, "path", r.RequestURI)
}

// proxyFile fetches a missing file from a server-suggested origin, streams it
// to the client, and caches the result.
func (h *HTTPServer) proxyFile(w http.ResponseWriter, r *http.Request, hvf *HVFile, fileindex, xres, fileid string) {
	sources := h.rpc.GetStaticRangeFetchURL(fileindex, xres, fileid)
	if len(sources) == 0 {
		h.empty(w, http.StatusNotFound)
		return
	}
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(sources[0])
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		h.empty(w, http.StatusNotFound)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", hvf.Mime())
	w.Header().Set("Cache-Control", "public, max-age=31536000")
	if resp.ContentLength > 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	}
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	tmp, err := os.CreateTemp(h.settings.TempDir, "pcache_")
	var mw io.Writer = w
	if err == nil {
		mw = io.MultiWriter(w, tmp)
	}
	got, _ := io.Copy(mw, resp.Body)
	if tmp != nil {
		tmp.Close()
		if got == hvf.Size {
			os.MkdirAll(filepath.Dir(h.cache.LocalPath(hvf)), 0o755)
			os.Rename(tmp.Name(), h.cache.LocalPath(hvf))
		} else {
			os.Remove(tmp.Name())
		}
	}
	Info("proxied", "code", 200, "bytes", got, "path", r.RequestURI)
}

// handleServerCmd serves /servercmd/{cmd}/{add}/{time}/{key}.
func (h *HTTPServer) handleServerCmd(w http.ResponseWriter, r *http.Request, seg []string) {
	if !h.settings.IsValidRPCServer(net.ParseIP(ipOf(r.RemoteAddr))) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if len(seg) < 6 {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	cmd := seg[2]
	add := seg[3]
	t, err := strconv.ParseInt(seg[4], 10, 64)
	if err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	key := seg[5]
	if abs64(h.settings.ServerTime()-t) > MaxKeyTimeDrift ||
		servercmdKey(cmd, add, h.settings.ClientID, t, h.settings.ClientKey) != key {
		Debug("servercmd bad/expired key")
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	switch cmd {
	case "still_alive":
		w.Write([]byte("I feel FANTASTIC and I'm still alive"))
	case "refresh_settings":
		if h.client != nil {
			h.client.TriggerRefreshSettings()
		}
	case "refresh_certs":
		if h.client != nil {
			h.client.TriggerCertRefresh()
		}
	case "speed_test":
		// server-initiated speedtest response; full impl deferred
	default:
		w.Write([]byte("INVALID_COMMAND"))
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
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
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
	w.Header().Set("Content-Type", "text/plain; charset=iso-8859-1")
	w.WriteHeader(code)
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
