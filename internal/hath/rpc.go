package hath

// ServerHandler implements the outbound H@H RPC. This is the most
// safety-sensitive part of the client: every authenticated request carries a
// time-corrected SHA-1 actkey, and the server locks accounts that send too
// many malformed/ill-timed requests. Clock sync (server_stat) and the
// KEY_EXPIRED retry path exist precisely to avoid that.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// maxRPCMemory caps in-memory RPC text responses (mirrors the original 10MB).
const maxRPCMemory = 10 * 1024 * 1024

// rpcUserAgent is the UA sent on every outbound request.
const rpcUserAgent = "Hentai@Home " + ClientVer

// RespStatus mirrors ServerResponse.RESPONSE_STATUS_*.
type RespStatus int

const (
	RespNull RespStatus = iota
	RespOK
	RespFail
)

// ServerResponse is a parsed RPC reply.
type ServerResponse struct {
	Status   RespStatus
	Lines    []string // response text after the status line (OK only)
	FailCode string
	FailHost string
}

// ServerHandler talks to the H@H RPC server.
type ServerHandler struct {
	settings      *Settings
	client        *http.Client
	stats         *Stats
	lastOverload  time.Time
	loginValidated bool
}

// NewServerHandler builds the RPC client. A single http.Client with keep-alives
// disabled emulates the original "Connection: Close" behavior.
func NewServerHandler(s *Settings, stats *Stats) *ServerHandler {
	return &ServerHandler{
		settings: s,
		stats:    stats,
		client: &http.Client{
			Transport: &http.Transport{
				DisableKeepAlives: true,
				DialContext:       (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			},
		},
	}
}

// LoginValidated reports whether client_login has succeeded this run.
func (h *ServerHandler) LoginValidated() bool { return h.loginValidated }

// --- URL construction (must match the server's parser byte-for-byte) ---

// statURL builds the unauthenticated server_stat URL.
func (h *ServerHandler) statURL() string {
	return ClientRPCProtocol + h.settings.RPCServerHost() + "/" + h.settings.RPCPath +
		"clientbuild=" + itoa(ClientBuild) + "&act=" + ActServerStat
}

// queryURL builds an authenticated URL for act+add.
//
//	clientbuild=178&act=<act>&add=<add>&cid=<id>&acttime=<time>&actkey=<sha1>
//
// add is inserted verbatim (never URL-encoded), matching the Java client.
func (h *ServerHandler) queryURL(act, add string) string {
	t := h.settings.ServerTime()
	key := actkey(act, add, h.settings.ClientID, t, h.settings.ClientKey)
	return ClientRPCProtocol + h.settings.RPCServerHost() + "/" + h.settings.RPCPath +
		fmt.Sprintf("clientbuild=%d&act=%s&add=%s&cid=%d&acttime=%d&actkey=%s",
			ClientBuild, act, add, h.settings.ClientID, t, key)
}

// --- core fetch ---

// fetch performs a GET, demands Content-Length, and enforces size caps. It is
// the single chokepoint for every outbound RPC, so size/length policy lives here.
func (h *ServerHandler) fetch(rawurl string, timeout time.Duration) (host, body string, err error) {
	host = hostOf(rawurl)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return host, "", err
	}
	req.Header.Set("Connection", "close")
	req.Header.Set("User-Agent", rpcUserAgent)

	Debug("rpc GET", "url", rawurl)
	resp, err := h.client.Do(req)
	if err != nil {
		return host, "", err
	}
	defer resp.Body.Close()

	if resp.ContentLength < 0 {
		// The server always sends Content-Length; a missing one means something
		// is wrong (or a firewall/PeerBlock is interfering). Abort.
		return host, "", errors.New("missing Content-Length")
	}
	if resp.ContentLength > maxRPCMemory {
		return host, "", fmt.Errorf("rpc reply %d bytes exceeds memory cap %d", resp.ContentLength, maxRPCMemory)
	}
	if resp.ContentLength > h.settings.MaxAllowedFile {
		return host, "", fmt.Errorf("rpc reply %d exceeds max allowed filesize %d", resp.ContentLength, h.settings.MaxAllowedFile)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, resp.ContentLength+1))
	if err != nil {
		return host, "", err
	}
	if int64(len(data)) != resp.ContentLength {
		return host, "", fmt.Errorf("short read: got %d want %d", len(data), resp.ContentLength)
	}
	return host, string(data), nil
}

// fetchFile downloads rawurl to dest via a temp file (atomic rename), with up
// to 3 retries. Used for get_cert (PKCS#12).
func (h *ServerHandler) fetchFile(rawurl, dest string, timeout time.Duration) error {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		err := func() error {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
			if err != nil {
				return err
			}
			req.Header.Set("Connection", "close")
			req.Header.Set("User-Agent", rpcUserAgent)
			resp, err := h.client.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.ContentLength <= 0 {
				return errors.New("missing Content-Length")
			}
			if resp.ContentLength > h.settings.MaxAllowedFile {
				return fmt.Errorf("file %d exceeds max %d", resp.ContentLength, h.settings.MaxAllowedFile)
			}
			tmp := dest + ".tmp"
			f, err := os.Create(tmp)
			if err != nil {
				return err
			}
			n, err := io.Copy(f, io.LimitReader(resp.Body, resp.ContentLength))
			f.Close()
			if err != nil {
				os.Remove(tmp)
				return err
			}
			if n != resp.ContentLength {
				os.Remove(tmp)
				return fmt.Errorf("short file read: got %d want %d", n, resp.ContentLength)
			}
			return os.Rename(tmp, dest)
		}()
		if err == nil {
			return nil
		}
		lastErr = err
		Warn("rpc file fetch failed; retrying", "attempt", attempt+1, "err", err)
	}
	return lastErr
}

// --- response parsing ---

// callAuthed performs an authenticated act with add="" and retries once on
// KEY_EXPIRED (re-synchronizing the clock first).
func (h *ServerHandler) callAuthed(act string) *ServerResponse {
	return h.callURL(h.queryURL(act, ""), act)
}

// callURL fetches and parses. When retryAct != "", a KEY_EXPIRED reply triggers
// a clock refresh (server_stat) and exactly one retry with a fresh acttime.
func (h *ServerHandler) callURL(rawurl, retryAct string) *ServerResponse {
	host, body, err := h.fetch(rawurl, 60*time.Second)
	if err != nil || body == "" {
		return &ServerResponse{Status: RespNull, FailCode: "NO_RESPONSE", FailHost: lower(host)}
	}
	Debug("received response", "body", body)

	lines := strings.Split(body, "\n")
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], "\r")
	}
	if len(lines) == 0 || lines[0] == "" {
		return &ServerResponse{Status: RespNull, FailCode: "NO_RESPONSE", FailHost: lower(host)}
	}

	switch first := lines[0]; {
	case strings.HasPrefix(first, "TEMPORARILY_UNAVAILABLE"):
		return &ServerResponse{Status: RespNull, FailCode: "TEMPORARILY_UNAVAILABLE", FailHost: lower(host)}
	case first == "OK":
		return &ServerResponse{Status: RespOK, Lines: lines[1:]}
	case first == "KEY_EXPIRED" && retryAct != "":
		Warn("server reported expired key; refreshing clock and retrying")
		h.RefreshServerStat()
		return h.callURL(h.queryURL(retryAct, ""), "") // retry exactly once
	default:
		return &ServerResponse{Status: RespFail, FailCode: first, FailHost: lower(host)}
	}
}

// noteNull marks RPC-server failure on NULL responses (failover).
func (h *ServerHandler) noteNull(sr *ServerResponse) {
	if sr.Status == RespNull {
		h.settings.MarkRPCServerFailure(sr.FailHost)
	}
}

// --- actions ---

// RefreshServerStat syncs the clock and min-build from the server.
func (h *ServerHandler) RefreshServerStat() bool {
	sr := h.callURL(h.statURL(), ActServerStat)
	h.noteNull(sr)
	if sr.Status == RespOK {
		h.settings.ApplySettings(sr.Lines)
		return true
	}
	return false
}

// LoadClientSettingsFromServer runs the startup server_stat + client_login
// handshake until validated. In headless/Docker mode invalid credentials are
// fatal (no interactive prompt).
func (h *ServerHandler) LoadClientSettingsFromServer() {
	for {
		if !h.RefreshServerStat() {
			dieErr("failed to get initial stat from server")
		}
		Info("reading client settings from server...")
		sr := h.callAuthed(ActClientLogin)
		switch sr.Status {
		case RespOK:
			h.loginValidated = true
			Info("applying settings...")
			h.settings.ApplySettings(sr.Lines)
			Info("finished applying settings")
			return
		case RespNull:
			dieErr("failed to get a login response from server")
		default:
			// auth failure. Headless: cannot prompt — surface and exit.
			Error("authentication failed", "code", sr.FailCode)
			dieErr("invalid Client ID/Key (code: " + sr.FailCode + "). Fix data/client_login and restart.")
		}
	}
}

// RefreshServerSettings pulls client_settings.
func (h *ServerHandler) RefreshServerSettings() bool {
	Info("refreshing client settings from server...")
	sr := h.callAuthed(ActClientSettings)
	h.noteNull(sr)
	if sr.Status == RespOK {
		h.settings.ApplySettings(sr.Lines)
		Info("finished applying settings")
		return true
	}
	Warn("failed to refresh settings")
	return false
}

// NotifyStart reports startup; returns false on connectivity failures.
func (h *ServerHandler) NotifyStart() bool {
	sr := h.callAuthed(ActClientStart)
	h.noteNull(sr)
	if sr.Status == RespOK {
		Info("start notification successful")
		if h.stats != nil {
			h.stats.ServerContact()
		}
		return true
	}
	fc := sr.FailCode
	Warn("startup failure", "code", fc)
	switch {
	case strings.HasPrefix(fc, "FAIL_CONNECT_TEST"):
		Error("external connectivity test failed; port not reachable from the internet",
			"port", h.settings.ClientPort)
	case strings.HasPrefix(fc, "FAIL_OTHER_CLIENT_CONNECTED"):
		dieErr("FAIL_OTHER_CLIENT_CONNECTED (one client per public IPv4)")
	case strings.HasPrefix(fc, "FAIL_CID_IN_USE"):
		dieErr("FAIL_CID_IN_USE (another client uses this Client ID; wait up to 24h or use a different ID)")
	}
	return false
}

// NotifySuspend / Resume / Stop are simple notifications.
func (h *ServerHandler) NotifySuspend() bool { return h.simpleNotify(ActClientSuspend, "Suspend") }
func (h *ServerHandler) NotifyResume() bool  { return h.simpleNotify(ActClientResume, "Resume") }
func (h *ServerHandler) NotifyStop() bool    { return h.simpleNotify(ActClientStop, "Stop") }

func (h *ServerHandler) simpleNotify(act, label string) bool {
	sr := h.callAuthed(act)
	h.noteNull(sr)
	if sr.Status == RespOK {
		Debug("notification successful", "kind", label)
		return true
	}
	Warn("notification failed", "kind", label)
	return false
}

// NotifyOverload is throttled to once per 30s.
func (h *ServerHandler) NotifyOverload() bool {
	now := time.Now()
	if h.lastOverload.Add(30 * time.Second).After(now) {
		return false
	}
	h.lastOverload = now
	return h.simpleNotify(ActOverload, "Overload")
}

// StillAlive runs the heartbeat. resume=true is sent after a suspend/resume.
func (h *ServerHandler) StillAlive(resume bool) bool {
	add := ""
	if resume {
		add = "resume"
	}
	sr := h.callURL(h.queryURL(ActStillAlive, add), "")
	h.noteNull(sr)
	switch sr.Status {
	case RespOK:
		Debug("stillAlive successful")
		if h.stats != nil {
			h.stats.ServerContact()
		}
		return true
	case RespNull:
		Warn("failed to contact server for stillAlive (temporary?)")
	case RespFail:
		if strings.HasPrefix(sr.FailCode, "TERM_BAD_NETWORK") {
			dieErr("network misconfigured; correct firewall/forwarding then restart")
		}
		Warn("stillAlive failed", "code", sr.FailCode)
	}
	return false
}

// GetBlacklist fetches the file blacklist newer than deltatime seconds.
func (h *ServerHandler) GetBlacklist(deltatime int64) []string {
	sr := h.callURL(h.queryURL(ActGetBlacklist, fmt.Sprintf("%d", deltatime)), "")
	h.noteNull(sr)
	if sr.Status == RespOK {
		return sr.Lines
	}
	return nil
}

// GetStaticRangeFetchURL asks the server for source URLs to fetch a missing
// static-range file.
func (h *ServerHandler) GetStaticRangeFetchURL(fileindex, xres, fileid string) []string {
	sr := h.callURL(h.queryURL(ActStaticRangeFetch, fileindex+";"+xres+";"+fileid), "")
	h.noteNull(sr)
	if sr.Status == RespOK {
		var urls []string
		for _, l := range sr.Lines {
			if l != "" {
				urls = append(urls, l)
			}
		}
		return urls
	}
	Info("failed to request static range download link", "fileid", fileid)
	return nil
}

// GetDownloaderFetchURL fetches a gallery download URL.
func (h *ServerHandler) GetDownloaderFetchURL(gid, page, fileindex int, xres string, fileretry int) string {
	add := fmt.Sprintf("%d;%d;%d;%s;%d", gid, page, fileindex, xres, fileretry)
	sr := h.callURL(h.queryURL(ActDownloaderFetch, add), "")
	h.noteNull(sr)
	if sr.Status == RespOK && len(sr.Lines) > 0 {
		return sr.Lines[0]
	}
	Info("failed to request gallery file url", "fileindex", fileindex)
	return ""
}

// ReportDownloaderFailures reports up to 50 distinct download failures.
func (h *ServerHandler) ReportDownloaderFailures(failures []string) {
	if len(failures) < 1 || len(failures) > 50 {
		return
	}
	sr := h.callURL(h.queryURL(ActDownloaderFailRep, strings.Join(failures, ";")), "")
	h.noteNull(sr)
	Debug("reported download failures", "count", len(failures), "status", sr.Status == RespOK)
}

// GetCertificate downloads the PKCS#12 cert to dest.
func (h *ServerHandler) GetCertificate(dest string) error {
	return h.fetchFile(h.queryURL(ActGetCertificate, ""), dest, 300*time.Second)
}

// FetchQueue hits the gallery download queue (/15/dl? act=fetchqueue). add is
// "<gid>;<minxres>" when marking the previous gallery done, or "".
func (h *ServerHandler) FetchQueue(add string) string {
	t := h.settings.ServerTime()
	key := actkey("fetchqueue", add, h.settings.ClientID, t, h.settings.ClientKey)
	rawurl := ClientRPCProtocol + h.settings.RPCServerHost() + "/15/dl?" +
		fmt.Sprintf("clientbuild=%d&act=fetchqueue&add=%s&cid=%d&acttime=%d&actkey=%s",
			ClientBuild, add, h.settings.ClientID, t, key)
	_, body, err := h.fetch(rawurl, 30*time.Second)
	if err != nil {
		return ""
	}
	return body
}

// originClient builds an HTTP client for fetching from origin servers / other
// H@H nodes, honoring the optional image proxy (HTTP or SOCKS).
func (h *ServerHandler) originClient(allowProxy bool) *http.Client {
	c := &http.Client{Timeout: 5 * time.Minute}
	if !allowProxy || h.settings.ImageProxyHost == "" {
		return c
	}
	switch h.settings.ImageProxyType {
	case "http", "https":
		proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%d", h.settings.ImageProxyHost, imageProxyPortOrDefault(h.settings)))
		if err == nil {
			c.Transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
		}
	case "socks":
		dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("%s:%d", h.settings.ImageProxyHost, imageProxyPortOrDefault(h.settings)), nil, proxy.Direct)
		if err == nil {
			c.Transport = &http.Transport{Dial: dialer.Dial}
		}
	}
	return c
}

func imageProxyPortOrDefault(s *Settings) int {
	if s.ImageProxyPort != 0 {
		return s.ImageProxyPort
	}
	if s.ImageProxyType == "http" {
		return 8080
	}
	return 1080
}

// DownloadToFile fetches rawurl to dest (atomic temp+rename), enforcing size
// caps and optional bandwidth limiting. Hath-Request is sent when isHath is
// true (proxy fetches from other clients).
func (h *ServerHandler) DownloadToFile(rawurl, dest string, timeout time.Duration, allowProxy, isHath bool, limiter *BandwidthMonitor, fileid string) (int64, error) {
	cl := h.originClient(allowProxy)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Connection", "close")
	req.Header.Set("User-Agent", rpcUserAgent)
	if isHath {
		req.Header.Set("Hath-Request", fmt.Sprintf("%d-%s", h.settings.ClientID, sha1Hex(h.settings.ClientKey+fileid)))
	}
	resp, err := cl.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.ContentLength < 0 {
		return 0, errors.New("missing Content-Length")
	}
	if resp.ContentLength > h.settings.MaxAllowedFile {
		return 0, fmt.Errorf("file %d exceeds max %d", resp.ContentLength, h.settings.MaxAllowedFile)
	}
	tmp := dest + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return 0, err
	}
	var r io.Reader = resp.Body
	if limiter != nil {
		r = &limitReader{r: resp.Body, lim: limiter}
	}
	n, err := io.Copy(f, r)
	f.Close()
	if err != nil {
		os.Remove(tmp)
		return n, err
	}
	if resp.ContentLength > 0 && n != resp.ContentLength {
		os.Remove(tmp)
		return n, fmt.Errorf("short read: got %d want %d", n, resp.ContentLength)
	}
	return n, os.Rename(tmp, dest)
}

// limitReader applies BandwidthMonitor throttling to a read stream.
type limitReader struct {
	r   io.Reader
	lim *BandwidthMonitor
}

func (l *limitReader) Read(p []byte) (int, error) {
	n, err := l.r.Read(p)
	if n > 0 {
		l.lim.WaitForQuota(n)
	}
	return n, err
}

// --- helpers ---

func hostOf(rawurl string) string {
	u, err := url.Parse(rawurl)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func lower(s string) string { return strings.ToLower(s) }
func itoa(i int) string     { return fmt.Sprintf("%d", i) }
