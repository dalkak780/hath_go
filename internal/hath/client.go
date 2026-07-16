package hath

// HathClient orchestrates startup, the periodic main loop, and shutdown. It is
// the Go counterpart of HentaiAtHomeClient.

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// HathClient ties the subsystems together.
var certRefreshSleep = 5 * time.Second // overridable in tests to skip the real delay

type HathClient struct {
	stateMu  sync.Mutex
	settings *Settings
	stats    *Stats
	rpc      *ServerHandler
	cache    *CacheHandler
	cert     *CertManager
	server   *HTTPServer

	suspendedUntil  time.Time
	doCertRefresh   bool
	counter         int
	shutdown        bool
	gallery         *GalleryDownloader
	serverErr       chan error
	startupComplete bool
}

// NewHathClient builds a client with the given settings/stats.
func NewHathClient(s *Settings, stats *Stats) *HathClient {
	return &HathClient{settings: s, stats: stats}
}

// TriggerRefreshSettings handles a servercmd refresh_settings.
func (c *HathClient) TriggerRefreshSettings() { c.rpc.RefreshServerSettings() }

// TriggerCertRefresh schedules a TLS restart to pick up a fresh cert.
func (c *HathClient) TriggerCertRefresh() {
	c.stateMu.Lock()
	c.doCertRefresh = true
	c.stateMu.Unlock()
}

// Run performs startup then the periodic loop until ctx is cancelled.
func (c *HathClient) Run(ctx context.Context) error {
	c.stats.ResetStats()
	c.stats.SetProgramStatus("Logging in to main server...")

	// credentials: file first, then env (handy for first-run Docker).
	if err := c.settings.LoadLogin(); err != nil {
		c.applyLoginEnv()
	}
	if !c.settings.LoginValid() {
		c.applyLoginEnv()
	}
	if !c.settings.LoginValid() {
		dieErr("no valid Client ID/Key. Put '<id>-<key>' in data/client_login or set HATH_CLIENT_ID/HATH_CLIENT_KEY.")
	}
	if err := c.settings.SaveLogin(); err != nil {
		Warn("could not persist client_login", "err", err)
	}

	Info("connecting to H@H server to register client", "id", c.settings.ClientID)
	c.rpc = NewServerHandler(c.settings, c.stats)
	c.rpc.LoadClientSettingsFromServer()

	c.stats.SetProgramStatus("Initializing cache handler...")
	cache, err := NewCacheHandler(c)
	if err != nil {
		return err
	}
	c.cache = cache

	c.stats.SetProgramStatus("Starting HTTP server...")
	if err := c.startServer(); err != nil {
		return err
	}

	c.stats.SetProgramStatus("Sending startup notification...")
	Info("notifying server that the client is up...")
	if !c.rpc.NotifyStart() {
		c.doShutdown()
		return errf("startup notification failed (connectivity test?)")
	}
	c.startupComplete = true
	c.server.AllowNormalConnections()

	if c.settings.WarnNewClient {
		Warn("a new client version is available; see http://hentaiathome.net/")
	}
	if c.cache.CacheCount() < 1 {
		Info("cache is empty; expect little traffic for a while")
	}

	c.rpc.RefreshServerSettings()
	c.stats.ResetStats() // resetBytesSentHistory equivalent
	c.stats.ProgramStarted()
	c.cache.ProcessBlacklist(c.rpc, 259200)

	Info("startup completed; normal operation")

	// honor SIGINT/SIGTERM in addition to ctx
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	cancelCtx, cancel := watchSignals(sigCh, ctx)
	defer cancel()

	var lastThreadTime time.Duration
	for !c.IsShuttingDown() {
		select {
		case <-cancelCtx.Done():
			c.doShutdown()
			return nil
		case err := <-c.serverErr:
			c.doShutdown()
			return errf("HTTP listener terminated: %v", err)
		default:
		}

		sleep := time.Duration(10000 - lastThreadTime.Milliseconds())
		if sleep < 1000 {
			sleep = 1000
		}
		select {
		case <-cancelCtx.Done():
			c.doShutdown()
			return nil
		case err := <-c.serverErr:
			c.doShutdown()
			return errf("HTTP listener terminated: %v", err)
		case <-time.After(sleep):
		}

		start := time.Now()
		c.cycle()

		c.counter++
		lastThreadTime = time.Since(start)
	}
	return nil
}

// cycle runs one pass of scheduled tasks (mirrors HentaiAtHomeClient.run loop).
func (c *HathClient) cycle() {
	now := time.Now()
	c.stateMu.Lock()
	suspendedUntil := c.suspendedUntil
	refresh := c.doCertRefresh
	c.stateMu.Unlock()
	if !suspendedUntil.IsZero() && suspendedUntil.After(now) {
		return
	}
	if !suspendedUntil.IsZero() && suspendedUntil.Before(now) {
		c.stateMu.Lock()
		c.suspendedUntil = time.Time{}
		c.stateMu.Unlock()
		c.rpc.NotifyResume()
	}

	if refresh {
		if c.refreshCerts() {
			c.stateMu.Lock()
			c.doCertRefresh = false
			c.stateMu.Unlock()
		}
		return
	}

	if c.counter%11 == 0 {
		c.rpc.StillAlive(false)
	}
	if c.counter%30 == 1 {
		if abs64(c.settings.ServerTimeDelta()) > 86400 {
			Warn("system time appears off by more than 24h")
		}
		if c.server.CertExpired() {
			dieErr("certificate expired or clock wrong; check system clock and restart")
		}
	}
	if c.counter%6 == 2 {
		c.server.PruneFloodControl()
	}
	if c.counter%1440 == 1439 {
		c.settings.ClearRPCServerFailure()
	}
	if c.counter%2160 == 2159 {
		c.cache.ProcessBlacklist(c.rpc, 43200)
	}

	c.cache.CycleLRUCacheTable()
	c.stats.ShiftBytesSentHistory()
}

// watchSignals returns a context cancelled when sigCh fires or ctx is
// cancelled. Extracted from Run so the cancellation logic is unit-testable
// (OS signals themselves cannot be delivered deterministically in a test).
// (OS signals themselves cannot be delivered deterministically in a test).
func watchSignals(sigCh <-chan os.Signal, ctx context.Context) (context.Context, context.CancelFunc) {
	cancelCtx, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-sigCh:
			cancel()
		case <-cancelCtx.Done():
		}
	}()
	return cancelCtx, cancel
}

// startServer fetches the cert and binds the TLS listener synchronously.
func (c *HathClient) startServer() error {
	c.cert = &CertManager{settings: c.settings}
	if err := c.cert.LoadOrRefresh(c.rpc); err != nil {
		return err
	}
	c.server = NewHTTPServer(c.settings, c.cache, c.rpc, c.stats, c.cert, c)
	if err := c.server.Start(); err != nil {
		return err
	}
	c.serverErr = make(chan error, 1)
	go func(server *HTTPServer) {
		if err := <-server.Done(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			c.serverErr <- err
		}
	}(c.server)
	return nil
}

// refreshCerts restarts the TLS server with a freshly fetched certificate.
func (c *HathClient) refreshCerts() bool {
	Info("internal restart of HTTP server to refresh certs")
	if !c.rpc.NotifySuspend() {
		Warn("failed to suspend for cert refresh; will retry")
		return false
	}
	time.Sleep(certRefreshSleep)
	if err := c.cert.LoadOrRefresh(c.rpc); err != nil {
		Error("cert refresh failed", "err", err)
		c.rpc.StillAlive(true) // undo server-side suspension; old TLS listener is healthy
		return false
	}
	// TLSConfig.GetCertificate reads the validated certificate dynamically, so
	// the working listener never needs to be torn down during rotation.
	c.rpc.StillAlive(true)
	Info("internal HTTP server certificate refreshed")
	return true
}

func (c *HathClient) doShutdown() {
	c.requestShutdown()
	Info("shutting down...")
	if c.startupComplete {
		c.rpc.NotifyStop()
	}
	if c.server != nil {
		c.server.Shutdown()
	}
	if c.cache != nil && c.cache.pruner != nil {
		c.cache.pruner.stop()
	}
	if c.cache != nil {
		c.cache.TerminateCache()
	}
}

func (c *HathClient) requestShutdown() {
	c.stateMu.Lock()
	c.shutdown = true
	c.stateMu.Unlock()
}

// IsShuttingDown reports whether shutdown has been requested.
func (c *HathClient) IsShuttingDown() bool {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.shutdown
}

// IsSuspended reports whether the master thread is currently suspended.
func (c *HathClient) IsSuspended() bool {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return !c.suspendedUntil.IsZero() && c.suspendedUntil.After(time.Now())
}

// StartDownloader launches the gallery downloader (servercmd start_downloader).
func (c *HathClient) StartDownloader() {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.gallery == nil {
		c.gallery = newGalleryDownloader(c)
		go c.gallery.loop()
	}
}

func (c *HathClient) galleryDone(g *GalleryDownloader) {
	c.stateMu.Lock()
	if c.gallery == g {
		c.gallery = nil
	}
	c.stateMu.Unlock()
}

func (c *HathClient) applyLoginEnv() {
	if v := os.Getenv("HATH_CLIENT_ID"); v != "" {
		c.settings.ClientID = atoi(v)
	}
	if v := os.Getenv("HATH_CLIENT_KEY"); v != "" {
		c.settings.ClientKey = v
	}
}
