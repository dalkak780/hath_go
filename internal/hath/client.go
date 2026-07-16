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
var certRestartSleep = time.Second

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
	shutdownOnce    sync.Once
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
	activeClient.Store(c)
	defer activeClient.CompareAndSwap(c, nil)
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
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	cancelCtx, cancel := watchSignals(sigCh, ctx)
	defer cancel()
	if !c.rpc.NotifyStart() {
		Warn("startup notification failed; listener remains available for diagnostics")
		select {
		case <-cancelCtx.Done():
			c.doShutdown()
			return nil
		case err := <-c.serverErr:
			c.doShutdown()
			return errf("HTTP listener terminated after startup failure: %v", err)
		}
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
	c.counter = 1

	Info("startup completed; normal operation")

	var lastThreadTime time.Duration
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()
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
		timer.Reset(sleep)
		select {
		case <-cancelCtx.Done():
			c.doShutdown()
			return nil
		case err := <-c.serverErr:
			c.doShutdown()
			return errf("HTTP listener terminated: %v", err)
		case <-timer.C:
		}

		start := time.Now()
		c.cycle()
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
		c.counter = 0
		c.stateMu.Unlock()
		c.stats.ProgramResumed()
		c.rpc.NotifyResume()
	}

	if refresh {
		if c.refreshCerts() {
			c.stateMu.Lock()
			c.doCertRefresh = false
			c.stateMu.Unlock()
		}
	} else if c.counter%11 == 0 {
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
	c.counter++
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
	c.watchServer(c.server)
	return nil
}

func (c *HathClient) watchServer(server *HTTPServer) {
	done := make(chan error, 1)
	c.serverErr = done
	go func(server *HTTPServer) {
		if err := <-server.Done(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			done <- err
		}
	}(server)
}

// refreshCerts restarts the TLS server with a freshly fetched certificate.
func (c *HathClient) refreshCerts() bool {
	Info("internal restart of HTTP server to refresh certs")
	if !c.rpc.NotifySuspend() {
		Warn("failed to suspend for cert refresh; will retry")
		return false
	}
	time.Sleep(certRefreshSleep)
	c.server.Shutdown()
	time.Sleep(certRestartSleep)
	if err := c.cert.LoadOrRefresh(c.rpc); err != nil {
		dieErr("failed to reinitialize HTTPServer certificate: " + err.Error())
		return false
	}
	server := NewHTTPServer(c.settings, c.cache, c.rpc, c.stats, c.cert, c)
	if err := server.Start(); err != nil {
		dieErr("failed to reinitialize HTTPServer: " + err.Error())
		return false
	}
	server.AllowNormalConnections()
	c.server = server
	c.watchServer(server)
	c.rpc.StillAlive(true)
	Info("internal HTTP server was successfully restarted")
	return true
}

func (c *HathClient) doShutdown() {
	c.shutdownOnce.Do(func() {
		c.requestShutdown()
		Info("shutting down...")
		if c.startupComplete && c.rpc != nil {
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
	})
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

// Suspend pauses the master cycle for 1..86400 seconds and notifies the RPC
// server, matching ClientAPI.clientSuspend in the Java client.
func (c *HathClient) Suspend(seconds int) bool {
	c.stateMu.Lock()
	if seconds < 1 || seconds > 86400 || c.suspendedUntil.After(time.Now()) {
		c.stateMu.Unlock()
		return false
	}
	c.suspendedUntil = time.Now().Add(time.Duration(seconds) * time.Second)
	c.stateMu.Unlock()
	c.stats.ProgramSuspended()
	return c.rpc.NotifySuspend()
}

// Resume immediately resumes the master cycle and notifies the RPC server.
func (c *HathClient) Resume() bool {
	c.stateMu.Lock()
	c.suspendedUntil = time.Time{}
	c.counter = 0
	c.stateMu.Unlock()
	c.stats.ProgramResumed()
	return c.rpc.NotifyResume()
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
