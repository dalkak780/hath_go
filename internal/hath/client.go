package hath

// HathClient orchestrates startup, the periodic main loop, and shutdown. It is
// the Go counterpart of HentaiAtHomeClient.

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// HathClient ties the subsystems together.
type HathClient struct {
	settings *Settings
	stats    *Stats
	rpc      *ServerHandler
	cache    *CacheHandler
	cert     *CertManager
	server   *HTTPServer

	suspendedUntil time.Time
	doCertRefresh  bool
	counter        int
	shutdown       bool
}

// NewHathClient builds a client with the given settings/stats.
func NewHathClient(s *Settings, stats *Stats) *HathClient {
	return &HathClient{settings: s, stats: stats}
}

// TriggerRefreshSettings handles a servercmd refresh_settings.
func (c *HathClient) TriggerRefreshSettings() { c.rpc.RefreshServerSettings() }

// TriggerCertRefresh schedules a TLS restart to pick up a fresh cert.
func (c *HathClient) TriggerCertRefresh() { c.doCertRefresh = true }

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
	cache, err := NewCacheHandler(c.settings, c.stats)
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
		return errf("startup notification failed (connectivity test?)")
	}
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
	cancelCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-sigCh:
			cancel()
		case <-cancelCtx.Done():
		}
	}()

	var lastThreadTime time.Duration
	for !c.shutdown {
		select {
		case <-cancelCtx.Done():
			c.doShutdown()
			return nil
		default:
		}

		sleep := time.Duration(10000-lastThreadTime.Milliseconds())
		if sleep < 1000 {
			sleep = 1000
		}
		select {
		case <-cancelCtx.Done():
			c.doShutdown()
			return nil
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
	if !c.suspendedUntil.IsZero() && c.suspendedUntil.After(now) {
		return
	}
	if !c.suspendedUntil.IsZero() && c.suspendedUntil.Before(now) {
		c.suspendedUntil = time.Time{}
		c.rpc.NotifyResume()
	}

	if c.doCertRefresh {
		c.refreshCerts()
		c.doCertRefresh = false
		return
	}

	if c.counter%11 == 0 {
		c.rpc.StillAlive(false)
	}
	if c.counter%30 == 1 {
		if abs64(c.settings.serverTimeDelta) > 86400 {
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

// startServer fetches the cert and starts the TLS server in a goroutine.
func (c *HathClient) startServer() error {
	c.cert = &CertManager{settings: c.settings}
	if err := c.cert.LoadOrRefresh(c.rpc); err != nil {
		return err
	}
	c.server = NewHTTPServer(c.settings, c.cache, c.rpc, c.stats, c.cert, c)
	go func() {
		if err := c.server.Start(); err != nil {
			Error("http server exited", "err", err)
		}
	}()
	// give the listener a moment to bind / surface errors
	time.Sleep(200 * time.Millisecond)
	return nil
}

// refreshCerts restarts the TLS server with a freshly fetched certificate.
func (c *HathClient) refreshCerts() {
	Info("internal restart of HTTP server to refresh certs")
	if !c.rpc.NotifySuspend() {
		Warn("failed to suspend for cert refresh; will retry")
		return
	}
	time.Sleep(5 * time.Second)
	c.server.Shutdown()
	if err := c.cert.LoadOrRefresh(c.rpc); err != nil {
		Error("cert refresh failed", "err", err)
		return
	}
	// spin up a new server with the fresh cert
	c.server = NewHTTPServer(c.settings, c.cache, c.rpc, c.stats, c.cert, c)
	go func() {
		if err := c.server.Start(); err != nil {
			Error("http server exited on restart", "err", err)
		}
	}()
	c.server.AllowNormalConnections()
	c.rpc.StillAlive(true)
	Info("internal HTTP server restarted")
}

func (c *HathClient) doShutdown() {
	c.shutdown = true
	Info("shutting down...")
	c.rpc.NotifyStop()
	if c.server != nil {
		c.server.Shutdown()
	}
	if c.cache != nil {
		c.cache.TerminateCache()
	}
}

func (c *HathClient) applyLoginEnv() {
	if v := os.Getenv("HATH_CLIENT_ID"); v != "" {
		c.settings.ClientID = atoi(v)
	}
	if v := os.Getenv("HATH_CLIENT_KEY"); v != "" {
		c.settings.ClientKey = v
	}
}
