package hath

// CachePruner is a faithful port of the original CachePruner thread. It wakes
// every second, aggressively prunes when the cache exceeds its limit, otherwise
// runs a prune at the current cadence, and watches free disk space — shutting
// the client down if the device drops below the safety threshold.

import (
	"sync/atomic"
	"time"
)

// CachePruner runs the prune/disk-watch loop in its own goroutine.
type CachePruner struct {
	cache   *CacheHandler
	client  *HathClient
	freq    atomic.Int64 // seconds between periodic checks
	diskInt int          // ticks between free-disk watchdogs (0 = every tick)
	stopCh  chan struct{}
}

// diskCheckTicks is the number of 1s ticks between free-disk watchdogs.
// Kept as a field (default 300s, matching the original) so tests can tighten it.
const defaultDiskCheckTicks = 300

func newCachePruner(cache *CacheHandler, client *HathClient) *CachePruner {
	p := &CachePruner{
		cache:  cache,
		client: client,
		diskInt: defaultDiskCheckTicks,
		stopCh: make(chan struct{}),
	}
	p.freq.Store(60)
	go p.loop()
	return p
}

func (p *CachePruner) setCheckFrequency(secs int) {
	if p == nil {
		return
	}
	p.freq.Store(int64(secs))
}

func (p *CachePruner) loop() {
	cacheCheckTicks := 0
	diskCheckTicks := 0
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			Debug("cache handler: pruner thread exited")
			return
		case <-ticker.C:
		}

		// A panic in cache maintenance must not take down the whole node; log
		// it and let the loop continue. Disk-full is a deliberate fatal exit via
		// dieErr (not a panic), so it still stops the process.
		func() {
			defer func() {
				if r := recover(); r != nil {
					Error("cache pruner panicked; continuing", "err", r)
				}
			}()

			cacheLimit := p.cache.settings.DiskLimit
		cacheSize := p.cache.CacheSizeWithOverhead()

		if cacheSize > cacheLimit {
			Info("cache handler: cache over limit, pruning aggressively",
				"pctOver", 100.0*float64(cacheSize)/float64(cacheLimit)-100.0)
			p.cache.CheckAndPruneCache()
			return
		}

		cacheCheckTicks++
		if cacheCheckTicks > int(p.freq.Load()) {
			p.cache.CheckAndPruneCache()
			cacheCheckTicks = 0
		}

		diskCheckTicks++
		if diskCheckTicks > p.diskInt {
			if !p.cache.HasFreeDiskSpace() {
				dieErr("free disk space dropped below the minimum threshold; free space or reduce cache size at https://e-hentai.org/hentaiathome.php?cid=" +
					itoa(p.cache.settings.ClientID))
			}
			diskCheckTicks = 0
		}
		}()
	}
}

// stop ends the pruner loop (called on shutdown).
func (p *CachePruner) stop() {
	if p != nil {
		select {
		case <-p.stopCh:
		default:
			close(p.stopCh)
		}
	}
}
