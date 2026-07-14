package hath

// BandwidthMonitor is a direct port of HTTPBandwidthMonitor: a 50-tick
// sliding window over one second that throttles outbound writes for non-local
// traffic. It puts the calling goroutine to sleep in 10ms increments when the
// configured throttle would be exceeded.

import (
	"sync"
	"time"
)

const (
	bwmTicks = 50
	bwmWindow = 5
)

// BandwidthMonitor throttles bandwidth to settings.ThrottleBytes per second.
type BandwidthMonitor struct {
	millisPerTick int64
	bytesPerTick  int64

	mu          sync.Mutex
	tickBytes   []int64
	tickSeconds []int64
}

// NewBandwidthMonitor builds a limiter for bytesPerSec.
func NewBandwidthMonitor(bytesPerSec int64) *BandwidthMonitor {
	bpt := (bytesPerSec + bwmTicks - 1) / bwmTicks // ceil
	return &BandwidthMonitor{
		millisPerTick: 1000 / bwmTicks,
		bytesPerTick:  bpt,
		tickBytes:     make([]int64, bwmTicks),
		tickSeconds:   make([]int64, bwmTicks),
	}
}

// WaitForQuota blocks until bytecount may be sent without exceeding the limit.
func (b *BandwidthMonitor) WaitForQuota(bytecount int) {
	for {
		b.mu.Lock()
		now := time.Now().UnixMilli()
		epochSeconds := now / 1000
		currentTick := int((now - epochSeconds*1000) / b.millisPerTick)
		currentSecond := int(epochSeconds)

		var bytesThisTick, bytesLastWindow, bytesLastSecond int64
		for tickCounter := currentTick - bwmTicks; tickCounter < currentTick; tickCounter++ {
			tickIndex := tickCounter
			validSecond := currentSecond
			if tickCounter < 0 {
				tickIndex = bwmTicks + tickCounter
				validSecond = currentSecond - 1
			}
			if b.tickSeconds[tickIndex] == int64(validSecond) {
				if tickCounter >= currentTick-bwmWindow {
					bytesLastWindow += b.tickBytes[tickIndex]
				}
				bytesLastSecond += b.tickBytes[tickIndex]
			}
		}
		if b.tickSeconds[currentTick] == int64(currentSecond) {
			bytesThisTick = b.tickBytes[currentTick]
		}

		// over-budget? sleep and re-evaluate.
		if bytesThisTick > int64(float64(b.bytesPerTick)*1.1) ||
			bytesLastWindow > int64(float64(b.bytesPerTick*bwmWindow)*1.05) ||
			bytesLastSecond > b.bytesPerTick*bwmTicks {
			b.mu.Unlock()
			time.Sleep(10 * time.Millisecond)
			continue
		}

		if b.tickSeconds[currentTick] != int64(currentSecond) {
			b.tickSeconds[currentTick] = int64(currentSecond)
			b.tickBytes[currentTick] = 0
		}
		b.tickBytes[currentTick] += int64(bytecount)
		b.mu.Unlock()
		return
	}
}
