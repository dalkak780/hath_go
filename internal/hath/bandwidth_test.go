package hath

import (
	"testing"
	"time"
)

func TestBandwidthGrantsUnderLimit(t *testing.T) {
	bwm := NewBandwidthMonitor(1 << 20) // 1 MiB/s
	start := time.Now()
	bwm.WaitForQuota(1000)
	if time.Since(start) > 100*time.Millisecond {
		t.Fatalf("small quota should not sleep: %v", time.Since(start))
	}
}

func TestBandwidthThrottlesOverLimit(t *testing.T) {
	// 100 B/s → ~2 B per 20ms tick. A tight burst must eventually engage the
	// 10ms sleep path (the algorithm blocks once the tick budget is exceeded).
	bwm := NewBandwidthMonitor(100)
	start := time.Now()
	for i := 0; i < 50; i++ {
		bwm.WaitForQuota(2)
	}
	// 50 grants of 2B = 100B into a ~2B/tick budget → many 10ms sleeps expected
	if time.Since(start) < 40*time.Millisecond {
		t.Fatalf("expected throttling to engage; elapsed only %v", time.Since(start))
	}
}
