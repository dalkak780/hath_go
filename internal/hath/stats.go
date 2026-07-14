package hath

import (
	"sync"
	"time"
)

// Stats tracks runtime counters. A direct, mutex-guarded port of the original
// Stats; the GUI/stat-listener plumbing is dropped (headless-only).
type Stats struct {
	mu               sync.Mutex
	clientRunning    bool
	clientSuspended  bool
	programStatus    string
	clientStartTime  time.Time
	lastServerContact time.Time
	filesSent        int64
	filesRcvd        int64
	bytesSent        int64
	bytesRcvd        int64
	cacheCount       int
	cacheSize        int64
	bytesSentHistory []int
	openConnections  int
}

func NewStats() *Stats {
	s := &Stats{programStatus: "Stopped", bytesSentHistory: make([]int, 361)}
	return s
}

func (s *Stats) SetProgramStatus(v string) {
	s.mu.Lock()
	s.programStatus = v
	s.mu.Unlock()
}

func (s *Stats) ProgramStatus() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.programStatus
}

func (s *Stats) ResetStats() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clientRunning = false
	s.programStatus = "Stopped"
	s.filesSent, s.filesRcvd, s.bytesSent, s.bytesRcvd = 0, 0, 0, 0
	s.cacheCount, s.cacheSize = 0, 0
	for i := range s.bytesSentHistory {
		s.bytesSentHistory[i] = 0
	}
}

func (s *Stats) ProgramStarted() {
	s.mu.Lock()
	s.clientStartTime = time.Now()
	s.clientRunning = true
	s.programStatus = "Running"
	s.mu.Unlock()
}

func (s *Stats) ServerContact() {
	s.mu.Lock()
	s.lastServerContact = time.Now()
	s.mu.Unlock()
}

func (s *Stats) FileSent() {
	s.mu.Lock()
	s.filesSent++
	s.mu.Unlock()
}

func (s *Stats) FileRcvd() {
	s.mu.Lock()
	s.filesRcvd++
	s.mu.Unlock()
}

func (s *Stats) BytesSent(b int64) {
	s.mu.Lock()
	if s.clientRunning {
		s.bytesSent += b
		if len(s.bytesSentHistory) > 0 {
			s.bytesSentHistory[0] += int(b)
		}
	}
	s.mu.Unlock()
}

func (s *Stats) BytesRcvd(b int64) {
	s.mu.Lock()
	if s.clientRunning {
		s.bytesRcvd += b
	}
	s.mu.Unlock()
}

func (s *Stats) SetCacheCount(c int) {
	s.mu.Lock()
	s.cacheCount = c
	s.mu.Unlock()
}

func (s *Stats) SetCacheSize(sz int64) {
	s.mu.Lock()
	s.cacheSize = sz
	s.mu.Unlock()
}

func (s *Stats) SetOpenConnections(c int) {
	s.mu.Lock()
	s.openConnections = c
	s.mu.Unlock()
}

func (s *Stats) OpenConnections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.openConnections
}

// ShiftBytesSentHistory rolls the per-10s history window (called each cycle).
func (s *Stats) ShiftBytesSentHistory() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := 360; i > 0; i-- {
		s.bytesSentHistory[i] = s.bytesSentHistory[i-1]
	}
	s.bytesSentHistory[0] = 0
}
