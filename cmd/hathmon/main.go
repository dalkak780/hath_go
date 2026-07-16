// Command hathmon records lightweight Linux process metrics and periodically
// captures Go CPU and heap profiles from a private pprof endpoint.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type sample struct {
	Time       time.Time `json:"time"`
	CPUPercent float64   `json:"cpu_percent"`
	RSSBytes   int64     `json:"rss_bytes"`
	VMBytes    int64     `json:"vm_bytes"`
	Threads    int64     `json:"threads"`
	FDs        int       `json:"fds"`
	ReadBytes  int64     `json:"read_bytes"`
	WriteBytes int64     `json:"write_bytes"`
}

type procReading struct {
	runtimeNS  int64
	rssBytes   int64
	vmBytes    int64
	threads    int64
	fds        int
	readBytes  int64
	writeBytes int64
}

type config struct {
	pid          int
	dir          string
	pprofURL     string
	interval     time.Duration
	heapInterval time.Duration
	cpuInterval  time.Duration
	cpuDuration  time.Duration
	retention    time.Duration
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := os.MkdirAll(cfg.dir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func loadConfig() (config, error) {
	c := config{pid: 1, dir: "/profiles", pprofURL: "http://127.0.0.1:6060", interval: time.Minute, heapInterval: time.Hour, cpuInterval: 6 * time.Hour, cpuDuration: time.Minute, retention: 7 * 24 * time.Hour}
	if v := os.Getenv("HATHMON_TARGET_PID"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return c, fmt.Errorf("invalid HATHMON_TARGET_PID %q", v)
		}
		c.pid = n
	}
	if v := os.Getenv("HATHMON_OUTPUT_DIR"); v != "" {
		c.dir = v
	}
	if v := os.Getenv("HATHMON_PPROF_URL"); v != "" {
		c.pprofURL = strings.TrimRight(v, "/")
	}
	for name, dst := range map[string]*time.Duration{
		"HATHMON_INTERVAL":      &c.interval,
		"HATHMON_HEAP_INTERVAL": &c.heapInterval,
		"HATHMON_CPU_INTERVAL":  &c.cpuInterval,
		"HATHMON_CPU_DURATION":  &c.cpuDuration,
		"HATHMON_RETENTION":     &c.retention,
	} {
		if v := os.Getenv(name); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil || d <= 0 {
				return c, fmt.Errorf("invalid %s %q", name, v)
			}
			*dst = d
		}
	}
	return c, nil
}

func run(ctx context.Context, cfg config) error {
	previous, err := readProc(cfg.pid)
	if err != nil {
		return fmt.Errorf("read target process %d: %w", cfg.pid, err)
	}
	previousAt := time.Now()
	metrics := time.NewTicker(cfg.interval)
	heap := time.NewTicker(cfg.heapInterval)
	cpu := time.NewTicker(cfg.cpuInterval)
	cleanup := time.NewTicker(time.Hour)
	defer metrics.Stop()
	defer heap.Stop()
	defer cpu.Stop()
	defer cleanup.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-metrics.C:
			current, err := readProc(cfg.pid)
			if err != nil {
				return fmt.Errorf("read target process %d: %w", cfg.pid, err)
			}
			elapsed := now.Sub(previousAt)
			value := sample{Time: now, RSSBytes: current.rssBytes, VMBytes: current.vmBytes, Threads: current.threads, FDs: current.fds, ReadBytes: current.readBytes, WriteBytes: current.writeBytes}
			if elapsed > 0 && current.runtimeNS >= previous.runtimeNS {
				value.CPUPercent = float64(current.runtimeNS-previous.runtimeNS) / float64(elapsed.Nanoseconds()) * 100
			}
			if err := appendSample(cfg.dir, value); err != nil {
				return err
			}
			previous, previousAt = current, now
		case now := <-heap.C:
			go captureProfile(cfg, "heap", now, 30*time.Second)
		case now := <-cpu.C:
			go captureProfile(cfg, "cpu", now, cfg.cpuDuration+15*time.Second)
		case now := <-cleanup.C:
			prune(cfg.dir, now.Add(-cfg.retention))
		}
	}
}

func readProc(pid int) (procReading, error) {
	base := filepath.Join("/proc", strconv.Itoa(pid))
	var r procReading
	b, err := os.ReadFile(filepath.Join(base, "schedstat"))
	if err != nil {
		return r, err
	}
	fields := strings.Fields(string(b))
	if len(fields) < 1 {
		return r, fmt.Errorf("invalid schedstat")
	}
	r.runtimeNS, err = strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return r, err
	}
	if err := scanKeyValues(filepath.Join(base, "status"), func(key, value string) {
		switch key {
		case "VmRSS":
			r.rssBytes = parseKB(value)
		case "VmSize":
			r.vmBytes = parseKB(value)
		case "Threads":
			r.threads, _ = strconv.ParseInt(strings.Fields(value)[0], 10, 64)
		}
	}); err != nil {
		return r, err
	}
	_ = scanKeyValues(filepath.Join(base, "io"), func(key, value string) {
		n, _ := strconv.ParseInt(strings.Fields(value)[0], 10, 64)
		if key == "read_bytes" {
			r.readBytes = n
		} else if key == "write_bytes" {
			r.writeBytes = n
		}
	})
	if entries, err := os.ReadDir(filepath.Join(base, "fd")); err == nil {
		r.fds = len(entries)
	}
	return r, nil
}

func scanKeyValues(path string, visit func(string, string)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), ":")
		if ok {
			visit(key, strings.TrimSpace(value))
		}
	}
	return scanner.Err()
}

func parseKB(value string) int64 {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return 0
	}
	n, _ := strconv.ParseInt(fields[0], 10, 64)
	return n * 1024
}

func appendSample(dir string, value sample) error {
	path := filepath.Join(dir, "metrics-"+value.Time.Format("20060102")+".jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(value)
}

func captureProfile(cfg config, kind string, now time.Time, timeout time.Duration) {
	endpoint := kind
	if kind == "cpu" {
		endpoint = "profile"
	}
	url := cfg.pprofURL + "/debug/pprof/" + endpoint
	if kind == "cpu" {
		url += "?seconds=" + strconv.Itoa(int(cfg.cpuDuration.Seconds()))
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "capture", kind, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "capture", kind, resp.Status)
		return
	}
	path := filepath.Join(cfg.dir, kind+"-"+now.Format("20060102-150405")+".pprof")
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err == nil {
		_, err = io.Copy(f, resp.Body)
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
	}
	if err != nil {
		_ = os.Remove(tmp)
		fmt.Fprintln(os.Stderr, "capture", kind, err)
		return
	}
	_ = os.Rename(tmp, path)
}

func prune(dir string, cutoff time.Time) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || !(strings.HasPrefix(entry.Name(), "metrics-") || strings.HasPrefix(entry.Name(), "heap-") || strings.HasPrefix(entry.Name(), "cpu-")) {
			continue
		}
		if info, err := entry.Info(); err == nil && info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(dir, entry.Name()))
		}
	}
}
