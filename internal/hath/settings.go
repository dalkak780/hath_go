package hath

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Settings holds all client configuration. The server pushes most of it via
// the client_login/client_settings/server_stat RPCs; local state (login
// credentials, RPC-server failover, time delta) lives here too.
type Settings struct {
	// credentials
	ClientID  int
	ClientKey string

	// network identity
	ClientHost string
	ClientPort int

	// throttling / limits
	ThrottleBytes    int64
	OverrideConns    int
	MaxAllowedFile   int64
	DiskLimit        int64
	DiskMinRemaining int64
	FSBlockSize      int64
	MaxFilenameLen   int
	StaticRangeCount int

	// rpc
	RPCServerPort int
	RPCPath       string
	StaticRanges  map[string]bool

	// image proxy
	ImageProxyType string
	ImageProxyHost string
	ImageProxyPort int

	// directories
	DataDir     string
	LogDir      string
	CacheDir    string
	TempDir     string
	DownloadDir string

	// flags
	VerifyCache          bool
	RescanCache          bool
	SkipFreeSpaceCheck   bool
	WarnNewClient        bool
	UseLessMemory        bool
	DisableBWM           bool
	DisableDownloadBWM   bool
	DisableFileVerify    bool
	DisableLogs          bool
	FlushLogs            bool
	DisableIPOriginCheck bool
	DisableFloodControl  bool

	// runtime
	serverTimeDelta int64

	// rpc-server failover (guarded by mu)
	mu                sync.Mutex
	rpcServers        []net.IP
	rpcServerCurrent  string
	rpcServerLastFail string
}

// NewSettings returns settings with the original client defaults.
func NewSettings() *Settings {
	return &Settings{
		MaxAllowedFile: 1073741824,
		FSBlockSize:    4096,
		MaxFilenameLen: 125,
		RPCServerPort:  80,
		RPCPath:        defaultRPCPath,
		DataDir:        "data",
		LogDir:         "log",
		CacheDir:       "cache",
		TempDir:        "tmp",
		DownloadDir:    "download",
		ImageProxyType: "socks",
	}
}

// ServerTime returns the server-corrected unix seconds.
func (s *Settings) ServerTime() int64 {
	s.mu.Lock()
	delta := s.serverTimeDelta
	s.mu.Unlock()
	return time.Now().Unix() + delta
}

// SetServerTime records the delta implied by a server-reported timestamp.
func (s *Settings) SetServerTime(serverTime int64) {
	s.mu.Lock()
	s.serverTimeDelta = serverTime - time.Now().Unix()
	s.mu.Unlock()
}

func (s *Settings) ServerTimeDelta() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.serverTimeDelta
}

// MaxConnections replicates the original formula.
func (s *Settings) MaxConnections() int {
	if s.OverrideConns > 0 {
		return s.OverrideConns
	}
	return 20 + min(480, int(s.ThrottleBytes/10000))
}

func (s *Settings) DiskLimitBytes() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.DiskLimit
}

// LoginValid checks clientID>0 and key is exactly 20 alphanumerics.
func (s *Settings) LoginValid() bool {
	if s.ClientID < 1 {
		return false
	}
	if len(s.ClientKey) != ClientKeyLen {
		return false
	}
	for _, r := range s.ClientKey {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// LoadLogin reads data/client_login ("ID-KEY").
func (s *Settings) LoadLogin() error {
	b, err := os.ReadFile(filepath.Join(s.DataDir, "client_login"))
	if err != nil {
		return err
	}
	parts := strings.SplitN(strings.TrimSpace(string(b)), "-", 2)
	if len(parts) != 2 {
		return fmt.Errorf("malformed client_login")
	}
	id, err := strconv.Atoi(parts[0])
	if err != nil {
		return err
	}
	s.ClientID = id
	s.ClientKey = parts[1]
	return nil
}

// SaveLogin writes data/client_login.
func (s *Settings) SaveLogin() error {
	return os.WriteFile(filepath.Join(s.DataDir, "client_login"),
		[]byte(fmt.Sprintf("%d-%s", s.ClientID, s.ClientKey)), 0o600)
}

// InitDirs creates all working directories.
func (s *Settings) InitDirs() error {
	for _, d := range []string{s.DataDir, s.LogDir, s.CacheDir, s.TempDir, s.DownloadDir} {
		if err := os.MkdirAll(d, 0o777); err != nil {
			return err
		}
	}
	return nil
}

// ParseArgs applies --flag=value style arguments.
func (s *Settings) ParseArgs(args []string) {
	for _, a := range args {
		if !strings.HasPrefix(a, "--") {
			Warn("invalid command argument", "arg", a)
			continue
		}
		body := a[2:]
		name, val, found := strings.Cut(body, "=")
		if !found {
			val = "true"
		}
		s.applySetting(strings.ReplaceAll(strings.ToLower(name), "-", "_"), val)
	}
}

// ApplySettings parses server-pushed settings (one "key=value" per line).
func (s *Settings) ApplySettings(lines []string) {
	for _, line := range lines {
		if line == "" {
			continue
		}
		k, v, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		s.applySetting(strings.ToLower(strings.TrimSpace(k)), v)
	}
}

func atoi64(v string) int64 { n, _ := strconv.ParseInt(v, 10, 64); return n }
func atoi(v string) int     { n, _ := strconv.Atoi(v); return n }

// applySetting mirrors Settings.updateSetting. Unknown keys are ignored
// (the original warned; we stay quiet to match the "silent" GUI keys).
func (s *Settings) applySetting(name, value string) {
	switch name {
	case "min_client_build":
		if n, err := strconv.Atoi(value); err == nil && n > ClientBuild {
			dieErr(fmt.Sprintf("client too old (need build %s); update from http://hentaiathome.net/", value))
		}
	case "cur_client_build":
		if n, err := strconv.Atoi(value); err == nil && n > ClientBuild {
			s.WarnNewClient = true
		}
	case "server_time":
		if n, err := strconv.ParseInt(value, 10, 64); err == nil {
			s.SetServerTime(n)
			Debug("setting altered", "server_time_delta", s.ServerTimeDelta())
		}
	case "rpc_server_port":
		if n, err := strconv.ParseInt(value, 10, 16); err == nil {
			s.RPCServerPort = int(n)
		}
	case "rpc_server_ip":
		s.setRPCServers(value)
	case "rpc_path":
		s.RPCPath = value
	case "host":
		s.ClientHost = value
	case "port":
		if s.ClientPort == 0 {
			if n, err := strconv.Atoi(value); err == nil {
				s.ClientPort = n
			}
		}
	case "throttle_bytes":
		if n, err := strconv.ParseInt(value, 10, 64); err == nil {
			s.ThrottleBytes = n
		}
	case "disklimit_bytes":
		// increases only; reductions apply on restart (matches original)
		if n, err := strconv.ParseInt(value, 10, 64); err == nil && n >= s.DiskLimit {
			s.DiskLimit = n
		} else if err == nil {
			Warn("disk limit reduced; takes effect after restart")
		}
	case "diskremaining_bytes":
		if n, err := strconv.ParseInt(value, 10, 64); err == nil {
			s.DiskMinRemaining = n
		}
	case "filesystem_blocksize":
		if bs, err := strconv.ParseInt(value, 10, 64); err != nil {
			return
		} else if bs > 0 && bs <= 65536 {
			s.FSBlockSize = bs
		} else {
			s.FSBlockSize = 4096
		}
	case "rescan_cache":
		s.RescanCache = value == "true"
	case "verify_cache":
		s.VerifyCache = value == "true"
		s.RescanCache = value == "true"
	case "use_less_memory":
		s.UseLessMemory = value == "true"
	case "disable_logging":
		s.DisableLogs = value == "true"
	case "disable_bwm":
		s.DisableBWM = value == "true"
		s.DisableDownloadBWM = value == "true"
	case "disable_download_bwm":
		s.DisableDownloadBWM = value == "true"
	case "disable_file_verification":
		s.DisableFileVerify = value == "true"
	case "disable_ip_origin_check":
		s.DisableIPOriginCheck = value == "true"
	case "disable_flood_control":
		s.DisableFloodControl = value == "true"
	case "skip_free_space_check":
		s.SkipFreeSpaceCheck = value == "true"
	case "max_connections":
		if n, err := strconv.Atoi(value); err == nil {
			s.OverrideConns = n
		}
	case "max_allowed_filesize":
		if n, err := strconv.ParseInt(value, 10, 64); err == nil {
			s.MaxAllowedFile = n
		}
	case "max_filename_length":
		if n, err := strconv.Atoi(value); err == nil {
			s.MaxFilenameLen = n
		}
	case "static_ranges":
		ranges := make(map[string]bool)
		for _, r := range strings.Split(value, ";") {
			if len(r) == 4 {
				ranges[r] = true
			}
		}
		s.mu.Lock()
		s.StaticRanges = ranges
		s.StaticRangeCount = len(ranges)
		s.mu.Unlock()
	case "static_range_count":
		if n, err := strconv.Atoi(value); err == nil {
			s.StaticRangeCount = n
		}
	case "cache_dir":
		s.CacheDir = value
	case "temp_dir":
		s.TempDir = value
	case "data_dir":
		s.DataDir = value
	case "log_dir":
		s.LogDir = value
	case "download_dir":
		s.DownloadDir = value
	case "image_proxy_type":
		s.ImageProxyType = strings.ToLower(value)
	case "image_proxy_host":
		s.ImageProxyHost = strings.ToLower(value)
	case "image_proxy_port":
		if n, err := strconv.Atoi(value); err == nil {
			s.ImageProxyPort = n
		}
	case "flush_logs":
		s.FlushLogs = value == "true"
	case "silentstart":
		// GUI-only
	default:
		Debug("unknown setting ignored", "key", name, "value", value)
	}
}

// IsStaticRange reports whether the file id's range is assigned to this client.
func (s *Settings) IsStaticRange(fileid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.StaticRanges == nil || len(fileid) < 4 {
		return false
	}
	return s.StaticRanges[fileid[:4]]
}

// --- RPC server failover ---

func (s *Settings) setRPCServers(value string) {
	var servers []net.IP
	for _, host := range strings.Split(value, ";") {
		ips, err := net.LookupIP(strings.TrimSpace(host))
		if err != nil || len(ips) == 0 {
			return // Java preserves the previous list when any name fails
		}
		servers = append(servers, ips[0])
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	keepCurrent := false
	for _, ip := range servers {
		if s.rpcServerCurrent != "" && ip.String() == s.rpcServerCurrent {
			keepCurrent = true
		}
	}
	s.rpcServers = servers
	if !keepCurrent {
		s.rpcServerCurrent = ""
	}
}

// IsValidRPCServer reports whether addr belongs to the known RPC server set.
func (s *Settings) IsValidRPCServer(addr net.IP) bool {
	if s.DisableIPOriginCheck {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ip := range s.rpcServers {
		if ip.Equal(addr) {
			return true
		}
	}
	return false
}

// RPCServerHost selects a host, avoiding the last failed one. Mirrors the
// original random-scan-with-avoidance logic.
func (s *Settings) RPCServerHost() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rpcServerCurrent != "" {
		return withPort(s.rpcServerCurrent, s.RPCServerPort)
	}
	if len(s.rpcServers) == 0 {
		return ClientRPCHost
	}
	if len(s.rpcServers) == 1 {
		s.rpcServerCurrent = s.rpcServers[0].String()
		return withPort(s.rpcServerCurrent, s.RPCServerPort)
	}
	// pick a random starting index and a scan direction, skipping last failed
	start := rand.Intn(len(s.rpcServers))
	dir := 1
	if rand.Intn(2) == 0 {
		dir = -1
	}
	for i := 0; i < len(s.rpcServers); i++ {
		idx := (start + dir*i + len(s.rpcServers)*len(s.rpcServers)) % len(s.rpcServers)
		cand := s.rpcServers[idx].String()
		if cand == s.rpcServerLastFail && i < len(s.rpcServers)-1 {
			continue
		}
		s.rpcServerCurrent = cand
		break
	}
	return withPort(s.rpcServerCurrent, s.RPCServerPort)
}

// MarkRPCServerFailure records the host we couldn't reach and forces reselection.
func (s *Settings) MarkRPCServerFailure(host string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rpcServerCurrent != "" {
		Debug("marking last failed rpc host", "host", host)
		s.rpcServerLastFail = host
		s.rpcServerCurrent = ""
	}
}

// ClearRPCServerFailure periodically resets the failed-host marker so load
// evens out again (original runs this every 1440 cycles).
func (s *Settings) ClearRPCServerFailure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rpcServerLastFail != "" {
		Debug("cleared rpc last-failed")
		s.rpcServerLastFail = ""
		s.rpcServerCurrent = ""
	}
}

func withPort(host string, port int) string {
	if port == 0 || port == 80 {
		return host
	}
	return fmt.Sprintf("%s:%d", host, port)
}
