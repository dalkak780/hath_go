package hath

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Out wraps the original Java Out.* logging on top of go.uber.org/zap.
// zap is zero-allocation and level-gated, which matters here: the edge server
// emits a log line per request. We keep the original method names.
var logger atomic.Pointer[zap.SugaredLogger]

const (
	logMaxBytes = int64(64 << 20)
	logBackups  = 3
)

type rotatingFile struct {
	mu      sync.Mutex
	path    string
	file    *os.File
	size    int64
	max     int64
	backups int
}

func newRotatingFile(path string, max int64, backups int) (*rotatingFile, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &rotatingFile{path: path, file: f, size: info.Size(), max: max, backups: backups}, nil
}

func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.max > 0 && r.size > 0 && r.size+int64(len(p)) > r.max {
		if err := r.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := r.file.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *rotatingFile) Sync() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.file.Sync()
}

func (r *rotatingFile) rotate() error {
	if err := r.file.Close(); err != nil {
		return err
	}
	if r.backups > 0 {
		_ = os.Remove(fmt.Sprintf("%s.%d", r.path, r.backups))
		for i := r.backups - 1; i > 0; i-- {
			_ = os.Rename(fmt.Sprintf("%s.%d", r.path, i), fmt.Sprintf("%s.%d", r.path, i+1))
		}
		_ = os.Rename(r.path, r.path+".1")
	} else {
		_ = os.Remove(r.path)
	}
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	r.file, r.size = f, 0
	return nil
}

func init() {
	// Provide a usable default so callers (and tests) never hit a nil logger
	// before InitLog runs. InitLog replaces it at startup.
	if l, err := zap.NewDevelopment(zap.AddCallerSkip(1)); err == nil {
		logger.Store(l.Sugar())
	} else {
		logger.Store(zap.NewNop().Sugar())
	}
}

// InitLog configures the package logger.
func InitLog(levelDebug, disableFile bool, logDir string) {
	level := zapcore.InfoLevel
	if levelDebug {
		level = zapcore.DebugLevel
	}

	encCfg := zap.NewProductionEncoderConfig()
	encCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	encCfg.EncodeLevel = zapcore.CapitalLevelEncoder

	sinks := []zapcore.WriteSyncer{zapcore.AddSync(os.Stdout)}
	if !disableFile && logDir != "" {
		if f, err := newRotatingFile(logDir+"/log_all", logMaxBytes, logBackups); err == nil {
			// Keep the file log for compatibility, but never hide container logs.
			sinks = append(sinks, f)
		}
	}

	core := zapcore.NewCore(zapcore.NewConsoleEncoder(encCfg),
		zapcore.NewMultiWriteSyncer(sinks...), level)
	// Log through the package-level helpers without losing the real call site.
	// AddCaller enables the field; AddCallerSkip skips Info/Warn/Error/Debug.
	logger.Store(zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1)).Sugar())
}

func Info(msg string, args ...any)  { logger.Load().Infow(msg, args...) }
func Warn(msg string, args ...any)  { logger.Load().Warnw(msg, args...) }
func Error(msg string, args ...any) { logger.Load().Errorw(msg, args...) }
func Debug(msg string, args ...any) { logger.Load().Debugw(msg, args...) }
