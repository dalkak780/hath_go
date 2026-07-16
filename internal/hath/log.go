package hath

import (
	"os"
	"sync/atomic"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Out wraps the original Java Out.* logging on top of go.uber.org/zap.
// zap is zero-allocation and level-gated, which matters here: the edge server
// emits a log line per request. We keep the original method names.
var logger atomic.Pointer[zap.SugaredLogger]

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
		if f, err := os.OpenFile(logDir+"/log_all",
			os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
			// Keep the file log for compatibility, but never hide container logs.
			sinks = append(sinks, zapcore.AddSync(f))
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
