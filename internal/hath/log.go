package hath

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Out wraps the original Java Out.* logging on top of go.uber.org/zap.
// zap is zero-allocation and level-gated, which matters here: the edge server
// emits a log line per request. We keep the original method names.
var logger *zap.SugaredLogger

// InitLog configures the package logger.
func InitLog(levelDebug, disableFile bool, logDir string) {
	level := zapcore.InfoLevel
	if levelDebug {
		level = zapcore.DebugLevel
	}

	encCfg := zap.NewProductionEncoderConfig()
	encCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	encCfg.EncodeLevel = zapcore.CapitalLevelEncoder

	var ws zapcore.WriteSyncer = os.Stdout
	if !disableFile && logDir != "" {
		if f, err := os.OpenFile(logDir+"/log_all",
			os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
			// ponytail: single combined stream (original kept separate out/err).
			ws = zapcore.AddSync(f)
		}
	}

	core := zapcore.NewCore(zapcore.NewConsoleEncoder(encCfg), ws, level)
	logger = zap.New(core, zap.AddCallerSkip(1)).Sugar()
}

func Info(msg string, args ...any)  { logger.Infow(msg, args...) }
func Warn(msg string, args ...any)  { logger.Warnw(msg, args...) }
func Error(msg string, args ...any) { logger.Errorw(msg, args...) }
func Debug(msg string, args ...any) { logger.Debugw(msg, args...) }
