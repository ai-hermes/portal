package logging

import (
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Config struct {
	Level  string
	Format string
}

func New(cfg Config) (*zap.Logger, error) {
	level := zapcore.InfoLevel
	if cfg.Level != "" {
		if err := level.Set(strings.TrimSpace(cfg.Level)); err != nil {
			return nil, fmt.Errorf("parse log level: %w", err)
		}
	}

	encCfg := zap.NewProductionEncoderConfig()
	encCfg.TimeKey = "ts"
	encCfg.EncodeTime = zapcore.ISO8601TimeEncoder

	format := strings.ToLower(strings.TrimSpace(cfg.Format))
	if format == "" {
		format = "json"
	}

	var encoder zapcore.Encoder
	switch format {
	case "json":
		encoder = zapcore.NewJSONEncoder(encCfg)
	case "console":
		encCfg.EncodeLevel = zapcore.CapitalColorLevelEncoder
		encoder = zapcore.NewConsoleEncoder(encCfg)
	default:
		return nil, fmt.Errorf("unsupported log format: %s", cfg.Format)
	}

	logger := zap.New(
		zapcore.NewCore(encoder, zapcore.Lock(os.Stdout), level),
		zap.AddCaller(),
	)
	return logger, nil
}

func Sync(logger *zap.Logger) {
	if logger == nil {
		return
	}
	_ = logger.Sync()
}
