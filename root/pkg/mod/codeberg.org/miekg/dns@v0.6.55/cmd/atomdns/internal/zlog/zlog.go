// Package zlog provides an adapter that lets zap log through slog.
package zlog

import (
	"context"
	"log/slog"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// slogCore is a zapcore.Core that forwards logs to slog.
type slogCore struct {
	level  zapcore.LevelEnabler
	logger *slog.Logger
}

// New returns a *zap.Logger that writes through the given slog.Logger.
func New(debug bool) *zap.Logger {
	level := zapcore.InfoLevel
	if debug {
		level = zapcore.DebugLevel
	}
	core := &slogCore{level: level, logger: slog.Default()}
	return zap.New(core)
}

func (c *slogCore) Enabled(l zapcore.Level) bool { return c.level.Enabled(l) }
func (c *slogCore) Sync() error                  { return nil }

func (c *slogCore) With(fields []zapcore.Field) zapcore.Core {
	attrs := make([]any, 0, len(fields))
	for _, f := range fields {
		attrs = append(attrs, slog.Any(f.Key, f.Interface))
	}
	return &slogCore{level: c.level, logger: c.logger.With(attrs...)}
}

func (c *slogCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(ent.Level) {
		return ce.AddCore(ent, c)
	}
	return ce
}

func (c *slogCore) Write(ent zapcore.Entry, fields []zapcore.Field) error {
	attrs := make([]slog.Attr, 0, len(fields))
	for _, f := range fields {
		attrs = append(attrs, slog.Any(f.Key, f.Interface))
	}

	// Map zap levels to slog levels
	var lvl slog.Level
	switch ent.Level {
	case zapcore.DebugLevel:
		lvl = slog.LevelDebug
	case zapcore.InfoLevel:
		lvl = slog.LevelInfo
	case zapcore.WarnLevel:
		lvl = slog.LevelWarn
	case zapcore.ErrorLevel, zapcore.DPanicLevel, zapcore.PanicLevel, zapcore.FatalLevel:
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	c.logger.LogAttrs(context.Background(), lvl, ent.Message, attrs...)
	return nil
}
