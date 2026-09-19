// Package logging provides a context-scoped slog logger. Structured logs are
// how the range records which attack arrived, so every handler logs through
// From(ctx) rather than the global logger.
package logging

import (
	"context"
	"io"
	"log/slog"
	"strings"
)

// Format selects the log encoding.
type Format string

const (
	FormatJSON    Format = "json"
	FormatConsole Format = "console"
)

type loggerKey struct{}

var fallback = slog.New(slog.NewJSONHandler(io.Discard, nil))

// New builds a logger writing to w in the given format at the given level.
func New(w io.Writer, format Format, level slog.Level) *slog.Logger {
	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	switch format {
	case FormatConsole:
		handler = slog.NewTextHandler(w, opts)
	default:
		handler = slog.NewJSONHandler(w, opts)
	}
	return slog.New(handler)
}

// With returns a context carrying the given logger.
func With(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, logger)
}

// From returns the logger stored in ctx, or a discarding fallback.
func From(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(loggerKey{}).(*slog.Logger); ok {
		return logger
	}
	return fallback
}

// ParseFormat maps a string to a Format, defaulting to JSON.
func ParseFormat(s string) Format {
	if strings.EqualFold(s, string(FormatConsole)) {
		return FormatConsole
	}
	return FormatJSON
}

// ParseLevel maps a string to a slog.Level, defaulting to Info.
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
