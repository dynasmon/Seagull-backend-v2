package log

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
)

const (
	FormatJSON = "json"
	FormatText = "text"
)

type Options struct {
	Level   string
	Format  string
	Service string
	Version string
}

func New(w io.Writer, opts Options) (*slog.Logger, error) {
	level, err := parseLevel(opts.Level)
	if err != nil {
		return nil, err
	}
	handlerOptions := &slog.HandlerOptions{Level: level, AddSource: level <= slog.LevelDebug}

	var handler slog.Handler
	switch strings.ToLower(strings.TrimSpace(opts.Format)) {
	case "", FormatJSON:
		handler = slog.NewJSONHandler(w, handlerOptions)
	case FormatText:
		handler = slog.NewTextHandler(w, handlerOptions)
	default:
		return nil, fmt.Errorf("unsupported log format %q", opts.Format)
	}

	logger := slog.New(handler)
	if opts.Service != "" {
		logger = logger.With(slog.String("service", opts.Service))
	}
	if opts.Version != "" {
		logger = logger.With(slog.String("version", opts.Version))
	}
	return logger, nil
}

func parseLevel(value string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return slog.LevelDebug, nil
	case "", "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unsupported log level %q", value)
	}
}

type contextKey struct{}

func Into(ctx context.Context, logger *slog.Logger) context.Context {
	if logger == nil {
		return ctx
	}
	return context.WithValue(ctx, contextKey{}, logger)
}

func From(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(contextKey{}).(*slog.Logger); ok && logger != nil {
		return logger
	}
	return slog.Default()
}

func With(ctx context.Context, attrs ...slog.Attr) context.Context {
	if len(attrs) == 0 {
		return ctx
	}
	arguments := make([]any, 0, len(attrs))
	for _, attr := range attrs {
		arguments = append(arguments, attr)
	}
	return Into(ctx, From(ctx).With(arguments...))
}
