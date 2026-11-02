// Package logging defines the service's structured, credential-safe log format.
package logging

import (
	"context"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"
)

// Setup must run before configuration loading, which can itself fail.
func Setup(service string) error {
	var level slog.Level
	var err error
	switch strings.ToUpper(os.Getenv("LOG_LEVEL")) {
	case "", "INFO":
		level = slog.LevelInfo
	case "DEBUG":
		level = slog.LevelDebug
	case "WARN":
		level = slog.LevelWarn
	case "ERROR":
		level = slog.LevelError
	default:
		err = errors.New("LOG_LEVEL must be DEBUG, INFO, WARN, or ERROR")
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})).With("service", service))
	return err
}

// Kind deliberately never calls Error: backend errors may contain SQL,
// passwords, capability URLs, object names, or private endpoints.
func Kind(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		return "unexpected_eof"
	}
	var sqlState interface{ SQLState() string }
	if errors.As(err, &sqlState) {
		code := sqlState.SQLState()
		if len(code) == 5 && strings.IndexFunc(code, func(r rune) bool { return !(r >= '0' && r <= '9' || r >= 'A' && r <= 'Z') }) == -1 {
			return "postgres_" + code
		}
	}
	var network net.Error
	if errors.As(err, &network) {
		if network.Timeout() {
			return "timeout"
		}
		return "network"
	}
	return "internal"
}

type stageError struct {
	stage string
	err   error
}

func (e *stageError) Error() string { return e.err.Error() }
func (e *stageError) Unwrap() error { return e.err }

// Wrap adds a fixed, developer-supplied operation name without logging here.
func Wrap(stage string, err error) error {
	if err == nil {
		return nil
	}
	return &stageError{stage, err}
}

func ErrorAttrs(err error) []any {
	attrs := []any{"error_kind", Kind(err)}
	// Prefer the innermost fixed operation to a generic startup wrapper.
	stage := ""
	for current := err; current != nil; current = errors.Unwrap(current) {
		if staged, ok := current.(*stageError); ok {
			stage = staged.stage
		}
	}
	if stage != "" {
		attrs = append(attrs, "stage", stage)
	}
	return attrs
}

type serverWriter struct{}

func (serverWriter) Write(p []byte) (int, error) {
	// net/http can include raw panic values and request data. Request panics
	// are handled by Middleware; other server diagnostics use a fixed event.
	slog.Error("HTTP server diagnostic", "event", "server.diagnostic", "error_kind", "http_server")
	return len(p), nil
}

func ServerLogger() *log.Logger { return log.New(serverWriter{}, "", 0) }

// Printf implements the Redis logger without exposing its connection errors.
// Dependency transitions and failed application operations are logged instead.
type RedisLogger struct{}

func (RedisLogger) Printf(context.Context, string, ...interface{}) {}

// BootstrapToken preserves the one-time enrollment credential even when the
// operator selected ERROR. Filtering it would persist an unrecoverable hash
// without delivering its raw token. Handle bypasses only the level check.
func BootstrapToken(ctx context.Context, token string) {
	record := slog.NewRecord(time.Now(), slog.LevelWarn, "Bootstrap token created (one-time, first user only)", 0)
	record.Add("event", "bootstrap.token_created", "bootstrap_token", token)
	_ = slog.Default().Handler().Handle(ctx, record)
}
