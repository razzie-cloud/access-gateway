package logging

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type requestKey struct{}
type request struct {
	id, route, operation string
	attrs                []any
	failure              []any
	level                slog.Level
	writeFailed          bool
}

func state(ctx context.Context) *request {
	r, _ := ctx.Value(requestKey{}).(*request)
	return r
}

// For merges safe event fields with request context without duplicate keys.
func For(ctx context.Context, attrs ...any) *slog.Logger {
	if r := state(ctx); r != nil {
		fields := []any{"request_id", r.id}
		for i := 0; i+1 < len(r.attrs); i += 2 {
			overridden := false
			for j := 0; j+1 < len(attrs); j += 2 {
				if attrs[j] == r.attrs[i] {
					overridden = true
					break
				}
			}
			if !overridden {
				fields = append(fields, r.attrs[i:i+2]...)
			}
		}
		return slog.Default().With(append(fields, attrs...)...)
	}
	return slog.Default().With(attrs...)
}

// Fields accepts only explicitly selected, non-secret application attributes.
func Fields(ctx context.Context, attrs ...any) {
	if r := state(ctx); r != nil {
		for i := 0; i+1 < len(attrs); i += 2 {
			replaced := false
			for j := 0; j+1 < len(r.attrs); j += 2 {
				if r.attrs[j] == attrs[i] {
					r.attrs[j+1] = attrs[i+1]
					replaced = true
					break
				}
			}
			if !replaced {
				r.attrs = append(r.attrs, attrs[i:i+2]...)
			}
		}
	}
}

// Fail records context for one summary at request completion, including failures
// after response headers were sent. It also works without the HTTP middleware.
func Fail(ctx context.Context, level slog.Level, operation string, err error) {
	if errors.Is(err, context.Canceled) {
		level = slog.LevelDebug
	}
	recordFailure(ctx, level, operation, ErrorAttrs(err))
}

func FailKind(ctx context.Context, level slog.Level, operation, kind string) {
	recordFailure(ctx, level, operation, []any{"error_kind", kind})
}

func recordFailure(ctx context.Context, level slog.Level, operation string, attrs []any) {
	if r := state(ctx); r != nil {
		if r.failure == nil || level > r.level {
			r.operation, r.failure, r.level = operation, attrs, level
		}
		return
	}
	slog.Log(ctx, level, "Operation failed", append([]any{"event", "request.failed", "operation", operation}, attrs...)...)
}

// Route must receive a static route template, never a URL or matched value.
func Route(pattern string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		SetRoute(req.Context(), pattern)
		next.ServeHTTP(w, req)
	})
}

func SetRoute(ctx context.Context, pattern string) {
	if r := state(ctx); r != nil && pattern != "" {
		r.route = pattern
	}
}

type response struct {
	http.ResponseWriter
	status int
	bytes  int64
	r      *request
}

func (w *response) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *response) WriteHeader(code int) {
	if w.status == 0 {
		if code >= 200 {
			w.status = code
		}
		w.ResponseWriter.WriteHeader(code)
	}
}
func (w *response) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	w.r.writeFailed = w.r.writeFailed || err != nil
	return n, err
}
func (w *response) Flush() {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

// Interrupted distinguishes client disconnects from storage read failures.
func Interrupted(ctx context.Context, err error) {
	r := state(ctx)
	if errors.Is(ctx.Err(), context.Canceled) || r != nil && r.writeFailed {
		FailKind(ctx, slog.LevelDebug, "download", "client_disconnected")
	} else if ctx.Err() != nil {
		Fail(ctx, slog.LevelError, "download", ctx.Err())
	} else {
		Fail(ctx, slog.LevelError, "download", err)
	}
}

// Stack contains code locations only, with no runtime arguments or panic value.
func Stack() []string {
	var pcs [32]uintptr
	n := runtime.Callers(2, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])
	var result []string
	for {
		frame, more := frames.Next()
		result = append(result, frame.Function+":"+strconv.Itoa(frame.Line))
		if !more {
			return result
		}
	}
}

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/healthz" || req.URL.Path == "/readyz" {
			next.ServeHTTP(w, req)
			return
		}
		r := &request{id: rand.Text(), route: "unmatched"}
		req = req.WithContext(context.WithValue(req.Context(), requestKey{}, r))
		w.Header().Set("X-Request-ID", r.id)
		rw := &response{ResponseWriter: w, r: r}
		start := time.Now()
		defer func() {
			recovered := recover()
			abort := recovered == http.ErrAbortHandler
			if recovered != nil && !abort {
				r.operation, r.level = "panic", slog.LevelError
				r.failure = []any{"error_kind", "panic", "stack", Stack()}
				if rw.status == 0 {
					http.Error(rw, "Request failed", http.StatusInternalServerError)
				} else {
					abort = true
				}
			}
			status := rw.status
			if status == 0 {
				status = http.StatusOK
			}
			level, event, message := slog.LevelDebug, "request.completed", "Request completed"
			if r.failure != nil {
				level, event, message = r.level, "request.failed", "Operation failed"
			} else if status >= 500 {
				level, event, message = slog.LevelError, "request.failed", "Request failed"
				r.failure = []any{"error_kind", "internal"}
			}
			if r.operation == "" {
				r.operation = r.route
			}
			// Method is attacker-controlled too; bound it to a fixed vocabulary.
			method := req.Method
			switch method {
			case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE":
			default:
				method = "OTHER"
			}
			if level >= slog.LevelError || !strings.Contains(r.route, "/static/") {
				attrs := []any{"event", event, "operation", r.operation, "method", method, "route", r.route, "status", status, "duration_ms", float64(time.Since(start).Microseconds()) / 1000, "bytes", rw.bytes}
				attrs = append(attrs, r.failure...)
				For(req.Context()).Log(req.Context(), level, message, attrs...)
			}
			if abort {
				panic(http.ErrAbortHandler)
			}
		}()
		next.ServeHTTP(rw, req)
	})
}
