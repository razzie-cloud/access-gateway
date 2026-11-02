package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func capture(t *testing.T, level slog.Level) *bytes.Buffer {
	t.Helper()
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: level})).With("service", "test"))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &output
}

func record(t *testing.T, output *bytes.Buffer) map[string]any {
	t.Helper()
	var value map[string]any
	decoder := json.NewDecoder(output)
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		t.Fatalf("expected one JSON record, got additional output: %v", err)
	}
	return value
}

func TestRequestFailureIsSingleJSONRecordWithoutSecrets(t *testing.T) {
	output := capture(t, slog.LevelInfo)
	handler := Middleware(Route("GET /s/{share}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Fields(r.Context(), "owner_user_id", "known-owner")
		Fail(r.Context(), slog.LevelError, "storage_open", Wrap("load_metadata", errors.New("secret-password-in-SQL")))
		Fail(r.Context(), slog.LevelError, "second_failure", errors.New("secret-backend-url"))
		http.Error(w, "Request failed", 502)
	})))
	r := httptest.NewRequest("GET", "/s/secret-share-token?path=secret-object-name", strings.NewReader("secret-body"))
	r.Header.Set("Cookie", "auth=secret-cookie")
	r.Header.Set("X-Request-ID", "attacker-supplied-id")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if strings.Contains(output.String(), "secret-") || strings.Contains(output.String(), "attacker-supplied-id") {
		t.Fatalf("private data in logs: %s", output)
	}
	v := record(t, output)
	if v["event"] != "request.failed" || v["operation"] != "storage_open" || v["stage"] != "load_metadata" || v["route"] != "GET /s/{share}" || v["status"] != float64(502) || v["owner_user_id"] != "known-owner" {
		t.Fatalf("missing failure context: %#v", v)
	}
	if v["request_id"] == "" || v["request_id"] != w.Header().Get("X-Request-ID") || v["duration_ms"] == nil {
		t.Fatalf("missing request correlation: %#v", v)
	}
}

func TestRoutineTrafficAndHealthStayQuiet(t *testing.T) {
	output := capture(t, slog.LevelInfo)
	for _, path := range []string{"/", "/invalid", "/healthz", "/readyz"} {
		Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/readyz" {
				w.WriteHeader(503)
			} else {
				w.WriteHeader(404)
			}
		})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", path, nil))
	}
	if output.Len() != 0 {
		t.Fatalf("routine traffic generated logs: %s", output)
	}
}

func TestDebugRequestsUseTemplatesAndExcludeStatic(t *testing.T) {
	output := capture(t, slog.LevelDebug)
	handler := Middleware(Route("GET /directories/{id}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(206)
		_, _ = w.Write([]byte("part"))
	})))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/directories/private-id?path=private-name", nil))
	v := record(t, output)
	if v["event"] != "request.completed" || v["status"] != float64(206) || v["bytes"] != float64(4) || v["route"] != "GET /directories/{id}" {
		t.Fatalf("bad debug request: %#v", v)
	}
	Middleware(Route("GET /static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/static/app.js", nil))
	if output.Len() != 0 {
		t.Fatalf("static request logged: %s", output)
	}
}

func TestPanicsDoNotLeakValuesAndAbortRemainsSilent(t *testing.T) {
	output := capture(t, slog.LevelInfo)
	w := httptest.NewRecorder()
	Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("secret-password") })).ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 500 || strings.Contains(output.String(), "secret-password") {
		t.Fatalf("unsafe panic: %s", output)
	}
	v := record(t, output)
	if v["error_kind"] != "panic" || len(v["stack"].([]any)) == 0 {
		t.Fatalf("missing panic locations: %#v", v)
	}
	func() {
		defer func() {
			if recover() != http.ErrAbortHandler {
				t.Fatal("abort was swallowed")
			}
		}()
		Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) })).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	}()
	if output.Len() != 0 {
		t.Fatalf("abort logged at INFO: %s", output)
	}
}

func TestFlushAndResponseControllerRemainAvailable(t *testing.T) {
	output := capture(t, slog.LevelDebug)
	w := httptest.NewRecorder()
	Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("stream"))
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Fatal(err)
		}
	})).ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if !w.Flushed || w.Body.String() != "stream" {
		t.Fatal("streaming changed")
	}
	if record(t, output)["bytes"] != float64(6) {
		t.Fatal("stream byte count lost")
	}
}

func TestDownloadCancellationAndReadFailure(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(map[bool]string{false: "read_failure", true: "client_canceled"}[canceled], func(t *testing.T) {
			output := capture(t, slog.LevelInfo)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if canceled {
				cancel()
			}
			handler := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(206)
				Interrupted(r.Context(), io.ErrUnexpectedEOF)
				panic(http.ErrAbortHandler)
			}))
			func() {
				defer func() {
					if recover() != http.ErrAbortHandler {
						t.Fatal("download abort swallowed")
					}
				}()
				handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil).WithContext(ctx))
			}()
			if canceled {
				if output.Len() != 0 {
					t.Fatalf("canceled download logged at INFO: %s", output)
				}
			} else if record(t, output)["error_kind"] != "unexpected_eof" {
				t.Fatal("read failure not classified")
			}
		})
	}
}

func TestSetupAndErrorClassification(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	for _, level := range []string{"", "debug", "INFO", "WARN", "ERROR"} {
		t.Setenv("LOG_LEVEL", level)
		if err := Setup("test"); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("LOG_LEVEL", "secret-invalid-setting")
	if err := Setup("test"); err == nil || strings.Contains(err.Error(), "secret-invalid-setting") {
		t.Fatal("invalid level not rejected safely")
	}
	if Kind(Wrap("operation", context.DeadlineExceeded)) != "timeout" || Kind(errors.New("password")) != "internal" {
		t.Fatal("error classification changed")
	}
}

func TestDownloadDeadlineRemainsAnOperationalFailure(t *testing.T) {
	output := capture(t, slog.LevelInfo)
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	Interrupted(ctx, io.ErrUnexpectedEOF)
	if record(t, output)["error_kind"] != "timeout" {
		t.Fatal("deadline was treated as a client disconnect")
	}
}

func TestBootstrapCredentialSurvivesErrorOnlyLogging(t *testing.T) {
	output := capture(t, slog.LevelError)
	BootstrapToken(t.Context(), "one-time-test-token")
	event := record(t, output)
	if event["event"] != "bootstrap.token_created" || event["bootstrap_token"] != "one-time-test-token" || event["service"] != "test" {
		t.Fatalf("bootstrap credential was lost: %#v", event)
	}
}
