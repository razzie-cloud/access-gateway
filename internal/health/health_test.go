package health

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func probe(m *Monitor, method, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	m.Handle(w, httptest.NewRequest(method, path, nil))
	return w
}

func TestProbeContract(t *testing.T) {
	m := New()
	for _, tc := range []struct {
		method, path string
		status       int
		body         string
	}{
		{"GET", "/healthz", 200, "ok\n"},
		{"HEAD", "/healthz", 200, ""},
		{"GET", "/readyz", 503, "not ready\n"},
		{"HEAD", "/readyz", 503, ""},
		{"POST", "/healthz", 405, "method not allowed\n"},
		{"DELETE", "/readyz", 405, "method not allowed\n"},
	} {
		w := probe(m, tc.method, tc.path)
		if w.Code != tc.status || w.Body.String() != tc.body {
			t.Fatalf("%s %s: %d %q", tc.method, tc.path, w.Code, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("missing probe security headers")
		}
		if tc.status == 405 && w.Header().Get("Allow") != "GET, HEAD" {
			t.Fatal("missing Allow header")
		}
	}
	for _, path := range []string{"/healthz/", "/readyz/extra", "/other"} {
		if m.Handle(httptest.NewRecorder(), httptest.NewRequest("GET", path, nil)) {
			t.Fatalf("intercepted %s", path)
		}
	}
	var absent *Monitor
	if probe(absent, "GET", "/readyz").Code != 503 || probe(absent, "GET", "/healthz").Code != 200 {
		t.Fatal("nil monitor did not fail readiness closed")
	}
	m.check(t.Context())
	if probe(m, "GET", "/readyz").Code != 503 {
		t.Fatal("no configured dependencies must not be ready")
	}
}

func TestCachedChecksFailureRecoveryAndLogging(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs bytes.Buffer
		old := log.Writer()
		log.SetOutput(&logs)
		defer log.SetOutput(old)
		var fail atomic.Bool
		var calls atomic.Int32
		m := New(Check{Name: "postgres", Ping: func(context.Context) error {
			calls.Add(1)
			if fail.Load() {
				return errors.New("secret-backend-uri")
			}
			return nil
		}})
		stop := m.Start(t.Context())
		defer stop()
		synctest.Wait()
		for range 1000 {
			if w := probe(m, "GET", "/readyz"); w.Code != 200 {
				t.Fatalf("ready status %d", w.Code)
			}
		}
		if calls.Load() != 1 || logs.Len() != 0 {
			t.Fatalf("requests triggered work/logging: calls=%d logs=%s", calls.Load(), &logs)
		}
		fail.Store(true)
		time.Sleep(interval)
		synctest.Wait()
		if probe(m, "GET", "/readyz").Code != 503 || probe(m, "GET", "/healthz").Code != 200 {
			t.Fatal("dependency failure must affect readiness only")
		}
		if !strings.Contains(logs.String(), "health check failed: postgres") || strings.Contains(logs.String(), "secret-backend-uri") {
			t.Fatalf("unsafe or missing error log: %s", &logs)
		}
		logs.Reset()
		for range 1000 {
			probe(m, "GET", "/readyz")
		}
		if logs.Len() != 0 || calls.Load() != 2 {
			t.Fatal("failed probes generated request-dependent work")
		}
		fail.Store(false)
		time.Sleep(interval)
		synctest.Wait()
		if probe(m, "HEAD", "/readyz").Code != 200 || logs.Len() != 0 {
			t.Fatal("recovery did not restore quiet readiness")
		}
		stop()
		if probe(m, "GET", "/readyz").Code != 503 {
			t.Fatal("stopped monitor stayed ready")
		}
	})
}

func TestDeadlinesAndEveryDependency(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var second atomic.Bool
		m := New(
			Check{Name: "postgres", Ping: func(ctx context.Context) error {
				<-ctx.Done()
				return ctx.Err()
			}},
			Check{Name: "redis", Ping: func(context.Context) error { second.Store(true); return nil }},
		)
		stop := m.Start(t.Context())
		defer stop()
		time.Sleep(timeout)
		synctest.Wait()
		if !second.Load() || probe(m, "GET", "/readyz").Code != 503 {
			t.Fatal("timeout did not fail readiness or prevented other checks")
		}
	})
}

func TestStuckCheckExpiresWithoutOverlapping(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		var calls atomic.Int32
		m := New(Check{Name: "postgres", Ping: func(context.Context) error {
			if calls.Add(1) > 1 {
				<-release // Simulate a driver that ignores its deadline.
			}
			return nil
		}})
		stop := m.Start(t.Context())
		defer stop()
		defer close(release)
		synctest.Wait()
		time.Sleep(maxAge + interval)
		synctest.Wait()
		if probe(m, "GET", "/readyz").Code != 503 || calls.Load() != 2 {
			t.Fatalf("stale result accepted or checks overlapped: calls=%d", calls.Load())
		}
	})
}

func TestCancellationInterruptsCheck(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		m := New(Check{Name: "postgres", Ping: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		}})
		stop := m.Start(ctx)
		synctest.Wait()
		cancel()
		stop()
		if probe(m, "GET", "/readyz").Code != 503 {
			t.Fatal("cancelled monitor ready")
		}
	})
}
