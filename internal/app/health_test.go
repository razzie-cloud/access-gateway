package app

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthProbesBypassSessionAndRateLimits(t *testing.T) {
	// A session lookup would panic: health must work without a session backend,
	// even when a caller supplies an auth cookie or exhausts the normal budget.
	s := &Server{mux: http.NewServeMux()}
	h := s.handler()
	for range anonymousRequestsPerMinute * 2 {
		for _, tc := range []struct {
			method, path string
			status       int
		}{{"GET", "/healthz", 200}, {"HEAD", "/healthz", 200}, {"GET", "/readyz", 503}, {"POST", "/readyz", 405}} {
			r := httptest.NewRequest(tc.method, tc.path, nil)
			r.AddCookie(&http.Cookie{Name: "auth", Value: "untrusted"})
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("%s %s: %d", tc.method, tc.path, w.Code)
			}
		}
	}
	if len(s.limits.counters) != 0 {
		t.Fatal("probes consumed the login/anonymous rate limit")
	}
}
