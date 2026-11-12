package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrorFormatNegotiation(t *testing.T) {
	for _, tc := range []struct {
		accept, contentType string
		json                bool
	}{
		{"", "", false},
		{"*/*", "", false},
		{"text/plain", "", false},
		{"image/png", "application/json", false},
		{"application/json", "", true},
		{"APPLICATION/JSON", "", true},
		{"application/*", "", true},
		{"text/*", "", false},
		{"application/json, */*", "", true},
		{"text/html, application/json", "", false},
		{"text/html;q=0.5, application/json;q=0.9", "", true},
		{"text/html;q=0.9, application/json;q=0.5", "", false},
		{"application/json;q=0, */*;q=1", "", false},
		{"text/html;q=0, */*;q=1", "", true},
		{"application/json;q=0, text/html;q=0", "application/json", false},
		{"application/json;q=0.2, application/*;q=1, text/html;q=0.8", "", false},
		{"application/json;q=NaN, text/html;q=0.5", "", false},
		{"application/json;q=2", "", false},
		{"application/json;q=-1", "", false},
		{"application/json;q=invalid", "", false},
		{"broken/header/value", "", false},
		{"", "application/json; charset=utf-8", true},
		{"*/*", "application/json", true},
		{"*/*;q=0", "application/json", false},
		{"text/html", "application/json", false},
		{"text/html, */*;q=0.8", "application/json", false},
	} {
		t.Run(tc.accept+"/"+tc.contentType, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.Header.Set("Accept", tc.accept)
			r.Header.Set("Content-Type", tc.contentType)
			assert.Equal(t, tc.json, wantsJSON(r))
		})
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Add("Accept", "application/json;q=0.8")
	r.Header.Add("Accept", "text/html;q=0.9")
	assert.False(t, wantsJSON(r), "all Accept header lines must be considered")
}

func TestErrorsAcrossRoutesAndFormats(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, body, message string
		status                            int
		prepare                           func(*Server, *http.Request)
	}{
		{"not found", "GET", "/missing?token=secret", "", "Page not found", 404, nil},
		{"wrong method", "GET", "/api/login/begin", "", "Method not allowed", 405, nil},
		{"direct UI", "GET", "/ui/admin", "", "Sign in first", 401, nil},
		{"expired sign-in", "GET", "/auth/authorize?flow=secret", "", "Sign-in expired; return to the app and try again", 400, nil},
		{"forward auth disabled", "GET", "/forward_auth", "", "Forward authentication is not configured", 503, nil},
		{"invalid forward request", "GET", "/forward_auth", "", "Invalid forwarded app request", 400, func(s *Server, r *http.Request) {
			s.cfg.ForwardAuthOrigins = []string{testAppOrigin}
		}},
		{"callback state", "GET", "/forward_auth", "", "Missing sign-in state; return to the app and try again", 400, func(s *Server, r *http.Request) {
			s.cfg.ForwardAuthOrigins = []string{testAppOrigin}
			r.Header.Set("X-Forwarded-Proto", "https")
			r.Header.Set("X-Forwarded-Host", "app.example.net")
			r.Header.Set("X-Forwarded-Uri", "/_auth/callback?state=secret&code=secret")
			r.Header.Set("X-Forwarded-Method", "GET")
		}},
		{"origin check", "POST", "/ui/users", "", "request origin not allowed", 403, func(s *Server, r *http.Request) {
			r.Header.Del("Origin")
		}},
		{"media check", "POST", "/api/login/begin", "", "application/json required", 415, func(s *Server, r *http.Request) {
			r.Header.Set("Content-Type", "text/plain")
		}},
		{"JSON validation", "POST", "/api/login/begin", "{", "bad json", 400, nil},
		{"asset missing", "GET", "/static/missing.css", "", "Not Found", 404, nil},
		{"asset method", "POST", "/static/app.css", "", "Method not allowed", 405, nil},
		{"asset range", "GET", "/static/app.css", "", "Requested Range Not Satisfiable", 416, func(s *Server, r *http.Request) {
			r.Header.Set("Range", "bytes=999999999-")
		}},
		{"renderer failure", "GET", "/render-failure", "", "Unable to render page", 500, func(s *Server, r *http.Request) {
			s.mux.HandleFunc("/render-failure", func(w http.ResponseWriter, r *http.Request) {
				s.render(w, r, 200, "missing-template", viewData{})
			})
		}},
	} {
		for _, format := range []string{"text/html", "application/json"} {
			t.Run(tc.name+"/"+format, func(t *testing.T) {
				s := unitServer()
				r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
				r.Header.Set("Origin", s.cfg.Origin)
				r.Header.Set("Accept", format)
				r.Header.Set("Content-Type", "application/json")
				if tc.prepare != nil {
					tc.prepare(s, r)
				}
				w := httptest.NewRecorder()
				s.handler().ServeHTTP(w, r)
				require.Equal(t, tc.status, w.Code)
				assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
				assert.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"))
				assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
				assert.Contains(t, strings.Join(w.Header().Values("Vary"), ","), "Accept")
				assert.NotContains(t, w.Body.String(), "secret")
				for _, name := range []string{"Location", "Set-Cookie", "X-Auth-Request-User", "X-Auth-Request-Name", "X-Auth-Request-Token"} {
					assert.Empty(t, w.Header().Get(name))
				}
				if format == "application/json" {
					assert.Equal(t, format, w.Header().Get("Content-Type"))
					encoded, err := json.Marshal(map[string]string{"error": tc.message})
					require.NoError(t, err)
					assert.JSONEq(t, string(encoded), w.Body.String())
				} else {
					assert.Equal(t, "text/html; charset=utf-8", w.Header().Get("Content-Type"))
					assert.Contains(t, w.Body.String(), "<!doctype html>")
					assert.Contains(t, w.Body.String(), "Razzie Cloud")
					assert.Contains(t, w.Header().Get("Content-Security-Policy"), "default-src 'none'; style-src https://auth.example;")
				}
				if tc.status == 405 {
					assert.NotEmpty(t, w.Header().Get("Allow"))
				}
			})
		}
	}
}

func TestErrorFragmentsAndHead(t *testing.T) {
	for _, tc := range []struct{ method, accept, hx, contentType string }{
		{"GET", "text/html", "true", "text/html; charset=utf-8"},
		{"GET", "text/html", "false", "text/html; charset=utf-8"},
		{"GET", "application/json", "true", "application/json"},
		{"HEAD", "text/html", "", "text/html; charset=utf-8"},
		{"HEAD", "application/json", "", "application/json"},
	} {
		t.Run(tc.method+tc.accept+tc.hx, func(t *testing.T) {
			s := unitServer()
			r := httptest.NewRequest(tc.method, "/ui/admin", nil)
			r.Header.Set("Accept", tc.accept)
			r.Header.Set("HX-Request", tc.hx)
			w := httptest.NewRecorder()
			s.handler().ServeHTTP(w, r)
			assert.Equal(t, tc.contentType, w.Header().Get("Content-Type"))
			if tc.method == "HEAD" {
				assert.Equal(t, 405, w.Code)
				assert.Empty(t, w.Body.String())
			} else {
				assert.Equal(t, 401, w.Code)
				if tc.accept == "text/html" && tc.hx == "true" {
					assert.Contains(t, w.Body.String(), `role="alert"`)
					assert.NotContains(t, w.Body.String(), "<!doctype html>")
					assert.Contains(t, w.Header().Get("Content-Security-Policy"), "script-src 'self'")
				}
			}
		})
	}
}

func TestRateLimitFormatsPreserveRetryAfter(t *testing.T) {
	for _, format := range []string{"text/html", "application/json"} {
		s := unitServer()
		r := httptest.NewRequest("GET", "/register", nil)
		r.Header.Set("Accept", format)
		for range anonymousRequestsPerMinute {
			s.limits.allow(rateLimitKey{ip: s.clientIP(r)}, anonymousRequestsPerMinute, time.Now())
		}
		w := httptest.NewRecorder()
		s.handler().ServeHTTP(w, r)
		assert.Equal(t, 429, w.Code)
		assert.NotEmpty(t, w.Header().Get("Retry-After"))
		if format == "application/json" {
			assert.JSONEq(t, `{"error":"too many requests; try again later"}`, w.Body.String())
		} else {
			assert.Contains(t, w.Body.String(), "<!doctype html>")
			assert.Contains(t, w.Body.String(), "Too many requests")
		}
	}
}

func TestErrorMessagesAreEscaped(t *testing.T) {
	s := unitServer()
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	s.writeError(w, r, 400, `<script>alert("test")</script>`)
	assert.NotContains(t, w.Body.String(), "<script>")
	assert.Contains(t, w.Body.String(), "&lt;script&gt;")
}
