package app

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandlerRequestProtection(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, origin, contentType string
		status                                  int
	}{
		{"json", "POST", "/api/test", "https://auth.example", "application/json", 204},
		{"json with charset", "POST", "/api/test", "https://auth.example", "application/json; charset=utf-8", 204},
		{"missing origin", "POST", "/api/test", "", "application/json", 403},
		{"foreign origin", "POST", "/api/test", "https://evil.example", "application/json", 403},
		{"null origin", "POST", "/api/test", "null", "application/json", 403},
		{"origin prefix", "POST", "/api/test", "https://auth.example.evil", "application/json", 403},
		{"origin scheme", "POST", "/api/test", "http://auth.example", "application/json", 403},
		{"missing media type", "POST", "/api/test", "https://auth.example", "", 415},
		{"plain text", "POST", "/api/test", "https://auth.example", "text/plain", 415},
		{"malformed media type", "POST", "/api/test", "https://auth.example", "application/json; charset", 415},
		{"ui form", "POST", "/ui/test", "https://auth.example", "application/x-www-form-urlencoded", 204},
		{"ui origin", "POST", "/ui/test", "https://evil.example", "application/x-www-form-urlencoded", 403},
		{"get", "GET", "/api/test", "", "", 204},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{cfg: Config{Origin: "https://auth.example/"}, mux: http.NewServeMux()}
			called := false
			s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusNoContent)
			})
			r := httptest.NewRequest(tc.method, tc.path, nil)
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Content-Type", tc.contentType)
			w := httptest.NewRecorder()
			s.handler().ServeHTTP(w, r)
			assert.Equal(t, tc.status, w.Code)
			assert.Equal(t, tc.status == http.StatusNoContent, called, "downstream handler called")
			for name, want := range map[string]string{
				"Cache-Control":           "no-store",
				"Referrer-Policy":         "no-referrer",
				"X-Content-Type-Options":  "nosniff",
				"Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
			} {
				assert.Equal(t, want, w.Header().Get(name), "header %s", name)
			}
		})
	}
}

func TestHandlerBodyLimit(t *testing.T) {
	const limit = 2 << 20
	for _, tc := range []struct {
		name string
		size int
	}{{"at limit", limit}, {"over limit", limit + 1}} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{cfg: Config{Origin: "https://auth.example"}, mux: http.NewServeMux()}
			s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				_, err := io.Copy(io.Discard, r.Body)
				if tc.size == limit {
					assert.NoError(t, err, "body at limit rejected")
				} else {
					var maxErr *http.MaxBytesError
					if assert.ErrorAs(t, err, &maxErr) {
						assert.EqualValues(t, limit, maxErr.Limit)
					}
				}
			})
			r := httptest.NewRequest("POST", "/ui/test", strings.NewReader(strings.Repeat("x", tc.size)))
			r.Header.Set("Origin", s.cfg.Origin)
			s.handler().ServeHTTP(httptest.NewRecorder(), r)
		})
	}
}

func TestSetCookie(t *testing.T) {
	for _, origin := range []string{"http://localhost:8080", "https://auth.example"} {
		for _, maxAge := range []int{0, 3600, -1} {
			s := &Server{cfg: Config{Origin: origin}}
			w := httptest.NewRecorder()
			s.setCookie(w, "auth", "token", maxAge)
			cookies := w.Result().Cookies()
			require.Len(t, cookies, 1)
			c := cookies[0]
			assert.Equal(t, "auth", c.Name)
			assert.Equal(t, "token", c.Value)
			assert.Equal(t, "/", c.Path)
			assert.Equal(t, maxAge, c.MaxAge)
			assert.Empty(t, c.Domain)
			assert.True(t, c.HttpOnly)
			assert.Equal(t, http.SameSiteStrictMode, c.SameSite)
			assert.Equal(t, strings.HasPrefix(origin, "https://"), c.Secure, "origin %s", origin)
		}
	}
}

func TestCurrentUserWithoutValidSession(t *testing.T) {
	s := &Server{mem: NewMemorySessions(time.Minute)}
	s.mem.auth["expired"] = authEntry{username: "alice", exp: time.Now().Add(-time.Minute)}
	for _, token := range []string{"", "unknown", "expired"} {
		r := httptest.NewRequest("GET", "/", nil)
		if token != "" {
			r.AddCookie(&http.Cookie{Name: "auth", Value: token})
		}
		_, err := s.currentUser(r)
		assert.ErrorIs(t, err, http.ErrNoCookie, "token %q", token)
	}
}
