package brokerdiscovery

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testToken = "v1.k1.1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func tokenFile(t *testing.T, value string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	if os.WriteFile(p, []byte(value), 0600) != nil {
		t.Fatal("write")
	}
	return p
}
func TestAuthenticationAndURL(t *testing.T) {
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Query().Get("client") != "app" || r.URL.Query().Get("token") != testToken || len(r.URL.Query()["token"]) != 1 {
			t.Error("incorrect auth")
		}
		w.Write([]byte("postgres://u:p@database/db"))
	}))
	defer s.Close()
	got, e := Fetch(context.Background(), s.URL+"/uri?client=app&extra=a%26b", Options{TokenFile: tokenFile(t, testToken+"\n")})
	if e != nil || got != "postgres://u:p@database/db" || calls != 1 {
		t.Fatal("authenticated discovery")
	}
	for _, query := range []string{"?client=app&client=app", "?client=app&token=secret", "?client=app&token=one&token=two", "?client=app&bad=%zz", "?client=app;token=bad", ""} {
		_, e := Fetch(context.Background(), s.URL+query, Options{TokenFile: tokenFile(t, testToken)})
		if e == nil || strings.Contains(e.Error(), s.URL) || strings.Contains(e.Error(), "secret") {
			t.Fatal("invalid config/diagnostics")
		}
	}
	if calls != 1 {
		t.Fatal("invalid configuration reached server")
	}
	for _, value := range []string{"", "invalid", testToken + "\nextra", strings.Repeat("A", 256), " " + testToken} {
		if _, e := Fetch(context.Background(), s.URL+"?client=app", Options{TokenFile: tokenFile(t, value)}); e == nil {
			t.Fatal("invalid token file")
		}
	}
	if _, e := Fetch(context.Background(), s.URL+"?client=app", Options{TokenFile: "/missing"}); e == nil {
		t.Fatal("missing token must fail")
	}
}
func TestBoundedErrorsRedirectsAndCancellation(t *testing.T) {
	for _, status := range []int{200, 302, 401, 403, 404} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			calls := 0
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Location", "/secret")
				w.WriteHeader(status)
				w.Write([]byte(strings.Repeat("secret", 1000)))
			}))
			defer s.Close()
			_, e := Fetch(context.Background(), s.URL, Options{})
			if e == nil || strings.Contains(e.Error(), "secret") || strings.Contains(e.Error(), s.URL) || calls != 1 {
				t.Fatal("response not bounded or sanitized")
			}
		})
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, e := Fetch(ctx, s.URL, Options{}); e == nil {
		t.Fatal("cancel")
	}
}
func TestVerifiedTLSAndOptionalToken(t *testing.T) {
	calls := 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Query().Has("token") {
			t.Error("unexpected token")
		}
		w.Write([]byte("redis://u:p@redis:6379/1"))
	}))
	defer s.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0600)
	if _, e := Fetch(context.Background(), s.URL, Options{CAFile: ca}); e != nil || calls != 1 {
		t.Fatal("verified TLS")
	}
	// Inspect the prepared transport to establish verification remains enabled.
	_, client, e := prepare(s.URL, Options{CAFile: ca})
	if e != nil || client.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify {
		t.Fatal("TLS verification disabled")
	}
	u, _ := url.Parse(s.URL)
	u.Host = "wrong.invalid:" + u.Port()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, e := Fetch(ctx, u.String(), Options{CAFile: ca}); e == nil {
		t.Fatal("untrusted hostname")
	}
}
