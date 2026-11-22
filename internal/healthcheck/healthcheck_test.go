package healthcheck

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPort(t *testing.T) {
	t.Setenv("SERVICE_PORT", "")
	if got := port(); got != "8080" {
		t.Fatalf("default port = %q", got)
	}
	t.Setenv("SERVICE_PORT", "9090")
	if got := port(); got != "9090" {
		t.Fatalf("custom port = %q", got)
	}
}

func TestRun(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	for _, status := range []int{http.StatusOK, http.StatusServiceUnavailable, http.StatusFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/readyz" {
					t.Errorf("unexpected probe: %s %s", r.Method, r.URL.Path)
				}
				w.Header().Set("Location", "/readyz")
				w.WriteHeader(status)
			}))
			defer s.Close()
			_, p, _ := net.SplitHostPort(s.Listener.Addr().String())
			t.Setenv("SERVICE_PORT", p)
			want := 1
			if status == http.StatusOK {
				want = 0
			}
			if got := Run(); got != want {
				t.Fatalf("exit code = %d, want %d", got, want)
			}
			s.Close()
			if got := Run(); got != 1 {
				t.Fatalf("closed listener exit code = %d", got)
			}
		})
	}
}

func TestRunTimeout(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer s.Close()
	_, p, _ := net.SplitHostPort(s.Listener.Addr().String())
	t.Setenv("SERVICE_PORT", p)
	start := time.Now()
	if got := Run(); got != 1 {
		t.Fatalf("timeout exit code = %d", got)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("probe exceeded container timeout: %v", elapsed)
	}
}
