// Package health serves bounded, cached probes without doing request-time I/O.
package health

import (
	"context"
	"log"
	"net/http"
	"sync/atomic"
	"time"
)

const (
	interval = 10 * time.Second
	timeout  = 2 * time.Second
	maxAge   = 30 * time.Second
)

type Check struct {
	Name string
	Ping func(context.Context) error
}

type result struct {
	checked time.Time
	ready   bool
}

type Monitor struct {
	checks []Check
	result atomic.Pointer[result]
}

func New(checks ...Check) *Monitor {
	return &Monitor{checks: append([]Check(nil), checks...)}
}

// Start runs one check cycle at a time, immediately and then every ten seconds.
// Call the returned function before closing dependencies; it cancels and joins
// the worker. Checks must honor their context. A stuck worker cannot spawn more
// checks, and its last successful result expires.
func (m *Monitor) Start(parent context.Context) func() {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer m.result.Store(nil)
		for ctx.Err() == nil {
			m.check(ctx)
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

func (m *Monitor) check(ctx context.Context) {
	r := &result{checked: time.Now(), ready: len(m.checks) > 0}
	for _, check := range m.checks {
		if ctx.Err() != nil {
			return
		}
		probe, cancel := context.WithTimeout(ctx, timeout)
		err := check.Ping(probe)
		expired := probe.Err() != nil
		cancel()
		if err != nil || expired {
			r.ready = false
			if ctx.Err() == nil {
				// Backend errors may contain credentials or private addresses.
				// Names are fixed by the service, never supplied by a request.
				log.Printf("health check failed: %s", check.Name)
			}
		}
	}
	if ctx.Err() == nil {
		m.result.Store(r)
	}
}

// Handle intercepts only exact probe paths. It is safe on a nil monitor:
// liveness still works, while readiness fails closed until checks start.
func (m *Monitor) Handle(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/healthz" && r.URL.Path != "/readyz" {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	status, body := http.StatusOK, "ok\n"
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		status, body = http.StatusMethodNotAllowed, "method not allowed\n"
	} else if r.URL.Path == "/readyz" {
		var latest *result
		if m != nil {
			latest = m.result.Load()
		}
		if latest == nil || !latest.ready || time.Since(latest.checked) >= maxAge {
			w.Header().Set("Retry-After", "10")
			status, body = http.StatusServiceUnavailable, "not ready\n"
		} else {
			body = "ready\n"
		}
	}
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(body))
	}
	return true
}
