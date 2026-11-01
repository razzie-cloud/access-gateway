package app

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientIPTrustBoundary(t *testing.T) {
	s := unitServer()
	var err error
	s.trustedProxies, err = parseTrustedProxies([]string{"10.0.0.0/24", "::1", "127.0.0.1"})
	require.NoError(t, err)
	for _, tc := range []struct{ peer, chain, want string }{
		{"198.51.100.1:1234", "203.0.113.10", "198.51.100.1"},
		{"10.0.0.5:1234", "203.0.113.10", "203.0.113.10"},
		{"10.0.0.5:1234", "192.0.2.99, 203.0.113.10", "203.0.113.10"},
		{"10.0.0.5:1234", "203.0.113.10, 10.0.0.6", "203.0.113.10"},
		{"10.0.0.5:1234", "broken", "10.0.0.5"},
		{"10.0.0.5:1234", "", "10.0.0.5"},
		{"[::ffff:198.51.100.1]:1234", "203.0.113.10", "198.51.100.1"},
		{"[::1]:1234", "2001:db8::5", "2001:db8::5"},
		{"10.0.0.5:1234", strings.Repeat("1", 4097), "10.0.0.5"},
	} {
		r := httptest.NewRequest("GET", "/register", nil)
		r.RemoteAddr = tc.peer
		r.Header.Set("X-Forwarded-For", tc.chain)
		r.Header.Set("X-Real-IP", "192.0.2.88")
		assert.Equal(t, tc.want, s.clientIP(r).String(), "%+v", tc)
	}
	_, err = parseTrustedProxies([]string{"not-a-proxy"})
	require.Error(t, err)
	_, err = NewServer(Config{TrustedProxies: []string{"not-a-proxy"}})
	require.ErrorContains(t, err, "trusted proxy")
}

func TestRequestLimitsConcurrencyExpiryAndCapacity(t *testing.T) {
	l := newRequestLimits()
	now := time.Now()
	key := rateLimitKey{ip: netip.MustParseAddr("198.51.100.1")}
	var wg sync.WaitGroup
	var accepted atomic.Int32
	for range 200 {
		wg.Go(func() {
			if ok, _ := l.allow(key, 60, now); ok {
				accepted.Add(1)
			}
		})
	}
	wg.Wait()
	assert.EqualValues(t, 60, accepted.Load())
	ok, retry := l.allow(key, 60, now.Add(500*time.Millisecond))
	assert.False(t, ok)
	assert.Equal(t, 60, retry)
	ok, _ = l.allow(key, 60, now.Add(time.Minute))
	assert.True(t, ok)
	for i := 1; i < maxRateLimitCounters; i++ {
		ip := netip.AddrFrom4([4]byte{192, 0, byte(i >> 8), byte(i)})
		ok, _ := l.allow(rateLimitKey{ip: ip}, 60, now.Add(time.Minute))
		require.True(t, ok)
	}
	ok, _ = l.allow(rateLimitKey{ip: netip.MustParseAddr("203.0.113.1")}, 60, now.Add(time.Minute))
	assert.False(t, ok)
	assert.Len(t, l.counters, maxRateLimitCounters)
	ok, _ = l.allow(key, 60, now.Add(2*time.Minute))
	assert.True(t, ok)
	assert.Len(t, l.counters, 1)
}

func TestAnonymousRateLimitAndSessionExemption(t *testing.T) {
	s := unitServer()
	for i := range anonymousRequestsPerMinute + 1 {
		r := httptest.NewRequest("GET", "/register", nil)
		r.Header.Set("X-Forwarded-For", fmt.Sprintf("203.0.113.%d", i))
		r.AddCookie(&http.Cookie{Name: "auth", Value: "forged"})
		w := httptest.NewRecorder()
		s.handler().ServeHTTP(w, r)
		if i < anonymousRequestsPerMinute {
			require.Equal(t, http.StatusOK, w.Code)
		} else {
			require.Equal(t, http.StatusTooManyRequests, w.Code)
			require.NotEmpty(t, w.Header().Get("Retry-After"))
			require.Empty(t, w.Result().Cookies())
		}
	}
	testMemory(s).PutAuth("valid", "alice")
	assert.Equal(t, 200, request(s, "GET", "/register", "", "valid").Code)
	assert.Equal(t, 429, request(s, "GET", "/register", "", "").Code)
	r := httptest.NewRequest("GET", "/register", nil)
	r.RemoteAddr = "203.0.113.2:1234"
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	assert.Equal(t, 200, w.Code)
}

func TestLoginBudgetIncludesFinishAndAuthenticatedRequests(t *testing.T) {
	s := unitServer()
	testMemory(s).PutAuth("valid", "alice")
	for i := range loginRequestsPerMinute + 1 {
		// Invalid JSON and missing SIDs must consume the same IP budget too.
		path := "/api/login/begin"
		if i%2 == 0 {
			path = "/api/login/finish"
		}
		w := request(s, "POST", path, "{", "valid")
		if i < loginRequestsPerMinute {
			assert.NotEqual(t, http.StatusTooManyRequests, w.Code)
		} else {
			assert.Equal(t, http.StatusTooManyRequests, w.Code)
			assert.Empty(t, w.Result().Cookies())
		}
	}
}

func TestForwardAuthRateLimitDoesNotAllocateMoreFlows(t *testing.T) {
	s := unitServer()
	s.cfg.ForwardAuthOrigins = []string{testAppOrigin}
	for range anonymousRequestsPerMinute {
		require.Equal(t, 303, forwardRequest(s, testAppOrigin, "/").Code)
	}
	w := forwardRequest(s, testAppOrigin, "/")
	assert.Equal(t, 429, w.Code)
	assert.Empty(t, w.Result().Cookies())
	assert.Len(t, testMemory(s).flows, anonymousRequestsPerMinute)
	// A live, origin-bound app session continues working at an exhausted IP.
	testMemory(s).PutAuth("parent", "alice")
	flow, state, ok := testMemory(s).beginAppLogin(testAppOrigin, testAppOrigin+"/")
	require.True(t, ok)
	code, ok := testMemory(s).authorizeAppLogin(flow, "parent")
	require.True(t, ok)
	token, _, ok := testMemory(s).completeAppLogin(flow, code, state, testAppOrigin)
	require.True(t, ok)
	r := httptest.NewRequest("GET", "/forward_auth", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "app.example.net")
	r.Header.Set("X-Forwarded-Uri", "/")
	r.AddCookie(&http.Cookie{Name: appCookieName(testAppOrigin, "app"), Value: token})
	assert.True(t, s.authenticatedForRateLimit(r))
	r.Header.Set("X-Forwarded-Host", "evil.example")
	assert.False(t, s.authenticatedForRateLimit(r))
}
