package app

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	anonymousRequestsPerMinute = 60
	loginRequestsPerMinute     = 10
	maxRateLimitCounters       = 16384
)

type rateLimitKey struct {
	ip    netip.Addr
	login bool
}

type attemptCounter struct {
	count   int
	expires time.Time
}

// Fixed windows and a hard capacity keep anonymous clients from growing this
// table indefinitely. Full tables reject new clients until counters expire;
// evicting live counters would let attackers reset their allowances.
type requestLimits struct {
	mu          sync.Mutex
	counters    map[rateLimitKey]attemptCounter
	nextCleanup time.Time
}

func newRequestLimits() *requestLimits {
	return &requestLimits{counters: make(map[rateLimitKey]attemptCounter)}
}

func (l *requestLimits) allow(key rateLimitKey, limit int, now time.Time) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !now.Before(l.nextCleanup) {
		for key, counter := range l.counters {
			if !now.Before(counter.expires) {
				delete(l.counters, key)
			}
		}
		l.nextCleanup = now.Add(time.Minute)
	}
	counter, exists := l.counters[key]
	if !exists || !now.Before(counter.expires) {
		if !exists && len(l.counters) >= maxRateLimitCounters {
			return false, 60
		}
		counter = attemptCounter{expires: now.Add(time.Minute)}
	}
	if counter.count >= limit {
		return false, max(1, int((counter.expires.Sub(now)+time.Second-1)/time.Second))
	}
	counter.count++
	l.counters[key] = counter
	return true, 0
}

func parseTrustedProxies(values []string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, raw := range values {
		raw = strings.TrimSpace(raw)
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			ip, ipErr := netip.ParseAddr(raw)
			if ipErr != nil || ip.Zone() != "" {
				return nil, fmt.Errorf("invalid trusted proxy address or CIDR %q", raw)
			}
			ip = ip.Unmap()
			prefix = netip.PrefixFrom(ip, ip.BitLen())
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

func (s *Server) trustedProxy(ip netip.Addr) bool {
	for _, prefix := range s.trustedProxies {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Server) clientIP(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{} // Malformed peers share one bucket, never a bypass.
	}
	peer = peer.Unmap()
	if !s.trustedProxy(peer) {
		return peer
	}
	forwarded := strings.Join(r.Header.Values("X-Forwarded-For"), ",")
	if forwarded == "" || len(forwarded) > 4096 {
		return peer
	}
	chain := strings.Split(forwarded, ",")
	if len(chain) > 32 {
		return peer
	}
	// Walk from the trusted socket peer towards the client. An untrusted hop
	// cannot choose its own identity by prepending forged addresses.
	client := peer
	for i := len(chain) - 1; i >= 0 && s.trustedProxy(client); i-- {
		ip, err := netip.ParseAddr(strings.TrimSpace(chain[i]))
		if err != nil || ip.Zone() != "" {
			return peer
		}
		client = ip.Unmap()
	}
	return client
}

func (s *Server) authenticatedForRateLimit(r *http.Request) bool {
	if cookie, err := r.Cookie("auth"); err == nil && cookie.Value != "" {
		if _, ok, err := s.sessions.GetAuth(r.Context(), cookie.Value); err == nil && ok {
			return true
		}
	}
	if r.URL.Path == "/forward_auth" {
		target, err := s.forwardedAppURL(r)
		if err == nil {
			origin := target.Scheme + "://" + target.Host
			if cookie, err := r.Cookie(appCookieName(origin, "app")); err == nil {
				_, ok, err := s.sessions.getAppAuth(r.Context(), cookie.Value, origin)
				return err == nil && ok
			}
		}
	}
	return false
}

func (s *Server) enforceRateLimits(w http.ResponseWriter, r *http.Request) bool {
	ip, now := s.clientIP(r), time.Now()
	if !s.authenticatedForRateLimit(r) {
		if ok, retry := s.limits.allow(rateLimitKey{ip: ip}, anonymousRequestsPerMinute, now); !ok {
			writeRateLimit(w, retry)
			return false
		}
	}
	if r.Method == http.MethodPost && (r.URL.Path == "/api/login/begin" || r.URL.Path == "/api/login/finish") {
		if ok, retry := s.limits.allow(rateLimitKey{ip: ip, login: true}, loginRequestsPerMinute, now); !ok {
			writeRateLimit(w, retry)
			return false
		}
	}
	return true
}

func writeRateLimit(w http.ResponseWriter, retry int) {
	w.Header().Set("Retry-After", strconv.Itoa(retry))
	writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many requests; try again later"})
}
