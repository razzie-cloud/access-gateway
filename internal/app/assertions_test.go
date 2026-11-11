package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/stretchr/testify/require"
)

type memoryAssertionKeys struct {
	mu   sync.Mutex
	keys map[time.Time]paseto.V4AsymmetricSecretKey
}

func (m *memoryAssertionKeys) assertionKey(_ context.Context, start time.Time) (paseto.V4AsymmetricSecretKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.keys == nil {
		m.keys = make(map[time.Time]paseto.V4AsymmetricSecretKey)
	}
	key, ok := m.keys[start]
	if !ok {
		key = paseto.NewV4AsymmetricSecretKey()
		m.keys[start] = key
	}
	return key, nil
}

func TestAssertionKeysAndRequestClaims(t *testing.T) {
	s := unitServer()
	now := time.Now().UTC().Truncate(time.Second)
	set, err := s.assertionKeys(t.Context(), now)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(set.Keys), 2)
	require.Equal(t, s.cfg.Origin, set.Issuer)
	signed, err := s.signIdentity(t.Context(), now, "user-id", "alice", testAppOrigin, "POST", "/save?q=one", true)
	require.NoError(t, err)
	parser := paseto.NewParserWithoutExpiryCheck()
	footer, err := parser.UnsafeParseFooter(paseto.V4Public, signed)
	require.NoError(t, err)
	var public paseto.V4AsymmetricPublicKey
	for _, key := range set.Keys {
		if key.ID == string(footer) {
			public, err = paseto.NewV4AsymmetricPublicKeyFromHex(key.PublicKey)
			require.NoError(t, err)
		}
	}
	parser.AddRule(paseto.ValidAt(now), paseto.IssuedBy(s.cfg.Origin), paseto.ForAudience(testAppOrigin))
	token, err := parser.ParseV4Public(public, signed, nil)
	require.NoError(t, err)
	for claim, want := range map[string]string{"sub": "user-id", "name": "alice", "method": "POST", "uri": "/save?q=one"} {
		value, err := token.GetString(claim)
		require.NoError(t, err)
		require.Equal(t, want, value)
	}
	var admin bool
	require.NoError(t, token.Get("admin", &admin))
	require.True(t, admin)
	exp, err := token.GetExpiration()
	require.NoError(t, err)
	require.Equal(t, now.Add(assertionTTL), exp)
	w := request(s, "GET", "/.well-known/paseto-keys", "", "")
	require.Equal(t, http.StatusOK, w.Code)
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &set))
	require.NotContains(t, w.Body.String(), "secret")
	w = request(s, "HEAD", "/.well-known/paseto-keys", "", "")
	require.Equal(t, http.StatusOK, w.Code)
	require.Empty(t, w.Body.String())
}

func TestRedisAssertionKeysConcurrentRotationAndRestart(t *testing.T) {
	store := testRedisSessions(t, "")
	peer := peerRedisSessions(t, store)
	start := time.Now().UTC().Truncate(signingPeriod)
	const count = 16
	results := make(chan string, count)
	var wg sync.WaitGroup
	for i := range count {
		wg.Go(func() {
			backend := store
			if i%2 == 0 {
				backend = peer
			}
			key, err := backend.assertionKey(t.Context(), start)
			if err != nil {
				results <- ""
				return
			}
			results <- key.ExportHex()
		})
	}
	wg.Wait()
	close(results)
	var first string
	for value := range results {
		require.NotEmpty(t, value)
		if first == "" {
			first = value
		}
		require.Equal(t, first, value)
	}
	restarted := peerRedisSessions(t, store)
	key, err := restarted.assertionKey(t.Context(), start)
	require.NoError(t, err)
	require.Equal(t, first, key.ExportHex())
	next, err := peer.assertionKey(t.Context(), start.Add(signingPeriod))
	require.NoError(t, err)
	require.NotEqual(t, first, next.ExportHex())
	s := &Server{cfg: Config{Origin: "https://auth.example"}, assertions: store}
	before, err := s.assertionKeys(t.Context(), start.Add(signingPeriod-time.Second))
	require.NoError(t, err)
	after, err := s.assertionKeys(t.Context(), start.Add(signingPeriod+time.Second))
	require.NoError(t, err)
	require.Equal(t, before.Keys[1].ID, after.Keys[1].ID, "prepublished key must be active after rotation")
	require.Equal(t, before.Keys[0].ID, after.Keys[0].ID, "previous key overlaps")
	deadline := start.Add(signingPeriod + keyOverlap)
	ttl, err := store.client.PTTL(t.Context(), store.prefix+"paseto:"+strconv.FormatInt(start.Unix(), 10)).Result()
	require.NoError(t, err)
	require.InDelta(t, time.Until(deadline).Milliseconds(), ttl.Milliseconds(), 1000)
}

type failedAssertionKeys struct{}

func (failedAssertionKeys) assertionKey(context.Context, time.Time) (paseto.V4AsymmetricSecretKey, error) {
	return paseto.V4AsymmetricSecretKey{}, errors.New("unavailable")
}
func TestAssertionKeysUnavailable(t *testing.T) {
	s := unitServer()
	s.assertions = failedAssertionKeys{}
	w := request(s, "GET", "/.well-known/paseto-keys", "", "")
	require.Equal(t, http.StatusServiceUnavailable, w.Code)
	require.Empty(t, w.Header().Get(assertionHeader))
}
