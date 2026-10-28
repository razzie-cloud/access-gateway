package app

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TEST_REDIS_URL must point to a disposable local backend. Only the random
// per-test namespace is removed; tests never flush a database or change CONFIG.
func testRedisSessions(t *testing.T, namespace string) *redisSessions {
	t.Helper()
	uri := os.Getenv("TEST_REDIS_URL")
	if uri == "" {
		t.Skip("TEST_REDIS_URL unset; Redis integration test")
	}
	if namespace == "" {
		namespace = "test-" + uuid.NewString()
	}
	s, err := newRedisSessions(uri, namespace)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		var cursor uint64
		var keys []string
		for {
			batch, next, err := s.client.Scan(ctx, cursor, s.prefix+"*", 100).Result()
			if err != nil {
				break
			}
			keys = append(keys, batch...)
			cursor = next
			if cursor == 0 {
				break
			}
		}
		if len(keys) > 0 {
			_ = s.client.Del(ctx, keys...).Err()
		}
		_ = s.Close()
	})
	return s
}

func peerRedisSessions(t *testing.T, first *redisSessions) *redisSessions {
	t.Helper()
	peer, err := newRedisSessions(os.Getenv("TEST_REDIS_URL"), "peer")
	require.NoError(t, err)
	peer.prefix = first.prefix
	t.Cleanup(func() { _ = peer.Close() })
	return peer
}

func TestRedisSessionsShareCeremoniesAndSurviveRestart(t *testing.T) {
	s := testRedisSessions(t, "")
	peer := peerRedisSessions(t, s)
	ctx := t.Context()
	registration := registrationContext{User: User{ID: []byte{1, 2, 3}, Username: "alice"}, LinkHash: hashToken("secret-link")}
	sd := webauthn.SessionData{Challenge: "challenge", UserID: []byte{1, 2, 3}, Expires: time.Now().UTC().Add(time.Minute)}
	require.NoError(t, s.PutRegistration(ctx, "reg", registration, sd))
	require.NoError(t, s.PutLogin(ctx, "login", "alice", sd))
	require.NoError(t, s.PutAuth(ctx, "auth", "alice"))
	got, data, ok, err := peer.GetRegistration(ctx, "reg")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, registration, got)
	assert.Equal(t, sd, data)
	name, data, ok, err := peer.GetLogin(ctx, "login")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "alice", name)
	assert.Equal(t, sd, data)
	name, ok, err = peer.GetAuth(ctx, "auth")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "alice", name)
	_, cached := peer.cache.get(peer.key("auth", "auth"))
	require.True(t, cached)
	// A fresh client has an empty process cache but sees the same Redis sessions.
	restarted := peerRedisSessions(t, s)
	name, ok, err = restarted.GetAuth(ctx, "auth")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "alice", name)
	assert.Positive(t, s.client.PTTL(ctx, s.key("registration", "reg")).Val())
	assert.LessOrEqual(t, s.client.PTTL(ctx, s.key("registration", "reg")).Val(), ceremonyTTL)
	assert.Greater(t, s.client.PTTL(ctx, s.key("auth", "auth")).Val(), authTTL-time.Minute)
	// Immutable token keys prevent a cached identity from being overwritten.
	require.ErrorIs(t, s.PutAuth(ctx, "auth", "bob"), errSessionStore)
	require.NoError(t, s.DeleteSID(ctx, "reg"))
	_, _, ok, err = peer.GetRegistration(ctx, "reg")
	require.NoError(t, err)
	assert.False(t, ok)
}

func mintRedisAppSession(t *testing.T, s *redisSessions, parent string) string {
	t.Helper()
	flow, state, err := s.beginAppLogin(t.Context(), testAppOrigin, testAppOrigin+"/private")
	require.NoError(t, err)
	code, ok, err := s.authorizeAppLogin(t.Context(), flow, parent)
	require.NoError(t, err)
	require.True(t, ok)
	token, target, ok, err := s.completeAppLogin(t.Context(), flow, code, state, testAppOrigin)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, testAppOrigin+"/private", target)
	return token
}

func TestRedisLogoutAndExpiryRejectWarmCaches(t *testing.T) {
	for _, operation := range []string{"logout", "expiry", "eviction"} {
		t.Run(operation, func(t *testing.T) {
			s := testRedisSessions(t, "")
			peer := peerRedisSessions(t, s)
			ctx := t.Context()
			require.NoError(t, s.PutAuth(ctx, "parent", "alice"))
			token := mintRedisAppSession(t, s, "parent")
			name, ok, err := peer.getAppAuth(ctx, token, testAppOrigin)
			require.NoError(t, err)
			require.True(t, ok)
			assert.Equal(t, "alice", name)
			_, cached := peer.cache.get(peer.key("app", token))
			require.True(t, cached)
			switch operation {
			case "logout":
				require.NoError(t, s.DeleteAuth(ctx, "parent"))
			case "expiry":
				require.NoError(t, s.client.PExpireAt(ctx, s.key("auth", "parent"), time.Now().Add(-time.Second)).Err())
			case "eviction":
				require.NoError(t, s.client.Del(ctx, s.key("auth", "parent")).Err())
			}
			name, ok, err = peer.getAppAuth(ctx, token, testAppOrigin)
			require.NoError(t, err)
			assert.False(t, ok)
			assert.Empty(t, name)
			_, ok, err = peer.GetAuth(ctx, "parent")
			require.NoError(t, err)
			assert.False(t, ok)
		})
	}
}

func TestRedisFailureDeniesCachedSessions(t *testing.T) {
	s := testRedisSessions(t, "")
	peer := peerRedisSessions(t, s)
	ctx := t.Context()
	require.NoError(t, s.PutAuth(ctx, "parent", "alice"))
	token := mintRedisAppSession(t, s, "parent")
	_, ok, err := peer.getAppAuth(ctx, token, testAppOrigin)
	require.NoError(t, err)
	require.True(t, ok)
	require.NoError(t, peer.Close()) // Deterministic connection failure with a warm cache.
	_, ok, err = peer.getAppAuth(ctx, token, testAppOrigin)
	require.ErrorIs(t, err, errSessionStore)
	assert.False(t, ok)
	_, ok, err = peer.GetAuth(ctx, "parent")
	require.ErrorIs(t, err, errSessionStore)
	assert.False(t, ok)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, ok, err = s.GetAuth(cancelled, "parent")
	require.ErrorIs(t, err, errSessionStore)
	assert.False(t, ok)
}

func TestRedisLoginIsConsumedOnceAcrossReplicas(t *testing.T) {
	s := testRedisSessions(t, "")
	peer := peerRedisSessions(t, s)
	ctx := t.Context()
	require.NoError(t, s.PutLogin(ctx, "sid", "alice", webauthn.SessionData{Challenge: "challenge"}))
	_, _, ok, err := peer.GetLogin(ctx, "sid")
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = s.CompleteLogin(ctx, "sid", "wrong", "bob", 0)
	require.NoError(t, err)
	assert.False(t, ok)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			store := s
			if i%2 == 1 {
				store = peer
			}
			ok, err := store.CompleteLogin(ctx, "sid", fmt.Sprint("token-", i), "alice", 0)
			assert.NoError(t, err)
			if ok {
				wins.Add(1)
			}
		})
	}
	wg.Wait()
	assert.EqualValues(t, 1, wins.Load())
	_, _, ok, err = peer.GetLogin(ctx, "sid")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestRedisCallbackIsConsumedOnceAcrossReplicas(t *testing.T) {
	s := testRedisSessions(t, "")
	peer := peerRedisSessions(t, s)
	ctx := t.Context()
	require.NoError(t, s.PutAuth(ctx, "parent", "alice"))
	flow, state, err := s.beginAppLogin(ctx, testAppOrigin, testAppOrigin+"/private")
	require.NoError(t, err)
	_, ok, err := peer.appLogin(ctx, flow)
	require.NoError(t, err)
	require.True(t, ok)
	code, ok, err := peer.authorizeAppLogin(ctx, flow, "parent")
	require.NoError(t, err)
	require.True(t, ok)
	for _, mismatch := range []string{"origin", "code", "state", "flow"} {
		f, c, v, o := flow, code, state, testAppOrigin
		switch mismatch {
		case "origin":
			o = "https://other.example"
		case "code":
			c = "wrong"
		case "state":
			v = "wrong"
		case "flow":
			f = "wrong"
		}
		_, _, ok, err := s.completeAppLogin(ctx, f, c, v, o)
		require.NoError(t, err)
		assert.False(t, ok, mismatch)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := range 24 {
		wg.Go(func() {
			store := s
			if i%2 == 1 {
				store = peer
			}
			token, target, ok, err := store.completeAppLogin(ctx, flow, code, state, testAppOrigin)
			assert.NoError(t, err)
			if ok {
				wins.Add(1)
				assert.NotEmpty(t, token)
				assert.Equal(t, testAppOrigin+"/private", target)
			}
		})
	}
	wg.Wait()
	assert.EqualValues(t, 1, wins.Load())
	_, ok, err = peer.appLogin(ctx, flow)
	require.NoError(t, err)
	assert.False(t, ok, "warm flow cache bypassed single-use check")
}

func TestRedisHandoffExpiryAndLogout(t *testing.T) {
	for _, expired := range []string{"flow", "grant", "parent"} {
		t.Run(expired, func(t *testing.T) {
			s := testRedisSessions(t, "")
			ctx := t.Context()
			require.NoError(t, s.PutAuth(ctx, "parent", "alice"))
			flow, state, err := s.beginAppLogin(ctx, testAppOrigin, testAppOrigin+"/")
			require.NoError(t, err)
			code, ok, err := s.authorizeAppLogin(ctx, flow, "parent")
			require.NoError(t, err)
			require.True(t, ok)
			keys := map[string]string{"flow": s.key("flow", flow), "grant": s.key("grant", code), "parent": s.key("auth", "parent")}
			require.NoError(t, s.client.PExpireAt(ctx, keys[expired], time.Now().Add(-time.Second)).Err())
			_, _, ok, err = s.completeAppLogin(ctx, flow, code, state, testAppOrigin)
			require.NoError(t, err)
			assert.False(t, ok)
		})
	}
}

func TestRedisDoesNotStoreBearerTokens(t *testing.T) {
	s := testRedisSessions(t, "")
	ctx := t.Context()
	parent := "parent-bearer-token-that-must-not-appear"
	require.NoError(t, s.PutAuth(ctx, parent, "alice"))
	flow, state, err := s.beginAppLogin(ctx, testAppOrigin, testAppOrigin+"/")
	require.NoError(t, err)
	code, ok, err := s.authorizeAppLogin(ctx, flow, parent)
	require.NoError(t, err)
	require.True(t, ok)
	for _, key := range []string{s.key("auth", parent), s.key("flow", flow), s.key("grant", code)} {
		payload, err := s.client.Get(ctx, key).Result()
		require.NoError(t, err)
		for _, secret := range []string{parent, flow, state, code} {
			assert.NotContains(t, key, secret)
			assert.NotContains(t, payload, secret)
		}
	}
}

func TestRedisNamespaceAndCorruptSession(t *testing.T) {
	s := testRedisSessions(t, "")
	other := testRedisSessions(t, "")
	ctx := t.Context()
	require.NoError(t, s.PutAuth(ctx, "token", "alice"))
	_, ok, err := other.GetAuth(ctx, "token")
	require.NoError(t, err)
	assert.False(t, ok)
	key := s.key("auth", "corrupt")
	require.NoError(t, s.client.Set(ctx, key, "{", time.Minute).Err())
	_, ok, err = s.GetAuth(ctx, "corrupt")
	require.ErrorIs(t, err, errSessionStore)
	assert.False(t, ok)
	require.NoError(t, s.client.Set(ctx, s.key("auth", "no-expiry"), `{"Username":"alice"}`, 0).Err())
	_, ok, err = s.GetAuth(ctx, "no-expiry")
	require.NoError(t, err)
	assert.False(t, ok)
	assert.True(t, strings.Contains(s.prefix, "{"), "Redis script keys must share a hash slot")
}

func TestSessionCacheBoundsAndExpiry(t *testing.T) {
	c := newSessionCache()
	c.put("old", 1, time.Now().Add(-time.Second))
	_, ok := c.get("old")
	assert.False(t, ok)
	for i := range sessionCacheSize + 1 {
		c.put(fmt.Sprint(i), i, time.Now().Add(time.Minute))
	}
	assert.Len(t, c.entries, sessionCacheSize)
	_, ok = c.get("0")
	assert.False(t, ok)
	_, ok = c.get("1")
	require.True(t, ok)
	c.put("next", 2, time.Now().Add(time.Minute))
	_, ok = c.get("1")
	assert.True(t, ok, "recently used entry was evicted")
	_, ok = c.get("2")
	assert.False(t, ok)
}

var _ sessionStore = (*redisSessions)(nil)

func TestRedisFlowCapacityAndParentExpiry(t *testing.T) {
	s := testRedisSessions(t, "")
	ctx := t.Context()
	pipe := s.client.Pipeline()
	for i := range maxAppLoginFlows {
		pipe.ZAddArgs(ctx, s.prefix+"flows", redis.ZAddArgs{Members: []redis.Z{{Score: float64(time.Now().Add(time.Hour).UnixMilli()), Member: fmt.Sprint(i)}}})
	}
	_, err := pipe.Exec(ctx)
	require.NoError(t, err)
	_, _, err = s.beginAppLogin(ctx, testAppOrigin, testAppOrigin+"/")
	require.ErrorIs(t, err, errSessionStore)
	require.NoError(t, s.client.ZRem(ctx, s.prefix+"flows", "0").Err())
	require.NoError(t, s.PutAuth(ctx, "parent", "alice"))
	require.NoError(t, s.client.PExpire(ctx, s.key("auth", "parent"), 5*time.Second).Err())
	token := mintRedisAppSession(t, s, "parent")
	assert.LessOrEqual(t, s.client.PTTL(ctx, s.key("app", token)).Val(), 5*time.Second)
	name, ok, err := s.getAppAuth(ctx, token, "https://wrong.example")
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Empty(t, name)
}

func TestRedisFailureReturns503WithoutIssuingCookies(t *testing.T) {
	s := unitServer()
	store := testRedisSessions(t, "")
	s.sessions = peerRedisSessions(t, store)
	s.cfg.ForwardAuthOrigins = []string{testAppOrigin}
	require.NoError(t, store.PutAuth(t.Context(), "parent", "alice"))
	token := mintRedisAppSession(t, store, "parent")
	flow, _, err := store.beginAppLogin(t.Context(), testAppOrigin, testAppOrigin+"/")
	require.NoError(t, err)
	require.NoError(t, s.sessions.Close())
	for _, tc := range []struct{ method, path string }{
		{"GET", "/api/me"}, {"POST", "/api/logout"}, {"POST", "/ui/logout"},
		{"POST", "/ui/users"}, {"POST", "/ui/links"}, {"GET", "/auth/authorize?flow=" + flow},
		{"GET", "/ui/admin"},
		{"GET", "/ui/activity"}, {"POST", "/ui/devices/rename"}, {"POST", "/ui/devices/remove"}, {"POST", "/ui/sessions/remove"},
	} {
		w := request(s, tc.method, tc.path, `{}`, "parent")
		assert.Equal(t, 503, w.Code, tc.path)
		assert.Empty(t, w.Header().Get("Set-Cookie"), tc.path)
	}
	w := forwardRequest(s, testAppOrigin, "/", &http.Cookie{Name: appCookieName(testAppOrigin, "app"), Value: token})
	assert.Equal(t, 503, w.Code)
	assert.Empty(t, w.Header().Get("X-Auth-Request-User"))
	assert.Empty(t, w.Header().Get("Set-Cookie"))
}
