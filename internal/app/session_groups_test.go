package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGroupSessionViews(t *testing.T) {
	// Two logins using one device remain separate. Duplicate app origins remain
	// individually addressable, and a missing/mismatched parent is never shown.
	views := groupSessionViews([]sessionView{
		{sessionSummary: sessionSummary{ID: "app-b", Kind: "Application", Username: "alice", ParentID: "first", Origin: testAppOrigin}},
		{sessionSummary: sessionSummary{ID: "second", Kind: "Gateway", Username: "alice", DeviceID: 1}},
		{sessionSummary: sessionSummary{ID: "orphan", Kind: "Application", Username: "alice", ParentID: "absent"}},
		{sessionSummary: sessionSummary{ID: "first", Kind: "Gateway", Username: "alice", DeviceID: 1}, Current: true, DeviceName: "Laptop"},
		{sessionSummary: sessionSummary{ID: "app-a", Kind: "Application", Username: "alice", ParentID: "first", Origin: testAppOrigin}},
		{sessionSummary: sessionSummary{ID: "foreign", Kind: "Application", Username: "bob", ParentID: "first", Origin: testAppOrigin}},
	})
	require.Len(t, views, 2)
	assert.Equal(t, "first", views[0].ID)
	assert.True(t, views[0].Current)
	assert.Equal(t, "Laptop", views[0].DeviceName)
	require.Len(t, views[0].Apps, 2)
	assert.Equal(t, "app-a", views[0].Apps[0].ID)
	assert.Equal(t, "app-b", views[0].Apps[1].ID)
	assert.True(t, strings.HasSuffix(views[0].Apps[0].Label, " · 1"))
	assert.True(t, strings.HasSuffix(views[0].Apps[1].Label, " · 2"))
	assert.Empty(t, views[1].Apps)
}

type failingAppDeletion struct{ sessionStore }

func (failingAppDeletion) DeleteAppSessions(context.Context, []string) error {
	return sessionStoreError(errors.New("backend detail must not be rendered"))
}

func TestPostgresSelectedAppSessionRemoval(t *testing.T) {
	s := postgresServer(t)
	addUser(t, s, "admin", true)
	addUser(t, s, "alice", false)
	addUser(t, s, "bob", false)
	ctx := t.Context()
	store := s.sessions.(*redisSessions)
	peer := peerRedisSessions(t, store)
	require.NoError(t, store.PutAuth(ctx, "other", "alice"))
	first := mintRedisAppSession(t, store, "other")
	second := mintRedisAppSession(t, store, "other")
	retained := mintRedisAppSession(t, store, "other")
	current := mintRedisAppSession(t, store, "alice-session")
	foreign := mintRedisAppSession(t, store, "bob-session")
	form := func(parent string, tokens ...string) string {
		values := url.Values{"gateway_id": {hashToken(parent)}}
		for _, token := range tokens {
			values.Add("session_id", hashToken(token))
		}
		return values.Encode()
	}
	// Warm another replica's caches before revoking anything.
	for _, token := range []string{first, second, retained, current, foreign} {
		_, live, err := peer.getAppAuth(ctx, token, testAppOrigin)
		require.NoError(t, err)
		require.True(t, live)
	}
	for _, tc := range []struct {
		body string
		code int
	}{
		{form("other"), 400},
		{form("other", first, first), 400},
		{form("other", first, "absent"), 404},
		{form("other", first, foreign), 404},
		{form("other", first, current), 404},
		{form("bob-session", foreign), 404},
		{form("alice-session", current), 409},
		{form("other", "other"), 404}, // A gateway ID cannot select an app.
		{"gateway_id=invalid&session_id=invalid", 400},
	} {
		w := request(s, "POST", "/ui/sessions/apps/remove", tc.body, "alice-session")
		assert.Equal(t, tc.code, w.Code, w.Body.String())
		for _, token := range []string{first, second, retained, current, foreign} {
			_, live, err := peer.getAppAuth(ctx, token, testAppOrigin)
			require.NoError(t, err)
			assert.True(t, live, "invalid batch deleted %s", hashToken(token))
		}
	}
	// Failures preserve the activity controls and selections, with no backend data.
	s.sessions = failingAppDeletion{store}
	r := httptest.NewRequest(http.MethodPost, "/ui/sessions/apps/remove", strings.NewReader(form("other", first, second)))
	r.AddCookie(&http.Cookie{Name: "auth", Value: "alice-session"})
	r.Header.Set("Origin", s.cfg.Origin)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("HX-Request", "true")
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	assert.Equal(t, 503, w.Code)
	assert.Equal(t, "#sessions-feedback", w.Header().Get("HX-Retarget"))
	assert.Equal(t, "innerHTML", w.Header().Get("HX-Reswap"))
	assert.NotContains(t, w.Body.String(), "backend detail")
	s.sessions = store

	w = request(s, "POST", "/ui/sessions/apps/remove", form("other", first, second), "alice-session")
	require.Equal(t, 200, w.Code, w.Body.String())
	for _, token := range []string{first, second} {
		_, live, err := peer.getAppAuth(ctx, token, testAppOrigin)
		require.NoError(t, err)
		assert.False(t, live)
		assert.NotContains(t, w.Body.String(), hashToken(token))
	}
	for _, token := range []string{retained, current, foreign} {
		_, live, err := peer.getAppAuth(ctx, token, testAppOrigin)
		require.NoError(t, err)
		assert.True(t, live)
	}
	_, live, err := peer.GetAuth(ctx, "other")
	require.NoError(t, err)
	assert.True(t, live, "app deletion revoked the parent")
	w = request(s, "POST", "/ui/sessions/apps/remove", form("other", retained), "alice-session")
	require.Equal(t, 200, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "No app sessions")
	assert.Contains(t, w.Body.String(), hashToken("other"))
	// Admins may delete another account's apps, with the same parent binding.
	w = request(s, "POST", "/ui/sessions/apps/remove", form("bob-session", foreign), "admin-session")
	require.Equal(t, 200, w.Code, w.Body.String())
	_, live, err = peer.getAppAuth(ctx, foreign, testAppOrigin)
	require.NoError(t, err)
	assert.False(t, live)
}

func TestRedisBatchAppDeletionRejectsInvalidReferences(t *testing.T) {
	store := testRedisSessions(t, "")
	ctx := t.Context()
	require.NoError(t, store.PutAuth(ctx, "parent", "alice"))
	app := mintRedisAppSession(t, store, "parent")
	require.ErrorIs(t, store.DeleteAppSessions(ctx, []string{hashToken(app), "invalid"}), errSessionStore)
	_, live, err := store.getAppAuth(ctx, app, testAppOrigin)
	require.NoError(t, err)
	assert.True(t, live)
	require.NoError(t, store.DeleteAppSessions(ctx, []string{hashToken(app)}))
	_, live, err = store.getAppAuth(ctx, app, testAppOrigin)
	require.NoError(t, err)
	assert.False(t, live)
}
