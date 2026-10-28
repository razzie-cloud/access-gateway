package app

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdminRequiresLiveSession(t *testing.T) {
	s := unitServer()
	testMemory(s).auth["expired"] = authEntry{username: "admin", exp: time.Now().Add(-time.Minute)}
	for _, token := range []string{"", "unknown", "expired"} {
		w := request(s, "GET", "/ui/admin", "", token)
		assert.Equal(t, 401, w.Code)
		assert.NotContains(t, w.Body.String(), "<table>")
	}
}

func TestPostgresAdminPanel(t *testing.T) {
	s := postgresServer(t)
	admin := addUser(t, s, "admin", true)
	member := addUser(t, s, "member", false)
	// Accounts without a passkey or session must still appear.
	id := uuid.New()
	_, err := s.db.Exec(`INSERT INTO users(id,username,is_admin,created_at) VALUES($1,$2,FALSE,0)`, id[:], "<pending>")
	require.NoError(t, err)
	appToken := mintRedisAppSession(t, s.sessions.(*redisSessions), "member-session")
	for _, token := range []string{"", "unknown", "member-session"} {
		w := request(s, "GET", "/ui/admin", "", token)
		want := 401
		if token == "member-session" {
			want = 403
		}
		assert.Equal(t, want, w.Code)
		assert.NotContains(t, w.Body.String(), "<table>")
		assert.NotContains(t, w.Body.String(), id.String())
	}
	for _, token := range []string{"admin-session", "member-session", ""} {
		w := request(s, "GET", "/", "", token)
		require.Equal(t, 200, w.Code)
		assert.Equal(t, token != "", strings.Contains(w.Body.String(), `id="activity-data"`))
	}
	w := request(s, "GET", "/ui/admin", "", "admin-session")
	require.Equal(t, 200, w.Code, w.Body.String())
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	for _, u := range []User{admin, member} {
		uid, err := uuid.FromBytes(u.ID)
		require.NoError(t, err)
		assert.Contains(t, w.Body.String(), uid.String())
	}
	assert.Contains(t, w.Body.String(), id.String())
	assert.Contains(t, w.Body.String(), "&lt;pending&gt;")
	assert.Contains(t, w.Body.String(), "Users (3)")
	assert.Contains(t, w.Body.String(), "Active sessions (3)")
	assert.Contains(t, w.Body.String(), testAppOrigin)
	for _, secret := range []string{"admin-session", "member-session", appToken} {
		assert.NotContains(t, w.Body.String(), secret)
	}
	// Check the role on every request, including after a demotion.
	_, err = s.db.Exec(`UPDATE users SET is_admin=FALSE WHERE username='admin'`)
	require.NoError(t, err)
	w = request(s, "GET", "/ui/admin", "", "admin-session")
	assert.Equal(t, 403, w.Code)
}

func TestActivityTemplateEscapesMetadataAndHidesUsersForMembers(t *testing.T) {
	data := viewData{
		User:     &User{IsAdmin: true},
		Sessions: []sessionView{{sessionSummary: sessionSummary{Username: "<script>name</script>", Origin: `<img src=x onerror="alert(1)">`}}},
	}
	w := httptest.NewRecorder()
	render(w, 200, "activity", data)
	assert.NotContains(t, w.Body.String(), "<script>")
	assert.NotContains(t, w.Body.String(), "<img")
	assert.Contains(t, w.Body.String(), "&lt;script&gt;")
	data.User.IsAdmin = false
	w = httptest.NewRecorder()
	render(w, 200, "activity", data)
	assert.NotContains(t, w.Body.String(), "<h3>Users")
	data.User = nil
	w = httptest.NewRecorder()
	render(w, 200, "activity", data)
	assert.NotContains(t, w.Body.String(), "<table>")
}

func TestRedisSessionListing(t *testing.T) {
	s := testRedisSessions(t, "")
	peer := peerRedisSessions(t, s)
	other := testRedisSessions(t, "")
	ctx := t.Context()
	require.NoError(t, other.PutAuth(ctx, "other-namespace", "hidden"))
	for i := range 140 {
		require.NoError(t, s.PutAuth(ctx, fmt.Sprint("session-", i), "alice"))
	}
	app := mintRedisAppSession(t, s, "session-0")
	// These records must not count as active authenticated sessions.
	require.NoError(t, s.PutAuth(ctx, "revoked", "bob"))
	mintRedisAppSession(t, s, "revoked")
	require.NoError(t, s.DeleteAuth(ctx, "revoked"))
	require.NoError(t, s.PutAuth(ctx, "expired", "bob"))
	require.NoError(t, s.client.PExpireAt(ctx, s.key("auth", "expired"), time.Now().Add(-time.Minute)).Err())
	require.NoError(t, s.client.Set(ctx, s.key("auth", "no-ttl"), `{"Username":"bob"}`, 0).Err())
	_, _, err := s.beginAppLogin(ctx, testAppOrigin, testAppOrigin+"/")
	require.NoError(t, err)
	sessions, err := peer.ListSessions(ctx)
	require.NoError(t, err)
	require.Len(t, sessions, 141)
	ids := make(map[string]bool)
	for _, session := range sessions {
		assert.Equal(t, "alice", session.Username)
		assert.False(t, ids[session.ID], "duplicate session")
		ids[session.ID] = true
		assert.WithinDuration(t, time.Now().Add(authTTL), session.ExpiresAt, time.Minute)
		if session.Kind == "Application" {
			assert.Equal(t, testAppOrigin, session.Origin)
			assert.Equal(t, hashToken(app), session.ID)
		}
	}
	require.NoError(t, s.DeleteAuth(ctx, "session-0"))
	sessions, err = peer.ListSessions(ctx)
	require.NoError(t, err)
	assert.Len(t, sessions, 139)
	require.NoError(t, peer.Close())
	sessions, err = peer.ListSessions(ctx)
	require.ErrorIs(t, err, errSessionStore)
	assert.Empty(t, sessions)
}
