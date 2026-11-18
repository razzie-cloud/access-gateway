package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func accessForm(user User, enabled bool) string {
	return url.Values{"user_id": {userID(user.ID)}, "enabled": {fmt.Sprint(enabled)}}.Encode()
}

type failedUserRevocation struct{ sessionStore }

func (failedUserRevocation) RevokeUserSessions(context.Context, string) error {
	return sessionStoreError(errors.New("private backend detail"))
}

type failedUserActivity struct{ failedUserRevocation }

func (failedUserActivity) ListSessions(context.Context) ([]sessionSummary, error) {
	return nil, sessionStoreError(errors.New("private backend detail"))
}

func TestPostgresUserAccess(t *testing.T) {
	s := postgresServer(t)
	admin := addUser(t, s, "admin", true)
	alice := addUser(t, s, "Alice", false)
	addUser(t, s, "bob", false)
	credential, key, _ := signingDevice(t, s, alice)
	store := s.sessions.(*redisSessions)
	peer := peerRedisSessions(t, store)
	app := mintRedisAppSession(t, store, "Alice-session")
	link := issueLink(t, s, "admin", "Alice", 60)
	registration, err := s.registrationFromLink(t.Context(), link)
	require.NoError(t, err)
	// This signed ceremony began while enabled, and must fail after disabling.
	w := request(s, "POST", "/api/login/begin", `{"username":"alice"}`, "")
	require.Equal(t, 200, w.Code)
	sid := w.Result().Cookies()[0].Value
	_, sd, _, err := store.GetLogin(t.Context(), sid)
	require.NoError(t, err)
	body := signedAssertion(t, s, key, credential.ID, alice.ID, sd.Challenge, s.cfg.Origin)
	_, live, err := peer.getAppAuth(t.Context(), app, testAppOrigin)
	require.NoError(t, err)
	require.True(t, live)
	w = request(s, "POST", "/ui/users/access?devices_user=all&sessions_user=all", accessForm(alice, false), "admin-session")
	require.Equal(t, 200, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "Further login attempts are blocked")
	assert.Contains(t, w.Body.String(), `id="devices-user-value" name="devices_user" value="all"`)
	u, err := s.getUserByUsername(t.Context(), "ALICE")
	require.NoError(t, err)
	assert.True(t, u.Disabled)
	for _, token := range []string{"Alice-session"} {
		_, live, err := peer.GetAuth(t.Context(), token)
		require.NoError(t, err)
		assert.False(t, live)
	}
	_, live, err = peer.getAppAuth(t.Context(), app, testAppOrigin)
	require.NoError(t, err)
	assert.False(t, live)
	assert.Zero(t, store.client.Exists(t.Context(), store.key("app", app)).Val())
	_, live, err = store.GetAuth(t.Context(), "bob-session")
	require.NoError(t, err)
	assert.True(t, live)
	assert.Equal(t, 401, loginFinishRequest(s, sid, body).Code)
	_, err = s.completeDeviceLogin(t.Context(), sid, "forged", alice, credential)
	assert.ErrorIs(t, err, errUserDisabled)
	assert.ErrorIs(t, s.completeRegistration(t.Context(), registration, &webauthn.Credential{ID: []byte("blocked")}), errRegistrationUnavailable)
	for _, path := range []string{"/api/login/link", "/api/register/link", "/api/register/begin"} {
		assert.Equal(t, 403, request(s, "POST", path, `{"linkToken":"`+link+`"}`, "").Code, path)
	}
	allowed, dummy, err := s.loginCredentials(t.Context(), "ALICE")
	require.NoError(t, err)
	for _, item := range allowed {
		assert.NotEqual(t, credential.ID, item.CredentialID, "disabled user received a real credential ID")
	}
	assert.NotEqual(t, alice.ID, dummy.User.ID)
	assert.Equal(t, 409, request(s, "POST", "/ui/links", "username=Alice&minutes=60", "admin-session").Code)
	w = request(s, "POST", "/ui/users/access", accessForm(alice, true), "admin-session")
	require.Equal(t, 200, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "deleted sessions are not restored")
	_, live, err = store.GetAuth(t.Context(), "Alice-session")
	require.NoError(t, err)
	assert.False(t, live)
	// The unconsumed link and original passkey still work after re-enabling.
	assert.Equal(t, 200, request(s, "POST", "/api/login/link", `{"linkToken":"`+link+`"}`, "").Code)
	assert.Equal(t, 200, loginFinishRequest(s, sid, body).Code)
	// Idempotent enable must retain the user's newly created sessions.
	before, err := store.ListSessions(t.Context())
	require.NoError(t, err)
	_, err = s.changeUserAccess(t.Context(), admin, alice.ID, true)
	require.NoError(t, err)
	after, err := store.ListSessions(t.Context())
	require.NoError(t, err)
	beforeIDs, afterIDs := []string{}, []string{}
	for _, session := range before {
		beforeIDs = append(beforeIDs, session.ID)
	}
	for _, session := range after {
		afterIDs = append(afterIDs, session.ID)
	}
	assert.Equal(t, beforeIDs, afterIDs)
}

func TestPostgresUserAccessGuards(t *testing.T) {
	s := postgresServer(t)
	admin := addUser(t, s, "admin", true)
	alice := addUser(t, s, "alice", false)
	assert.Equal(t, 401, request(s, "POST", "/ui/users/access", accessForm(alice, false), "").Code)
	assert.Equal(t, 403, request(s, "POST", "/ui/users/access", accessForm(admin, false), "alice-session").Code)
	assert.Equal(t, 409, request(s, "POST", "/ui/users/access", accessForm(admin, false), "admin-session").Code)
	for _, body := range []string{"", "user_id=invalid&enabled=false", "user_id=" + userID(alice.ID), accessForm(alice, false) + "&enabled=true", accessForm(alice, false) + "&user_id=" + userID(admin.ID), "user_id=" + userID(alice.ID) + "&enabled=off"} {
		assert.Equal(t, 400, request(s, "POST", "/ui/users/access", body, "admin-session").Code, body)
	}
	assert.Equal(t, 404, request(s, "POST", "/ui/users/access", "user_id="+uuid.NewString()+"&enabled=false", "admin-session").Code)
	r := httptest.NewRequest("POST", "/ui/users/access", strings.NewReader(accessForm(alice, false)))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: "auth", Value: "admin-session"})
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	assert.Equal(t, 403, w.Code, "missing Origin accepted")
	_, err := s.db.Exec(`UPDATE users SET is_admin=FALSE WHERE id=$1`, admin.ID)
	require.NoError(t, err)
	_, err = s.changeUserAccess(t.Context(), admin, alice.ID, false)
	assert.ErrorIs(t, err, errUserAccessForbidden, "stale admin role trusted")
}

func TestPostgresUserAccessRevocationFailure(t *testing.T) {
	s := postgresServer(t)
	admin := addUser(t, s, "admin", true)
	alice := addUser(t, s, "alice", true)
	store := s.sessions.(*redisSessions)
	app := mintRedisAppSession(t, store, "alice-session")
	s.cfg.ForwardAuthOrigins = []string{testAppOrigin}
	authorize, state := startAppLogin(t, s, testAppOrigin, "/")
	w := request(s, "GET", authorize, "", "alice-session")
	require.Equal(t, 303, w.Code)
	callback, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	s.sessions = failedUserRevocation{store}
	for _, enabled := range []bool{false, true} {
		w = request(s, "POST", "/ui/users/access", accessForm(alice, enabled), "admin-session")
		require.Equal(t, 503, w.Code, w.Body.String())
		assert.Contains(t, w.Body.String(), "User remains disabled")
		assert.NotContains(t, w.Body.String(), "private backend detail")
		u, err := s.getUserByUsername(t.Context(), "alice")
		require.NoError(t, err)
		assert.True(t, u.Disabled)
	}
	// The Redis sessions still exist, but no authentication surface accepts them.
	_, live, err := store.GetAuth(t.Context(), "alice-session")
	require.NoError(t, err)
	require.True(t, live)
	assert.JSONEq(t, `{"authenticated":false,"username":""}`, request(s, "GET", "/api/me", "", "alice-session").Body.String())
	assert.Equal(t, 401, request(s, "GET", "/ui/activity", "", "alice-session").Code)
	for _, endpoint := range []string{"/forward_auth", "/forward_auth/admin"} {
		w = forwardRequestTo(s, endpoint, testAppOrigin, "/", &http.Cookie{Name: appCookieName(testAppOrigin, "app"), Value: app})
		assert.Equal(t, 401, w.Code)
		assert.Empty(t, w.Header().Get(assertionHeader))
	}
	w = request(s, "GET", authorize, "", "alice-session")
	assert.Equal(t, 200, w.Code)
	assert.Empty(t, w.Header().Get("Location"), "disabled user issued an SSO grant")
	w = forwardRequest(s, testAppOrigin, callback.RequestURI(), state)
	assert.Equal(t, 401, w.Code, "disabled user redeemed an earlier SSO grant")
	assert.Empty(t, w.Result().Cookies())
	s.sessions = store
	_, err = s.changeUserAccess(t.Context(), admin, alice.ID, true)
	require.NoError(t, err)
	_, live, err = store.GetAuth(t.Context(), "alice-session")
	require.NoError(t, err)
	assert.False(t, live, "re-enable resurrected old session")
}

func TestPostgresUserAccessFailureRefreshesAuthoritativeSwitch(t *testing.T) {
	s := postgresServer(t)
	addUser(t, s, "admin", true)
	alice := addUser(t, s, "alice", false)
	store := s.sessions
	s.sessions = failedUserActivity{failedUserRevocation{store}}
	r := httptest.NewRequest("POST", "/ui/users/access", strings.NewReader(accessForm(alice, false)))
	r.Header.Set("Origin", s.cfg.Origin)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("HX-Request", "true")
	r.Header.Set("HX-Target", "activity-data")
	r.AddCookie(&http.Cookie{Name: "auth", Value: "admin-session"})
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	require.Equal(t, 503, w.Code)
	assert.Equal(t, "#users", w.Header().Get("HX-Retarget"))
	assert.Equal(t, "outerHTML", w.Header().Get("HX-Reswap"))
	assert.Contains(t, w.Body.String(), "User remains disabled")
	assert.NotContains(t, w.Body.String(), "private backend detail")
	assert.Contains(t, w.Body.String(), `value="true"`)
	assert.NotContains(t, w.Body.String(), `id="devices"`)
	u, err := s.getUserByUsername(t.Context(), "alice")
	require.NoError(t, err)
	assert.True(t, u.Disabled)
}

type pausedLogin struct {
	sessionStore
	entered, resume chan struct{}
}

func (s pausedLogin) CompleteLogin(ctx context.Context, sid, token, username string, deviceID int64) (bool, error) {
	close(s.entered)
	select {
	case <-s.resume:
		return s.sessionStore.CompleteLogin(ctx, sid, token, username, deviceID)
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

func (s pausedLogin) PutLinkAuth(ctx context.Context, token, username string) error {
	close(s.entered)
	select {
	case <-s.resume:
		return s.sessionStore.PutLinkAuth(ctx, token, username)
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestPostgresUserDisableConcurrentLogin(t *testing.T) {
	s := postgresServer(t)
	admin := addUser(t, s, "admin", true)
	alice := addUser(t, s, "alice", false)
	_, credential := addDevice(t, s, alice, "Phone")
	require.NoError(t, s.sessions.PutLogin(t.Context(), "pending", alice.Username, webauthn.SessionData{}))
	paused := pausedLogin{s.sessions, make(chan struct{}), make(chan struct{})}
	loginServer := &Server{db: s.db, sessions: paused}
	loginDone, disableDone := make(chan error, 1), make(chan error, 1)
	go func() {
		_, err := loginServer.completeDeviceLogin(t.Context(), "pending", "racing", alice, credential)
		loginDone <- err
	}()
	<-paused.entered
	go func() { _, err := s.changeUserAccess(t.Context(), admin, alice.ID, false); disableDone <- err }()
	select {
	case err := <-disableDone:
		t.Fatalf("disable passed an in-flight login: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(paused.resume)
	require.NoError(t, <-loginDone)
	require.NoError(t, <-disableDone)
	_, live, err := s.sessions.GetAuth(t.Context(), "racing")
	require.NoError(t, err)
	assert.False(t, live, "in-flight login escaped revocation")
	_, err = s.completeDeviceLogin(t.Context(), "pending", "later", alice, credential)
	assert.ErrorIs(t, err, errUserDisabled)
}

func TestPostgresUserDisableConcurrentLinkLogin(t *testing.T) {
	s := postgresServer(t)
	admin := addUser(t, s, "admin", true)
	alice := addUser(t, s, "alice", false)
	link := issueLink(t, s, "admin", "alice", 60)
	paused := pausedLogin{s.sessions, make(chan struct{}), make(chan struct{})}
	loginServer := &Server{db: s.db, sessions: paused}
	loginDone, disableDone := make(chan error, 1), make(chan error, 1)
	var token string
	go func() {
		var err error
		token, _, err = loginServer.completeLinkLogin(t.Context(), link)
		loginDone <- err
	}()
	<-paused.entered
	go func() {
		_, err := s.changeUserAccess(t.Context(), admin, alice.ID, false)
		disableDone <- err
	}()
	select {
	case err := <-disableDone:
		t.Fatalf("disable passed an in-flight link login: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(paused.resume)
	require.NoError(t, <-loginDone)
	require.NoError(t, <-disableDone)
	_, live, err := s.sessions.GetAuth(t.Context(), token)
	require.NoError(t, err)
	assert.False(t, live, "in-flight link login escaped revocation")
}

func TestPostgresAdministratorsCannotDisableEachOtherConcurrently(t *testing.T) {
	s := postgresServer(t)
	first := addUser(t, s, "first", true)
	second := addUser(t, s, "second", true)
	start := make(chan struct{})
	var wg sync.WaitGroup
	errors := make(chan error, 2)
	for _, pair := range [][2]User{{first, second}, {second, first}} {
		wg.Go(func() {
			<-start
			_, err := s.changeUserAccess(t.Context(), pair[0], pair[1].ID, false)
			errors <- err
		})
	}
	close(start)
	wg.Wait()
	close(errors)
	successes := 0
	for err := range errors {
		if err == nil {
			successes++
		} else {
			assert.ErrorIs(t, err, errUserAccessForbidden)
		}
	}
	assert.Equal(t, 1, successes)
	var enabledAdmins int
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM users WHERE is_admin AND NOT disabled`).Scan(&enabledAdmins))
	assert.Equal(t, 1, enabledAdmins)
}

func TestUsersTemplateAccessControls(t *testing.T) {
	actor := User{Username: "admin", IsAdmin: true}
	for _, disabled := range []bool{false, true} {
		data := viewData{User: &actor, AdminUsers: []adminUser{{User: actor, UUID: "self"}, {User: User{Username: `<script>`, Disabled: disabled}, UUID: "target"}}}
		w := httptest.NewRecorder()
		unitServer().render(w, httptest.NewRequest("GET", "/ui/activity", nil), 200, "activity-users", data)
		require.Equal(t, 200, w.Code)
		body := w.Body.String()
		assert.NotContains(t, body, "<script>")
		assert.Contains(t, body, "&lt;script&gt;")
		assert.Contains(t, body, `role="switch"`)
		assert.Contains(t, body, `disabled aria-describedby="user-self-note"`)
		assert.Contains(t, body, `hx-post="/ui/users/access"`)
		assert.Contains(t, body, `id="disable-user-dialog"`)
	}
}

func TestRedisRevokeAllUserSessions(t *testing.T) {
	store := testRedisSessions(t, "")
	peer := peerRedisSessions(t, store)
	other := testRedisSessions(t, "")
	ctx := t.Context()
	for i := range 140 {
		require.NoError(t, store.PutAuth(ctx, fmt.Sprint("alice-", i), "Alice"))
	}
	require.NoError(t, store.PutAuth(ctx, "bob", "bob"))
	require.NoError(t, other.PutAuth(ctx, "alice-0", "Alice"))
	app := mintRedisAppSession(t, store, "alice-0")
	bobApp := mintRedisAppSession(t, store, "bob")
	_, live, err := peer.getAppAuth(ctx, app, testAppOrigin)
	require.NoError(t, err)
	require.True(t, live)
	flow, state, err := store.beginAppLogin(ctx, testAppOrigin, testAppOrigin+"/")
	require.NoError(t, err)
	code, ok, err := store.authorizeAppLogin(ctx, flow, "alice-1")
	require.NoError(t, err)
	require.True(t, ok)
	require.NoError(t, store.RevokeUserSessions(ctx, "alice"))
	for i := range 140 {
		_, live, err := peer.GetAuth(ctx, fmt.Sprint("alice-", i))
		require.NoError(t, err)
		assert.False(t, live)
	}
	_, live, err = peer.getAppAuth(ctx, app, testAppOrigin)
	require.NoError(t, err)
	assert.False(t, live)
	assert.Zero(t, store.client.Exists(ctx, store.key("app", app), store.key("grant", code)).Val())
	_, _, _, ok, err = store.completeAppLogin(ctx, flow, code, state, testAppOrigin)
	require.NoError(t, err)
	assert.False(t, ok, "grant survived revocation")
	_, live, err = store.getAppAuth(ctx, bobApp, testAppOrigin)
	require.NoError(t, err)
	assert.True(t, live)
	_, live, err = other.GetAuth(ctx, "alice-0")
	require.NoError(t, err)
	assert.True(t, live, "revocation crossed namespace")
	require.NoError(t, store.RevokeUserSessions(ctx, "Alice"), "retry must be idempotent")
}
