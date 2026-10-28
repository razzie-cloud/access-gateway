package app

import (
	"database/sql"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func addDevice(t *testing.T, s *Server, user User, name string) (int64, *webauthn.Credential) {
	t.Helper()
	c := &webauthn.Credential{ID: []byte(user.Username + ":" + name)}
	data, err := marshalCredential(c)
	require.NoError(t, err)
	var id int64
	require.NoError(t, s.db.QueryRow(`INSERT INTO webauthn_credentials(user_id,credential_id,credential_json,created_at,device_name) VALUES($1,$2,$3,0,$4) RETURNING id`, user.ID, c.ID, data, name).Scan(&id))
	return id, c
}

func bindDeviceSession(t *testing.T, s *Server, token string, user User, device int64) {
	t.Helper()
	ctx := t.Context()
	require.NoError(t, s.sessions.DeleteAuth(ctx, token))
	sid := "login-" + token
	require.NoError(t, s.sessions.PutLogin(ctx, sid, user.Username, webauthn.SessionData{}))
	ok, err := s.sessions.CompleteLogin(ctx, sid, token, user.Username, device)
	require.NoError(t, err)
	require.True(t, ok)
}

func sessionForm(kind, token string) string {
	return url.Values{"kind": {kind}, "session_id": {hashToken(token)}}.Encode()
}

func TestDeviceNameValidation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		valid bool
	}{
		{"Phone", true}, {strings.Repeat("é", 80), true}, {strings.Repeat("é", 81), false},
		{"", false}, {"   ", false}, {"one\nother", false}, {"x\x00y", false}, {"\xff", false},
	} {
		assert.Equal(t, tc.valid, validDeviceName(tc.name), "%q", tc.name)
	}
}

func TestActivityAndChangesRequireAuthenticationAndOrigin(t *testing.T) {
	s := unitServer()
	assert.Equal(t, 401, request(s, "GET", "/ui/activity", "", "").Code)
	for _, path := range []string{"/ui/devices/rename", "/ui/devices/remove", "/ui/sessions/remove"} {
		assert.Equal(t, 401, request(s, "POST", path, "", "").Code)
		r := httptest.NewRequest("POST", path, strings.NewReader(""))
		r.Header.Set("Origin", "https://other.example")
		w := httptest.NewRecorder()
		s.handler().ServeHTTP(w, r)
		assert.Equal(t, 403, w.Code)
	}
}

func TestPostgresRegistrationDeviceName(t *testing.T) {
	s := postgresServer(t)
	user := addUser(t, s, "alice", false)
	token := issueLink(t, s, "alice", "", 60)
	w := request(s, "POST", "/api/register/begin", `{"linkToken":"`+token+`","deviceName":"  Alice phone  "}`, "")
	require.Equal(t, 200, w.Code, w.Body.String())
	registration, _, ok, err := s.sessions.GetRegistration(t.Context(), w.Result().Cookies()[0].Value)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "Alice phone", registration.DeviceName)
	require.NoError(t, s.completeRegistration(t.Context(), registration, &webauthn.Credential{ID: []byte("named-device")}))
	devices, err := s.listDevices(t.Context(), user)
	require.NoError(t, err)
	require.Len(t, devices, 1)
	assert.Equal(t, "Alice phone", devices[0].Name)
	for _, name := range []string{"", strings.Repeat("x", 81), "name\nother"} {
		body := url.Values{"device_id": {fmt.Sprint(devices[0].ID)}, "device_name": {name}}.Encode()
		assert.Equal(t, 400, request(s, "POST", "/ui/devices/rename", body, "alice-session").Code)
	}
}

func TestPostgresActivityOwnershipAndRemoval(t *testing.T) {
	s := postgresServer(t)
	admin := addUser(t, s, "admin", true)
	alice := addUser(t, s, "alice", false)
	bob := addUser(t, s, "bob", false)
	adminDevice, _ := addDevice(t, s, admin, "Admin laptop")
	aliceDevice, _ := addDevice(t, s, alice, "Alice phone")
	spare, spareCredential := addDevice(t, s, alice, "Alice spare")
	bobDevice, _ := addDevice(t, s, bob, "Bob tablet")
	bindDeviceSession(t, s, "admin-session", admin, adminDevice)
	bindDeviceSession(t, s, "alice-session", alice, aliceDevice)
	bindDeviceSession(t, s, "alice-other", alice, spare)
	bindDeviceSession(t, s, "bob-session", bob, bobDevice)
	store := s.sessions.(*redisSessions)
	peer := peerRedisSessions(t, store)
	currentApp := mintRedisAppSession(t, store, "alice-session")
	otherApp := mintRedisAppSession(t, store, "alice-other")
	w := request(s, "GET", "/ui/activity", "", "alice-session")
	require.Equal(t, 200, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "Devices (2)")
	assert.Contains(t, w.Body.String(), "Active sessions (4)")
	assert.Contains(t, w.Body.String(), "This device")
	assert.Contains(t, w.Body.String(), "This browser")
	assert.NotContains(t, w.Body.String(), "Bob tablet")
	assert.NotContains(t, w.Body.String(), "Admin laptop")
	assert.NotContains(t, w.Body.String(), "Users (")
	assert.NotContains(t, w.Body.String(), hashToken("bob-session"))
	w = request(s, "GET", "/ui/activity", "", "admin-session")
	assert.Contains(t, w.Body.String(), "Devices (4)")
	assert.Contains(t, w.Body.String(), "Active sessions (6)")
	assert.Contains(t, w.Body.String(), "Bob tablet")
	for _, path := range []string{"/ui/devices/rename", "/ui/devices/remove"} {
		body := url.Values{"device_id": {fmt.Sprint(bobDevice)}, "device_name": {"stolen"}}.Encode()
		assert.Equal(t, 404, request(s, "POST", path, body, "alice-session").Code)
	}
	assert.Equal(t, 404, request(s, "POST", "/ui/sessions/remove", sessionForm("Gateway", "bob-session"), "alice-session").Code)
	// Rename the current device, then verify the corresponding sessions update.
	body := url.Values{"device_id": {fmt.Sprint(aliceDevice)}, "device_name": {`My <phone>`}}.Encode()
	w = request(s, "POST", "/ui/devices/rename", body, "alice-session")
	require.Equal(t, 200, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "My &lt;phone&gt;")
	assert.NotContains(t, w.Body.String(), "Alice phone")
	for _, tc := range []struct{ kind, token string }{{"Gateway", "alice-session"}, {"Application", currentApp}} {
		assert.Equal(t, 409, request(s, "POST", "/ui/sessions/remove", sessionForm(tc.kind, tc.token), "alice-session").Code)
	}
	for _, id := range []int64{aliceDevice, spare} {
		assert.Equal(t, 409, request(s, "POST", "/ui/devices/remove", fmt.Sprint("device_id=", id), "alice-session").Code)
	}
	// Removing an app session leaves its parent intact and defeats a warm cache.
	_, live, err := peer.getAppAuth(t.Context(), otherApp, testAppOrigin)
	require.NoError(t, err)
	require.True(t, live)
	w = request(s, "POST", "/ui/sessions/remove", sessionForm("Application", otherApp), "alice-session")
	require.Equal(t, 200, w.Code, w.Body.String())
	_, live, err = peer.getAppAuth(t.Context(), otherApp, testAppOrigin)
	require.NoError(t, err)
	assert.False(t, live)
	_, live, err = peer.GetAuth(t.Context(), "alice-other")
	require.NoError(t, err)
	assert.True(t, live)
	// Removing a gateway session invalidates all its derived app sessions.
	otherApp = mintRedisAppSession(t, store, "alice-other")
	_, _, err = peer.getAppAuth(t.Context(), otherApp, testAppOrigin)
	require.NoError(t, err)
	w = request(s, "POST", "/ui/sessions/remove", sessionForm("Gateway", "alice-other"), "alice-session")
	require.Equal(t, 200, w.Code, w.Body.String())
	_, live, err = peer.getAppAuth(t.Context(), otherApp, testAppOrigin)
	require.NoError(t, err)
	assert.False(t, live)
	w = request(s, "POST", "/ui/devices/remove", fmt.Sprint("device_id=", spare), "alice-session")
	require.Equal(t, 200, w.Code, w.Body.String())
	assert.NotContains(t, w.Body.String(), "Alice spare")
	// An already verified assertion for a deleted credential must not recreate it.
	require.NoError(t, s.sessions.PutLogin(t.Context(), "late-login", "alice", webauthn.SessionData{}))
	ok, err := s.completeDeviceLogin(t.Context(), "late-login", "late-session", alice, spareCredential)
	assert.ErrorIs(t, err, sql.ErrNoRows)
	assert.False(t, ok)
	// Admins can rename and remove other users' inactive devices and sessions.
	body = url.Values{"device_id": {fmt.Sprint(bobDevice)}, "device_name": {"Bob renamed"}}.Encode()
	assert.Equal(t, 200, request(s, "POST", "/ui/devices/rename", body, "admin-session").Code)
	assert.Equal(t, 200, request(s, "POST", "/ui/sessions/remove", sessionForm("Gateway", "bob-session"), "admin-session").Code)
	assert.Equal(t, 200, request(s, "POST", "/ui/devices/remove", fmt.Sprint("device_id=", bobDevice), "admin-session").Code)
}

func TestPostgresLegacySessionsProtectDevices(t *testing.T) {
	s := postgresServer(t)
	alice := addUser(t, s, "alice", false) // Legacy session has no device ID.
	id, _ := addDevice(t, s, alice, "Legacy phone")
	w := request(s, "GET", "/ui/activity", "", "alice-session")
	require.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "Unknown device")
	assert.Equal(t, 409, request(s, "POST", "/ui/devices/remove", fmt.Sprint("device_id=", id), "alice-session").Code)
	bindDeviceSession(t, s, "known-session", alice, id)
	assert.Equal(t, 200, request(s, "POST", "/ui/sessions/remove", sessionForm("Gateway", "alice-session"), "known-session").Code)
	assert.Equal(t, 409, request(s, "POST", "/ui/devices/remove", fmt.Sprint("device_id=", id), "known-session").Code)
}

func TestPostgresDeviceRemovalFailsClosedOnRedisError(t *testing.T) {
	s := postgresServer(t)
	alice := addUser(t, s, "alice", false)
	id, _ := addDevice(t, s, alice, "Protected phone")
	peer := peerRedisSessions(t, s.sessions.(*redisSessions))
	s.sessions = peer
	require.NoError(t, peer.Close())
	require.ErrorIs(t, s.removeDevice(t.Context(), alice, id), errSessionStore)
	var count int
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM webauthn_credentials WHERE id=$1`, id).Scan(&count))
	assert.Equal(t, 1, count)
}

func TestPostgresLoginAndDeviceRemovalRace(t *testing.T) {
	s := postgresServer(t)
	alice := addUser(t, s, "alice", false)
	require.NoError(t, s.sessions.DeleteAuth(t.Context(), "alice-session"))
	for i := range 8 {
		device, credential := addDevice(t, s, alice, fmt.Sprint("racing-device-", i))
		sid, token := fmt.Sprint("race-login-", i), fmt.Sprint("race-session-", i)
		require.NoError(t, s.sessions.PutLogin(t.Context(), sid, alice.Username, webauthn.SessionData{}))
		var loginErr, removeErr error
		var loggedIn bool
		var wg sync.WaitGroup
		wg.Go(func() { loggedIn, loginErr = s.completeDeviceLogin(t.Context(), sid, token, alice, credential) })
		wg.Go(func() { removeErr = s.removeDevice(t.Context(), alice, device) })
		wg.Wait()
		if loggedIn {
			require.NoError(t, loginErr)
			require.ErrorIs(t, removeErr, errDeviceInUse)
			require.NoError(t, s.sessions.DeleteAuth(t.Context(), token))
		} else {
			require.NoError(t, removeErr)
			require.ErrorIs(t, loginErr, sql.ErrNoRows)
		}
	}
}
