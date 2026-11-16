package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLinkLoginRequestGuards(t *testing.T) {
	for _, tc := range []struct {
		body   string
		status int
	}{
		{`{`, 400}, {`{"linkToken":"x","username":"alice"}`, 400},
		{`{"linkToken":"x","token":"bootstrap"}`, 400}, {`{}`, 403},
		{`{"linkToken":"` + strings.Repeat("A", 64) + `"}`, 403}, {`{"linkToken":"invalid"}`, 403},
	} {
		s := unitServer()
		w := request(s, "POST", "/api/login/link", tc.body, "")
		assert.Equal(t, tc.status, w.Code, w.Body.String())
		assert.Empty(t, w.Result().Cookies())
	}
	for _, tc := range []struct {
		origin, content string
		status          int
	}{
		{"", "application/json", 403}, {"https://evil.example", "application/json", 403},
		{"https://auth.example", "text/plain", 415},
	} {
		s := unitServer()
		r := httptest.NewRequest("POST", "/api/login/link", strings.NewReader(`{}`))
		r.Header.Set("Origin", tc.origin)
		r.Header.Set("Content-Type", tc.content)
		w := httptest.NewRecorder()
		s.handler().ServeHTTP(w, r)
		assert.Equal(t, tc.status, w.Code)
		assert.Empty(t, w.Result().Cookies())
	}
}

func TestPostgresLinkLoginAndRevocation(t *testing.T) {
	s := postgresServer(t)
	admin := addUser(t, s, "admin", true)
	alice := addUser(t, s, "alice", false)
	device, _ := addDevice(t, s, alice, "Unused phone")
	// Remove the test's legacy session; only the new link session should remain.
	require.NoError(t, s.sessions.DeleteAuth(t.Context(), "alice-session"))
	token := issueLink(t, s, admin.Username, alice.Username, 60)
	w := request(s, "POST", "/api/login/link", `{"linkToken":"`+token+`"}`, "")
	require.Equal(t, 200, w.Code, w.Body.String())
	assert.JSONEq(t, `{"ok":true}`, w.Body.String())
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"))
	var auth *http.Cookie
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == "auth" {
			auth = cookie
		}
	}
	require.NotNil(t, auth)
	assert.True(t, auth.Secure)
	assert.True(t, auth.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, auth.SameSite)
	assert.Equal(t, int(authTTL.Seconds()), auth.MaxAge)
	assert.NotEqual(t, token, auth.Value)
	peer := peerRedisSessions(t, s.sessions.(*redisSessions))
	name, live, err := peer.GetAuth(t.Context(), auth.Value)
	require.NoError(t, err)
	require.True(t, live)
	assert.Equal(t, "alice", name)
	devices, err := s.listDevices(t.Context(), alice)
	require.NoError(t, err)
	require.Len(t, devices, 1)
	assert.Equal(t, device, devices[0].ID)
	w = request(s, "GET", "/ui/activity", "", auth.Value)
	require.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "One-time link login")
	assert.NotContains(t, w.Body.String(), ">Unknown device<")
	assert.NotContains(t, w.Body.String(), "This device")
	app := mintRedisAppSession(t, s.sessions.(*redisSessions), auth.Value)
	sessions, err := peer.ListSessions(t.Context())
	require.NoError(t, err)
	found := 0
	for _, session := range sessions {
		if session.Username == "alice" {
			found++
			assert.True(t, session.LinkLogin)
			assert.Zero(t, session.DeviceID)
		}
	}
	assert.Equal(t, 2, found)
	// A browser authenticated by a link uses no registered device.
	require.NoError(t, s.removeDevice(t.Context(), alice, device))
	for _, path := range []string{"/api/login/link", "/api/register/link", "/api/register/begin"} {
		w = request(s, "POST", path, `{"linkToken":"`+token+`"}`, "")
		assert.Equal(t, 403, w.Code, path)
		assert.Empty(t, w.Result().Cookies())
	}
	_, live, err = peer.getAppAuth(t.Context(), app, testAppOrigin)
	require.NoError(t, err)
	require.True(t, live)
	// Administrator revocation invalidates the live gateway and derived app,
	// including their already-warm caches on another replica.
	w = request(s, "POST", "/ui/sessions/remove", sessionForm("Gateway", auth.Value), "admin-session")
	require.Equal(t, 200, w.Code, w.Body.String())
	_, live, err = peer.GetAuth(t.Context(), auth.Value)
	require.NoError(t, err)
	assert.False(t, live)
	_, live, err = peer.getAppAuth(t.Context(), app, testAppOrigin)
	require.NoError(t, err)
	assert.False(t, live)
}

func TestPostgresLinkLoginRejectsUnavailableAndInvitation(t *testing.T) {
	s := postgresServer(t)
	addUser(t, s, "admin", true)
	addUser(t, s, "alice", false)
	invitation := issueLink(t, s, "admin", "", 60)
	expired := issueLink(t, s, "admin", "alice", 60)
	_, err := s.db.Exec(`UPDATE registration_links SET expires_at=$1 WHERE token_hash=$2`, time.Now().Unix()-1, hashToken(expired))
	require.NoError(t, err)
	for _, token := range []string{invitation, expired, strings.Repeat("0", 64)} {
		w := request(s, "POST", "/api/login/link", `{"linkToken":"`+token+`"}`, "")
		assert.Equal(t, 403, w.Code)
		assert.Empty(t, w.Result().Cookies())
		assert.NotContains(t, w.Body.String(), token)
	}
	_, err = s.registrationFromLink(t.Context(), invitation)
	require.NoError(t, err, "invitation must remain available for enrollment")
	var count int
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM users`).Scan(&count))
	assert.Equal(t, 2, count)
}

type linkWriteStore struct {
	sessionStore
	write func(context.Context, string, string) error
}

func (s linkWriteStore) PutLinkAuth(ctx context.Context, token, username string) error {
	return s.write(ctx, token, username)
}

func TestPostgresLinkLoginRollsBackFailures(t *testing.T) {
	for _, kind := range []string{"redis-before-write", "redis-ambiguous-write", "commit-canceled"} {
		t.Run(kind, func(t *testing.T) {
			s := postgresServer(t)
			addUser(t, s, "alice", false)
			link := issueLink(t, s, "alice", "", 60)
			original := s.sessions
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var generated string
			s.sessions = linkWriteStore{sessionStore: original, write: func(ctx context.Context, token, username string) error {
				generated = token
				if kind != "redis-before-write" {
					require.NoError(t, original.PutLinkAuth(ctx, token, username))
				}
				if kind == "commit-canceled" {
					cancel()
					return nil
				}
				return sessionStoreError(errors.New("simulated lost Redis reply"))
			}}
			auth, _, err := s.completeLinkLogin(ctx, link)
			require.Error(t, err)
			assert.Empty(t, auth)
			_, live, err := original.GetAuth(t.Context(), generated)
			require.NoError(t, err)
			assert.False(t, live, "undisclosed session leaked")
			_, err = s.registrationFromLink(t.Context(), link)
			require.NoError(t, err, "failed login consumed link")
			s.sessions = original
			auth, _, err = s.completeLinkLogin(t.Context(), link)
			require.NoError(t, err)
			assert.NotEmpty(t, auth)
		})
	}
}

func TestPostgresLinkLoginCompetesWithEnrollmentAndOtherLogin(t *testing.T) {
	s := postgresServer(t)
	addUser(t, s, "alice", false)
	peer := *s
	peer.sessions = peerRedisSessions(t, s.sessions.(*redisSessions))
	for _, enroll := range []bool{false, true} {
		for i := range 4 {
			link := issueLink(t, s, "alice", "", 60)
			registration, err := s.registrationFromLink(t.Context(), link)
			require.NoError(t, err)
			type outcome struct {
				token string
				err   error
			}
			results := make(chan outcome, 2)
			var wg sync.WaitGroup
			wg.Go(func() { token, _, err := s.completeLinkLogin(t.Context(), link); results <- outcome{token, err} })
			wg.Go(func() {
				if enroll {
					results <- outcome{err: peer.completeRegistration(t.Context(), registration, &webauthn.Credential{ID: fmt.Appendf(nil, "racing-device-%d", i)})}
				} else {
					token, _, err := peer.completeLinkLogin(t.Context(), link)
					results <- outcome{token, err}
				}
			})
			wg.Wait()
			close(results)
			success := 0
			for result := range results {
				if result.err == nil {
					success++
				} else {
					assert.ErrorIs(t, result.err, errRegistrationUnavailable)
					assert.Empty(t, result.token)
				}
			}
			assert.Equal(t, 1, success, "enroll=%t iteration=%d", enroll, i)
		}
	}
}
