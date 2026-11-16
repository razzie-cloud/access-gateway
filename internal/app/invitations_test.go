package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func beginInvitation(t *testing.T, s *Server, token, username string) registrationContext {
	t.Helper()
	body, err := json.Marshal(registerBeginReq{LinkToken: token, Username: username, DeviceName: "First device"})
	require.NoError(t, err)
	w := request(s, "POST", "/api/register/begin", string(body), "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	registration, _, ok, err := s.sessions.GetRegistration(t.Context(), w.Result().Cookies()[0].Value)
	require.NoError(t, err)
	require.True(t, ok)
	require.True(t, registration.NewUser)
	require.False(t, registration.User.IsAdmin)
	return registration
}

func TestPostgresNewUserInvitation(t *testing.T) {
	s := postgresServer(t)
	addUser(t, s, "admin", true)
	member := addUser(t, s, "member", false)
	token := issueLink(t, s, "admin", "", 60)
	count, err := s.countUsers(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 2, count, "issuing an invitation must not create a user")
	w := request(s, "POST", "/api/register/link", `{"linkToken":"`+token+`"}`, "")
	require.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"newUser":true}`, w.Body.String())
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	for _, name := range []string{"", "  ", strings.Repeat("a", 65), strings.Repeat("é", 33), "alice@home", "alice bob", "admin", "ADMIN"} {
		body, err := json.Marshal(registerBeginReq{LinkToken: token, Username: name})
		require.NoError(t, err)
		w = request(s, "POST", "/api/register/begin", string(body), "")
		if strings.EqualFold(name, "admin") {
			assert.Equal(t, http.StatusConflict, w.Code)
		} else {
			assert.Equal(t, http.StatusBadRequest, w.Code)
		}
		assert.Empty(t, w.Result().Cookies())
	}
	registration := beginInvitation(t, s, token, "  recipient  ")
	assert.Equal(t, "recipient", registration.User.Username)
	count, err = s.countUsers(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 2, count, "begin must not create or reserve a user")
	require.NoError(t, s.completeRegistration(t.Context(), registration, &webauthn.Credential{ID: []byte("first-key")}))
	created, err := s.getUserByUsername(t.Context(), "recipient")
	require.NoError(t, err)
	assert.False(t, created.IsAdmin)
	assert.Equal(t, registration.User.ID, created.ID)
	devices, err := s.listDevices(t.Context(), created)
	require.NoError(t, err)
	require.Len(t, devices, 1)
	assert.Equal(t, "First device", devices[0].Name)
	var boundID []byte
	require.NoError(t, s.db.QueryRow(`SELECT user_id FROM registration_links WHERE token_hash=$1 AND used_at IS NOT NULL`, hashToken(token)).Scan(&boundID))
	assert.Equal(t, created.ID, boundID)
	for _, path := range []string{"/api/register/link", "/api/register/begin"} {
		w = request(s, "POST", path, `{"linkToken":"`+token+`"}`, "")
		assert.Equal(t, http.StatusForbidden, w.Code)
	}
	// Empty or omitted account fields from a regular user still target only
	// that user; they cannot create an unbound new-user invitation.
	memberToken := issueLink(t, s, "member", "", 60)
	existing, err := s.registrationFromLink(t.Context(), memberToken)
	require.NoError(t, err)
	assert.False(t, existing.NewUser)
	assert.Equal(t, member.ID, existing.User.ID)
	w = request(s, "POST", "/api/register/link", `{"linkToken":"`+memberToken+`"}`, "")
	assert.JSONEq(t, `{"newUser":false}`, w.Body.String())
	w = request(s, "POST", "/api/register/begin", `{"linkToken":"`+memberToken+`","username":"hijack"}`, "")
	assert.Equal(t, http.StatusBadRequest, w.Code)
	w = request(s, "POST", "/ui/links", "minutes=60", "admin-session")
	require.Equal(t, http.StatusOK, w.Code)
	self, err := s.registrationFromLink(t.Context(), linkPattern.FindStringSubmatch(w.Body.String())[1])
	require.NoError(t, err)
	assert.Equal(t, "admin", self.User.Username, "omitted field must preserve self-link API")
}

func TestPostgresInvitationRollbackAndExpiry(t *testing.T) {
	s := postgresServer(t)
	admin := addUser(t, s, "admin", true)
	_, err := s.db.Exec(`INSERT INTO webauthn_credentials(user_id,credential_id,credential_json,created_at) VALUES($1,$2,'{}',0)`, admin.ID, []byte("existing-key"))
	require.NoError(t, err)
	token := issueLink(t, s, "admin", "", 60)
	registration := beginInvitation(t, s, token, "recipient")
	assert.Error(t, s.completeRegistration(t.Context(), registration, &webauthn.Credential{ID: []byte("existing-key")}))
	_, err = s.getUserByUsername(t.Context(), "recipient")
	assert.Error(t, err, "failed credential insert must roll back user creation")
	link, err := s.registrationFromLink(t.Context(), token)
	require.NoError(t, err)
	assert.True(t, link.NewUser, "failed credential insert must leave the invitation unbound")
	// A name taken after begin must neither consume the invitation nor add a
	// credential to the existing account. A fresh begin can choose another name.
	addUser(t, s, "Recipient", false)
	assert.ErrorIs(t, s.completeRegistration(t.Context(), registration, &webauthn.Credential{ID: []byte("another-key")}), errUsernameTaken)
	registration = beginInvitation(t, s, token, "another-recipient")
	_, err = s.db.Exec(`UPDATE registration_links SET expires_at=$1 WHERE token_hash=$2`, time.Now().Unix()-1, hashToken(token))
	require.NoError(t, err)
	assert.ErrorIs(t, s.completeRegistration(t.Context(), registration, &webauthn.Credential{ID: []byte("expired-key")}), errRegistrationUnavailable)
	_, err = s.getUserByUsername(t.Context(), "another-recipient")
	assert.Error(t, err)
	w := request(s, "POST", "/api/register/link", `{"linkToken":"`+token+`"}`, "")
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestPostgresCompetingInvitations(t *testing.T) {
	for _, sameLink := range []bool{true, false} {
		t.Run(map[bool]string{true: "same link different names", false: "different links same name"}[sameLink], func(t *testing.T) {
			s := postgresServer(t)
			addUser(t, s, "admin", true)
			token := issueLink(t, s, "admin", "", 60)
			first := beginInvitation(t, s, token, "recipient")
			name := "other-recipient"
			if !sameLink {
				token = issueLink(t, s, "admin", "", 60)
				name = "RECIPIENT"
			}
			second := beginInvitation(t, s, token, name)
			var wg sync.WaitGroup
			results := make(chan error, 2)
			for i, registration := range []registrationContext{first, second} {
				wg.Go(func() {
					results <- s.completeRegistration(context.Background(), registration, &webauthn.Credential{ID: []byte{byte(i)}})
				})
			}
			wg.Wait()
			close(results)
			success, rejected := 0, 0
			for err := range results {
				if err == nil {
					success++
				} else if errors.Is(err, errRegistrationUnavailable) || errors.Is(err, errUsernameTaken) {
					rejected++
				} else {
					require.NoError(t, err)
				}
			}
			assert.Equal(t, 1, success)
			assert.Equal(t, 1, rejected)
			count, err := s.countUsers(t.Context())
			require.NoError(t, err)
			assert.Equal(t, 2, count)
		})
	}
}
