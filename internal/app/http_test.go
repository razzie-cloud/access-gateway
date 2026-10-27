package app

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func unitServer() *Server {
	s := &Server{
		cfg:      Config{Origin: "https://auth.example"},
		sessions: memorySessionStore{NewMemorySessions(time.Minute)},
		mux:      http.NewServeMux(),
	}
	s.routes()
	return s
}

func TestRoutesRejectWrongMethod(t *testing.T) {
	s := unitServer()
	for _, tc := range []struct{ method, path string }{
		{"POST", "/"}, {"POST", "/register"}, {"POST", "/ui/state"},
		{"POST", "/api/bootstrap"}, {"POST", "/api/me"},
		{"POST", "/forward_auth"}, {"POST", "/auth/authorize"},
		{"GET", "/ui/users"}, {"GET", "/ui/links"}, {"GET", "/ui/logout"},
		{"GET", "/api/register/begin"}, {"GET", "/api/register/finish"},
		{"GET", "/api/login/begin"}, {"GET", "/api/login/finish"}, {"GET", "/api/logout"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			w := request(s, tc.method, tc.path, "", "")
			assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
		})
	}
}

func TestBeginRejectsInvalidInput(t *testing.T) {
	for _, tc := range []struct{ name, path, body, message string }{
		{"malformed registration", "/api/register/begin", `{`, "bad json"},
		{"unknown registration field", "/api/register/begin", `{"unexpected":true}`, "bad json"},
		{"link username override", "/api/register/begin", `{"linkToken":"link","username":"alice"}`, "ambiguous registration"},
		{"link bootstrap override", "/api/register/begin", `{"linkToken":"link","token":"bootstrap"}`, "ambiguous registration"},
		{"empty registration", "/api/register/begin", `{}`, "username and bootstrap token required"},
		{"blank username", "/api/register/begin", `{"username":"  ","token":"bootstrap"}`, "username and bootstrap token required"},
		{"long username", "/api/register/begin", `{"username":"` + strings.Repeat("a", 65) + `","token":"bootstrap"}`, "username and bootstrap token required"},
		{"missing bootstrap token", "/api/register/begin", `{"username":"alice"}`, "username and bootstrap token required"},
		{"malformed login", "/api/login/begin", `{`, "bad json"},
		{"unknown login field", "/api/login/begin", `{"username":"alice","unexpected":true}`, "bad json"},
		{"empty login", "/api/login/begin", `{}`, "missing username"},
		{"blank login", "/api/login/begin", `{"username":" \t\n"}`, "missing username"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := unitServer()
			w := request(s, "POST", tc.path, tc.body, "")
			var body map[string]string
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Equal(t, tc.message, body["error"])
			assert.Empty(t, w.Result().Cookies(), "invalid input created a cookie")
			assert.Empty(t, testMemory(s).reg, "invalid input created a registration ceremony")
			assert.Empty(t, testMemory(s).log, "invalid input created a login ceremony")
		})
	}
}

func TestFinishRequiresLiveCeremony(t *testing.T) {
	for _, ceremony := range []string{"register", "login"} {
		for _, sid := range []string{"missing", "empty", "unknown", "expired"} {
			t.Run(ceremony+"/"+sid, func(t *testing.T) {
				s := unitServer()
				past := time.Now().Add(-time.Minute)
				testMemory(s).reg["expired"] = regEntry{exp: past}
				testMemory(s).log["expired"] = loginEntry{exp: past}
				r := httptest.NewRequest("POST", "/api/"+ceremony+"/finish", strings.NewReader(`{}`))
				r.Header.Set("Origin", s.cfg.Origin)
				r.Header.Set("Content-Type", "application/json")
				if sid != "missing" {
					value := sid
					if sid == "empty" {
						value = ""
					}
					r.AddCookie(&http.Cookie{Name: "sid", Value: value})
				}
				w := httptest.NewRecorder()
				s.handler().ServeHTTP(w, r)
				assert.Equal(t, http.StatusBadRequest, w.Code)
				assert.Empty(t, testMemory(s).auth, "rejected finish issued an auth session")
				assert.Empty(t, w.Result().Cookies(), "rejected finish issued a cookie")
			})
		}
	}
}

func TestMeAndLogout(t *testing.T) {
	s := unitServer()
	testMemory(s).PutAuth("valid", "alice")
	testMemory(s).PutAuth("other", "bob")
	testMemory(s).auth["expired"] = authEntry{username: "alice", exp: time.Now().Add(-time.Minute)}
	for _, token := range []string{"", "unknown", "expired", "valid"} {
		t.Run("me/"+token, func(t *testing.T) {
			w := request(s, "GET", "/api/me", "", token)
			var body struct {
				Authenticated bool   `json:"authenticated"`
				Username      string `json:"username"`
			}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
			wantName := ""
			if token == "valid" {
				wantName = "alice"
			}
			assert.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, token == "valid", body.Authenticated)
			assert.Equal(t, wantName, body.Username)
		})
	}

	// Logging out is safe to repeat, including with no auth cookie.
	for _, token := range []string{"valid", "valid", "unknown", ""} {
		w := request(s, "POST", "/api/logout", `{}`, token)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.JSONEq(t, `{"ok":true}`, w.Body.String())
		cookies := w.Result().Cookies()
		require.Len(t, cookies, 1)
		assert.Equal(t, "auth", cookies[0].Name)
		assert.Empty(t, cookies[0].Value)
		assert.Equal(t, -1, cookies[0].MaxAge, "logout did not expire the auth cookie")
	}
	_, ok := testMemory(s).GetAuth("valid")
	assert.False(t, ok, "logout left the auth session usable")
	username, ok := testMemory(s).GetAuth("other")
	assert.True(t, ok, "logout removed another user's auth session")
	assert.Equal(t, "bob", username)
}

type trackedBody struct {
	io.Reader
	closed bool
}

func (b *trackedBody) Close() error {
	b.closed = true
	return nil
}

func TestReadJSON(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		valid      bool
	}{
		{"valid", `{"username":"alice"}`, true},
		{"unknown field", `{"username":"alice","admin":true}`, false},
		{"wrong type", `{"username":123}`, false},
		{"malformed", `{"username":`, false},
		{"empty", ``, false},
		{"oversized", `{"username":"` + strings.Repeat("x", 2<<20) + `"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &trackedBody{Reader: strings.NewReader(tc.body)}
			r := httptest.NewRequest("POST", "/", nil)
			r.Body = body
			var got loginBeginReq
			err := readJSON(r, &got)
			assert.True(t, body.closed, "request body was not closed")
			if tc.valid {
				require.NoError(t, err)
				assert.Equal(t, "alice", got.Username)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestCeremonyTypesCannotBeInterchanged(t *testing.T) {
	s := unitServer()
	testMemory(s).PutLogin("login-only", "alice", webauthn.SessionData{})
	testMemory(s).PutRegistration("registration-only", registrationContext{}, webauthn.SessionData{})
	for _, tc := range []struct{ path, sid string }{
		{"/api/register/finish", "login-only"},
		{"/api/login/finish", "registration-only"},
	} {
		r := httptest.NewRequest("POST", tc.path, strings.NewReader(`{}`))
		r.Header.Set("Origin", s.cfg.Origin)
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(&http.Cookie{Name: "sid", Value: tc.sid})
		w := httptest.NewRecorder()
		s.handler().ServeHTTP(w, r)
		assert.Equal(t, http.StatusBadRequest, w.Code, "%s with %s", tc.path, tc.sid)
	}
}
