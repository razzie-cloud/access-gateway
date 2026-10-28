package app

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testAppOrigin = "https://app.example.net"

func forwardRequest(s *Server, origin, uri string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	u, _ := url.Parse(origin)
	r := httptest.NewRequest("GET", "/forward_auth", nil)
	r.Header.Set("X-Forwarded-Proto", u.Scheme)
	r.Header.Set("X-Forwarded-Host", u.Host)
	r.Header.Set("X-Forwarded-Uri", uri)
	r.Header.Set("X-Forwarded-Method", "GET")
	r.Header.Set("X-Auth-Request-User", "spoofed-id")
	r.Header.Set("X-Auth-Request-Name", "spoofed-name")
	for _, cookie := range cookies {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	return w
}

func TestForwardAuthConfig(t *testing.T) {
	for _, origin := range []string{
		"https://app.example.net", "https://app.example.net:8443/",
		"http://localhost:8081", "http://127.0.0.1:8082", "http://[::1]:8083",
		"http://files.localhost:8082", "http://Files.Localhost:8082", "http://files.wsl.localhost:8082",
	} {
		assert.NoError(t, validateForwardAuthConfig(Config{Origin: "https://auth.example", ForwardAuthOrigins: []string{origin}}))
	}
	for _, origin := range []string{
		"", "//app.example.net", "https://*.example.net", "http://app.example.net", "ftp://app.example.net",
		"https://app.example.net/path", "https://app.example.net?next=evil", "https://app.example.net#evil",
		"https://user@app.example.net", "https://app.example.net,evil.example", "https://auth.example",
		"https://app.example.net:bad", "https://app.example.net\\evil",
		"http://files.localhost.example:8082", "http://notlocalhost:8082", "http://files-localhost:8082",
		"http://files.localhost@evil.example:8082", "http://*.localhost:8082",
	} {
		t.Run(origin, func(t *testing.T) {
			cfg := Config{Origin: "https://auth.example", ForwardAuthOrigins: []string{origin}}
			require.Error(t, validateForwardAuthConfig(cfg))
			_, err := NewServer(cfg)
			require.Error(t, err, "invalid forward auth config should fail before connecting to PostgreSQL")
		})
	}
	assert.Error(t, validateForwardAuthConfig(Config{Origin: "https://auth.example/path", ForwardAuthOrigins: []string{testAppOrigin}}))
}

func TestForwardAuthRejectsUntrustedTargets(t *testing.T) {
	s := unitServer()
	w := request(s, "GET", "/forward_auth", "", "")
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	s.cfg.ForwardAuthOrigins = []string{testAppOrigin}
	for _, tc := range []struct{ proto, host, uri string }{
		{"", "", ""}, {"https", "evil.example", "/"}, {"http", "app.example.net", "/"},
		{"https", "app.example.net.evil", "/"}, {"https", "app.example.net,evil.example", "/"},
		{"https", "app.example.net", "https://evil.example/"}, {"https", "app.example.net", "//evil.example/"},
		{"https", "app.example.net", "/\\evil"}, {"https", "app.example.net", "/%0d%0aevil"},
		{"https", "app.example.net", ""}, {"https", "app.example.net", "/%invalid"},
		{"https", "app.example.net/path", "/"},
	} {
		r := httptest.NewRequest("GET", "/forward_auth", nil)
		r.Header.Set("X-Forwarded-Proto", tc.proto)
		r.Header.Set("X-Forwarded-Host", tc.host)
		r.Header.Set("X-Forwarded-Uri", tc.uri)
		w := httptest.NewRecorder()
		s.handler().ServeHTTP(w, r)
		assert.Equal(t, http.StatusBadRequest, w.Code, "%+v", tc)
		assert.Empty(t, w.Header().Get("Location"))
		assert.Empty(t, w.Header().Get("X-Auth-Request-User"))
		assert.Empty(t, w.Header().Get("Set-Cookie"))
	}
	r := httptest.NewRequest("GET", "/forward_auth", nil)
	r.Header["X-Forwarded-Host"] = []string{"app.example.net", "evil.example"}
	w = httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func startAppLogin(t *testing.T, s *Server, origin, uri string, cookies ...*http.Cookie) (string, *http.Cookie) {
	t.Helper()
	w := forwardRequest(s, origin, uri, cookies...)
	require.Equal(t, http.StatusSeeOther, w.Code)
	require.True(t, strings.HasPrefix(w.Header().Get("Location"), s.cfg.Origin+"/auth/authorize?flow="))
	assert.Empty(t, w.Header().Get("X-Auth-Request-User"))
	assert.Empty(t, w.Header().Get("X-Auth-Request-Name"))
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	c := w.Result().Cookies()
	require.Len(t, c, 1)
	assert.True(t, c[0].HttpOnly)
	assert.Equal(t, strings.HasPrefix(origin, "https://"), c[0].Secure)
	assert.Equal(t, http.SameSiteLaxMode, c[0].SameSite)
	assert.Empty(t, c[0].Domain)
	assert.Equal(t, "/", c[0].Path)
	return w.Header().Get("Location"), c[0]
}

func TestForwardAuthStartsLogin(t *testing.T) {
	for _, token := range []string{"", "unknown", "expired", "central-session"} {
		t.Run(token, func(t *testing.T) {
			s := unitServer()
			s.cfg.ForwardAuthOrigins = []string{testAppOrigin}
			testMemory(s).PutAuth("central-session", "alice")
			testMemory(s).apps["expired"] = appSession{origin: testAppOrigin, parent: "expired-parent"}
			testMemory(s).auth["expired-parent"] = authEntry{username: "alice", exp: time.Now().Add(-time.Minute)}
			_, state := startAppLogin(t, s, testAppOrigin, "/notes?sort=latest", &http.Cookie{Name: appCookieName(testAppOrigin, "app"), Value: token})
			assert.True(t, strings.HasPrefix(state.Name, "__Host-razcloud_state_"))
			assert.Equal(t, int(appLoginTTL.Seconds()), state.MaxAge)
			for _, flow := range testMemory(s).flows {
				assert.Equal(t, testAppOrigin+"/notes?sort=latest", flow.returnTo)
			}
		})
	}
}

func TestAuthorizeUsesExistingGatewaySession(t *testing.T) {
	s := unitServer()
	s.cfg.ForwardAuthOrigins = []string{testAppOrigin}
	testMemory(s).PutAuth("central", "alice")
	authorize, state := startAppLogin(t, s, testAppOrigin, "/notes")
	w := request(s, "GET", authorize, "", "central")
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.True(t, strings.HasPrefix(w.Header().Get("Location"), testAppOrigin+appCallbackPath+"?"))
	assert.Empty(t, w.Result().Cookies(), "gateway must not set the app's cookie from its own hostname")
	callback, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	assert.NotEmpty(t, callback.Query().Get("code"))
	assert.Equal(t, strings.TrimPrefix(state.Name, "__Host-razcloud_state_"), callback.Query().Get("state"))
	w = forwardRequest(s, testAppOrigin, callback.RequestURI(), state)
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, testAppOrigin+"/notes", w.Header().Get("Location"))
	cookies := w.Result().Cookies()
	require.Len(t, cookies, 2)
	assert.Equal(t, "__Host-razcloud_app", cookies[0].Name)
	assert.NotEqual(t, "central", cookies[0].Value)
	assert.Empty(t, cookies[0].Domain)
	assert.True(t, cookies[0].Secure)
	assert.True(t, cookies[0].HttpOnly)
	assert.Equal(t, state.Name, cookies[1].Name)
	assert.Equal(t, -1, cookies[1].MaxAge)
	w = forwardRequest(s, testAppOrigin, callback.RequestURI(), state)
	assert.Equal(t, http.StatusBadRequest, w.Code, "callback replay was accepted")
	assert.Empty(t, w.Header().Get("Set-Cookie"))
}

func TestAppCallbackRequiresBrowserState(t *testing.T) {
	s := unitServer()
	s.cfg.ForwardAuthOrigins = []string{testAppOrigin, "https://other.example.org"}
	testMemory(s).PutAuth("central", "alice")
	authorize, state := startAppLogin(t, s, testAppOrigin, "/")
	w := request(s, "GET", authorize, "", "central")
	callback, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	r := httptest.NewRequest("GET", "/forward_auth", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "app.example.net")
	r.Header.Set("X-Forwarded-Uri", callback.RequestURI())
	r.Header.Set("X-Forwarded-Method", "POST")
	r.AddCookie(state)
	w = httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	assert.Empty(t, w.Header().Get("Set-Cookie"))
	for _, tc := range []struct {
		name, origin, uri string
		cookies           []*http.Cookie
	}{
		{"missing state", testAppOrigin, callback.RequestURI(), nil},
		{"wrong state", testAppOrigin, callback.RequestURI(), []*http.Cookie{{Name: state.Name, Value: "wrong"}}},
		{"wrong origin", "https://other.example.org", callback.RequestURI(), []*http.Cookie{state}},
		{"missing code", testAppOrigin, appCallbackPath + "?state=" + callback.Query().Get("state"), []*http.Cookie{state}},
		{"duplicate code", testAppOrigin, callback.RequestURI() + "&code=bad", []*http.Cookie{state}},
		{"unknown flow", testAppOrigin, appCallbackPath + "?code=bad&state=unknown", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := forwardRequest(s, tc.origin, tc.uri, tc.cookies...)
			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Empty(t, w.Header().Get("Set-Cookie"))
			assert.Empty(t, w.Header().Get("Location"))
		})
	}
	w = forwardRequest(s, testAppOrigin, callback.RequestURI(), state)
	assert.Equal(t, http.StatusSeeOther, w.Code, "failed checks consumed the legitimate callback")
}

func TestForwardAuthLocalCookie(t *testing.T) {
	for _, origin := range []string{"http://127.0.0.1:8081", "http://files.localhost:8082"} {
		t.Run(origin, func(t *testing.T) {
			s := unitServer()
			s.cfg.ForwardAuthOrigins = []string{origin}
			testMemory(s).PutAuth("central", "alice")
			authorize, state := startAppLogin(t, s, origin, "/notes?sort=latest")
			assert.True(t, strings.HasPrefix(state.Name, "razcloud_state_"))
			assert.False(t, state.Secure)
			w := request(s, "GET", authorize, "", "central")
			require.Equal(t, http.StatusSeeOther, w.Code)
			callback, err := url.Parse(w.Header().Get("Location"))
			require.NoError(t, err)
			assert.Equal(t, origin, callback.Scheme+"://"+callback.Host)
			w = forwardRequest(s, origin, callback.RequestURI(), state)
			require.Equal(t, http.StatusSeeOther, w.Code)
			assert.Equal(t, origin+"/notes?sort=latest", w.Header().Get("Location"))
			cookies := w.Result().Cookies()
			require.Len(t, cookies, 2)
			assert.Equal(t, "razcloud_app", cookies[0].Name)
			assert.Empty(t, cookies[0].Domain)
			assert.False(t, cookies[0].Secure)
			assert.Equal(t, http.StatusBadRequest, forwardRequest(s, "http://other.localhost:8082", "/").Code,
				"localhost subdomains must still be explicitly allowlisted")
		})
	}
}

func TestAuthorizeRejectsExpiredOrUnknownFlow(t *testing.T) {
	s := unitServer()
	s.cfg.ForwardAuthOrigins = []string{testAppOrigin}
	testMemory(s).flows["expired"] = memoryAppLoginFlow{origin: testAppOrigin, exp: time.Now().Add(-time.Minute)}
	for _, flow := range []string{"", "unknown", "expired"} {
		w := request(s, "GET", "/auth/authorize?flow="+flow, "", "")
		assert.Equal(t, http.StatusBadRequest, w.Code)
	}
}

func TestForwardAuthSSO(t *testing.T) {
	s := postgresServer(t)
	s.cfg.ForwardAuthOrigins = []string{testAppOrigin, "https://second.example.org"}
	user := addUser(t, s, "alice", false)
	userID, err := uuid.FromBytes(user.ID)
	require.NoError(t, err)
	var appCookies []*http.Cookie
	for _, origin := range s.cfg.ForwardAuthOrigins {
		authorize, state := startAppLogin(t, s, origin, "/private?q=hello%20world")
		// Without a gateway session, render the normal login UI at the handoff URL.
		w := request(s, "GET", authorize, "", "")
		require.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), `data-webauthn="login"`)
		// A successful WebAuthn login populates this existing gateway session.
		w = request(s, "GET", authorize, "", "alice-session")
		require.Equal(t, http.StatusSeeOther, w.Code)
		callback, err := url.Parse(w.Header().Get("Location"))
		require.NoError(t, err)
		w = forwardRequest(s, origin, callback.RequestURI(), state)
		require.Equal(t, http.StatusSeeOther, w.Code)
		assert.Equal(t, origin+"/private?q=hello%20world", w.Header().Get("Location"))
		appCookie := w.Result().Cookies()[0]
		appCookies = append(appCookies, appCookie)
		w = forwardRequest(s, origin, "/private", appCookie)
		require.Equal(t, http.StatusNoContent, w.Code)
		assert.Equal(t, userID.String(), w.Header().Get("X-Auth-Request-User"))
		assert.Equal(t, "alice", w.Header().Get("X-Auth-Request-Name"))
		assert.Empty(t, w.Body.String())
		assert.Empty(t, w.Header().Get("Set-Cookie"))
		assert.Empty(t, w.Header().Get("Location"))
		assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
		// App cookies cannot authorize access to the gateway account UI/API.
		r := httptest.NewRequest("GET", "/api/me", nil)
		r.AddCookie(appCookie)
		me := httptest.NewRecorder()
		s.handler().ServeHTTP(me, r)
		assert.JSONEq(t, `{"authenticated":false}`, me.Body.String())
	}
	assert.NotEqual(t, appCookies[0].Value, appCookies[1].Value)
	startAppLogin(t, s, s.cfg.ForwardAuthOrigins[1], "/", appCookies[0])
	// A central cookie forwarded by an app also must not authenticate the app.
	startAppLogin(t, s, testAppOrigin, "/", &http.Cookie{Name: "auth", Value: "alice-session"})
	w := request(s, "POST", "/api/logout", `{}`, "alice-session")
	require.Equal(t, http.StatusOK, w.Code)
	for i, origin := range s.cfg.ForwardAuthOrigins {
		startAppLogin(t, s, origin, "/private", appCookies[i])
	}
}

func TestForwardAuthFailsClosedOnUserLookup(t *testing.T) {
	for _, brokenDB := range []bool{false, true} {
		s := postgresServer(t)
		s.cfg.ForwardAuthOrigins = []string{testAppOrigin}
		addUser(t, s, "alice", false)
		flow, state, err := s.sessions.beginAppLogin(t.Context(), testAppOrigin, testAppOrigin+"/")
		require.NoError(t, err)
		code, ok, err := s.sessions.authorizeAppLogin(t.Context(), flow, "alice-session")
		require.NoError(t, err)
		require.True(t, ok)
		token, _, ok, err := s.sessions.completeAppLogin(t.Context(), flow, code, state, testAppOrigin)
		require.NoError(t, err)
		require.True(t, ok)
		if brokenDB {
			require.NoError(t, s.db.Close())
		} else {
			_, err := s.db.Exec(`DELETE FROM users WHERE username='alice'`)
			require.NoError(t, err)
		}
		w := forwardRequest(s, testAppOrigin, "/", &http.Cookie{Name: appCookieName(testAppOrigin, "app"), Value: token})
		if brokenDB {
			assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		} else {
			assert.Equal(t, http.StatusUnauthorized, w.Code)
		}
		assert.Empty(t, w.Header().Get("X-Auth-Request-User"))
		assert.Empty(t, w.Header().Get("X-Auth-Request-Name"))
	}
}
