package app

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"image/png"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/pressly/goose/v3"
	gatewaydb "github.com/razzie-cloud/access-gateway/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func request(s *Server, method, path, body, auth string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Origin", s.cfg.Origin)
	if strings.HasPrefix(path, "/api/") {
		r.Header.Set("Content-Type", "application/json")
	} else {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if auth != "" {
		r.AddCookie(&http.Cookie{Name: "auth", Value: auth})
	}
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	return w
}

func TestLinkLifetime(t *testing.T) {
	for _, minutes := range []int{-1, 0, 43201, 1000000000} {
		_, err := linkLifetime(minutes)
		assert.Error(t, err, "accepted %d", minutes)
	}
	for _, minutes := range []int{1, 7, 60, 43200} {
		got, err := linkLifetime(minutes)
		require.NoError(t, err)
		assert.Equal(t, time.Duration(minutes)*time.Minute, got, "lifetime(%d)", minutes)
	}
}

func TestOriginAndAuthorization(t *testing.T) {
	s := &Server{cfg: Config{Origin: "https://auth.example"}, sessions: memorySessionStore{NewMemorySessions(time.Minute)}, mux: http.NewServeMux()}
	s.routes()
	for _, path := range []string{"/ui/users", "/ui/links"} {
		w := request(s, "POST", path, "username=other&minutes=60", "")
		assert.Equal(t, http.StatusUnauthorized, w.Code, "unauthenticated %s", path)
	}
	for _, origin := range []string{"", "https://evil.example", "null"} {
		r := httptest.NewRequest("POST", "/ui/links", nil)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		s.handler().ServeHTTP(w, r)
		assert.Equal(t, http.StatusForbidden, w.Code, "origin %q", origin)
	}
	r := httptest.NewRequest("POST", "/api/register/begin", strings.NewReader(`{}`))
	r.Header.Set("Origin", s.cfg.Origin)
	r.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	assert.Equal(t, http.StatusUnsupportedMediaType, w.Code)
	w = httptest.NewRecorder()
	s.setCookie(w, "auth", "test", 0)
	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	cookie := cookies[0]
	assert.True(t, cookie.Secure)
	assert.True(t, cookie.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
	w = request(s, "GET", "/register", "", "")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "/static/htmx.min.js")
	assert.Contains(t, w.Body.String(), "/static/pico.min.css")
	w = request(s, "GET", "/missing", "", "")
	assert.Equal(t, http.StatusNotFound, w.Code, "unknown paths must not serve account page")
}

// Opt in with a disposable PostgreSQL URL. Each test creates and drops its own schema.
func postgresServer(t *testing.T) *Server {
	t.Helper()
	raw := os.Getenv("TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("TEST_DATABASE_URL unset; PostgreSQL integration test")
	}
	admin, err := sql.Open("pgx", raw)
	require.NoError(t, err)
	schema := "onboarding_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	_, err = admin.Exec(`CREATE SCHEMA ` + schema)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`); _ = admin.Close() })
	uri, err := url.Parse(raw)
	require.NoError(t, err)
	query := uri.Query()
	query.Set("search_path", schema)
	uri.RawQuery = query.Encode()
	redisStore := testRedisSessions(t, "")
	s, err := NewServer(Config{DatabaseURL: uri.String(), RedisURL: os.Getenv("TEST_REDIS_URL"), Origin: "https://auth.example", RPID: "auth.example", RPName: "Test"})
	require.NoError(t, err)
	require.NoError(t, s.sessions.Close())
	s.sessions = redisStore
	t.Cleanup(func() { _ = s.db.Close() })
	return s
}

func addUser(t *testing.T, s *Server, username string, admin bool) User {
	t.Helper()
	id := uuid.New()
	u := User{ID: id[:], Username: username, IsAdmin: admin}
	_, err := s.db.Exec(`INSERT INTO users(id,username,is_admin,created_at) VALUES($1,$2,$3,0)`, u.ID, u.Username, u.IsAdmin)
	require.NoError(t, err)
	require.NoError(t, s.sessions.PutAuth(t.Context(), username+"-session", username))
	return u
}

var linkPattern = regexp.MustCompile(`https://auth.example/register#([a-f0-9]{64})`)

func issueLink(t *testing.T, s *Server, actor, target string, minutes int) string {
	t.Helper()
	body := url.Values{"username": {target}, "minutes": {fmt.Sprint(minutes)}}.Encode()
	w := request(s, "POST", "/ui/links", body, actor+"-session")
	require.Equal(t, http.StatusOK, w.Code, "issue link: %s", w.Body.String())
	match := linkPattern.FindStringSubmatch(w.Body.String())
	require.Len(t, match, 2, "no registration link")
	qr := regexp.MustCompile(`src="data:image/png;base64,([^"]+)"`).FindStringSubmatch(w.Body.String())
	require.Len(t, qr, 2, "no inline QR code")
	data, err := base64.StdEncoding.DecodeString(html.UnescapeString(qr[1]))
	require.NoError(t, err)
	image, err := png.Decode(bytes.NewReader(data))
	require.NoError(t, err)
	assert.Equal(t, 320, image.Bounds().Dx())
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"), "link response can be cached")
	return match[1]
}

func TestPostgresLinkPermissions(t *testing.T) {
	s := postgresServer(t)
	addUser(t, s, "admin", true)
	member := addUser(t, s, "member", false)
	for _, test := range []struct {
		path, body string
		status     int
	}{
		{"/ui/users", "username=new-user", 403}, {"/ui/links", "username=admin&minutes=60", 403},
		{"/ui/links", "minutes=0", 400}, {"/ui/links", "minutes=-1", 400}, {"/ui/links", "minutes=43201", 400}, {"/ui/links", "minutes=1.5", 400},
	} {
		w := request(s, "POST", test.path, test.body, "member-session")
		assert.Equal(t, test.status, w.Code, "%s %s", test.path, test.body)
	}
	w := request(s, "POST", "/ui/links", "username=missing&minutes=1", "admin-session")
	assert.Equal(t, http.StatusNotFound, w.Code, "unknown user accepted")
	w = request(s, "POST", "/ui/users", "username=new-user", "admin-session")
	require.Equal(t, http.StatusOK, w.Code, "admin create: %s", w.Body.String())
	assert.Equal(t, "#content", w.Header().Get("HX-Retarget"))
	created, err := s.getUserByUsername(context.Background(), "new-user")
	require.NoError(t, err)
	assert.False(t, created.IsAdmin, "new user has wrong role")
	w = request(s, "POST", "/ui/users", "username=new-user", "admin-session")
	assert.Equal(t, http.StatusConflict, w.Code, "duplicate user accepted")
	w = request(s, "GET", "/ui/state", "", "member-session")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotContains(t, w.Body.String(), "Create a user", "member dashboard exposed admin form")
	token := issueLink(t, s, "admin", "member", 17)
	registration, err := s.registrationFromLink(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, member.ID, registration.User.ID, "link target")
	var stored string
	var expires, createdAt int64
	err = s.db.QueryRow(`SELECT token_hash,expires_at,created_at FROM registration_links WHERE token_hash=$1`, hashToken(token)).Scan(&stored, &expires, &createdAt)
	require.NoError(t, err)
	assert.NotEqual(t, token, stored, "raw token stored")
	assert.EqualValues(t, 17*60, expires-createdAt, "incorrect expiry")
	issueLink(t, s, "member", "", 1)
	issueLink(t, s, "admin", "new-user", 43200)
}

func TestPostgresSingleUseExpiryAndRollback(t *testing.T) {
	s := postgresServer(t)
	user := addUser(t, s, "member", false)
	token := issueLink(t, s, "member", "", 60)
	w := request(s, "POST", "/api/register/begin", `{"linkToken":"`+token+`"}`, "")
	require.Equal(t, http.StatusOK, w.Code, "begin: %s", w.Body.String())
	w = request(s, "POST", "/api/register/begin", `{"linkToken":"`+token+`","username":"another"}`, "")
	assert.Equal(t, http.StatusBadRequest, w.Code, "allowed account override")
	registration, err := s.registrationFromLink(context.Background(), token)
	require.NoError(t, err)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results <- s.completeRegistration(context.Background(), registration, &webauthn.Credential{ID: fmt.Appendf(nil, "credential-%d", i)})
		}(i)
	}
	wg.Wait()
	close(results)
	success, unavailable := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, errRegistrationUnavailable) {
			unavailable++
		} else {
			require.NoError(t, err)
		}
	}
	assert.Equal(t, 1, success, "successful enrollments")
	assert.Equal(t, 1, unavailable, "unavailable enrollments")
	w = request(s, "POST", "/api/register/begin", `{"linkToken":"`+token+`"}`, "")
	assert.Equal(t, http.StatusForbidden, w.Code, "reused consumed link")
	secondCredential := &webauthn.Credential{ID: []byte("second-device")}
	token = issueLink(t, s, "member", "", 1)
	registration, err = s.registrationFromLink(context.Background(), token)
	require.NoError(t, err)
	require.NoError(t, s.completeRegistration(context.Background(), registration, secondCredential))
	waUser, err := s.loadWebAuthnUser(context.Background(), user)
	require.NoError(t, err)
	assert.Len(t, waUser.Creds, 2, "multiple passkeys not retained")
	token = issueLink(t, s, "member", "", 1)
	registration, err = s.registrationFromLink(context.Background(), token)
	require.NoError(t, err)
	assert.Error(t, s.completeRegistration(context.Background(), registration, secondCredential), "duplicate credential overwritten")
	_, err = s.registrationFromLink(context.Background(), token)
	require.NoError(t, err, "failed enrollment consumed link")
	w = request(s, "POST", "/api/register/begin", `{"linkToken":"`+token+`"}`, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	cookies := w.Result().Cookies()
	require.NotEmpty(t, cookies)
	pending, _, ok, err := s.sessions.GetRegistration(t.Context(), cookies[0].Value)
	require.NoError(t, err)
	require.True(t, ok, "missing ceremony")
	_, err = s.db.Exec(`UPDATE registration_links SET expires_at=$1 WHERE token_hash=$2`, time.Now().Unix()-1, hashToken(token))
	require.NoError(t, err)
	err = s.completeRegistration(context.Background(), pending, &webauthn.Credential{ID: []byte("expired")})
	assert.ErrorIs(t, err, errRegistrationUnavailable, "expired finish")
	w = request(s, "POST", "/api/register/begin", `{"linkToken":"`+token+`"}`, "")
	assert.Equal(t, http.StatusForbidden, w.Code, "expired begin accepted")
	w = request(s, "POST", "/api/register/begin", `{"linkToken":"invalid"}`, "")
	assert.Equal(t, http.StatusForbidden, w.Code, "invalid token accepted")
}

func TestPostgresBootstrapRetryAndRace(t *testing.T) {
	s := postgresServer(t)
	require.NoError(t, s.setAppState(context.Background(), "bootstrap_token_sha256", hashToken("bootstrap")))
	var registrations []registrationContext
	for _, username := range []string{"first", "second"} {
		w := request(s, "POST", "/api/register/begin", `{"username":"`+username+`","token":"bootstrap"}`, "")
		require.Equal(t, http.StatusOK, w.Code, "bootstrap begin: %s", w.Body.String())
		cookies := w.Result().Cookies()
		require.NotEmpty(t, cookies)
		registration, _, ok, err := s.sessions.GetRegistration(t.Context(), cookies[0].Value)
		require.NoError(t, err)
		require.True(t, ok, "missing session")
		registrations = append(registrations, registration)
	}
	n, err := s.countUsers(context.Background())
	require.NoError(t, err)
	assert.Zero(t, n, "begin persisted incomplete user")
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i, registration := range registrations {
		wg.Add(1)
		go func(i int, registration registrationContext) {
			defer wg.Done()
			results <- s.completeRegistration(context.Background(), registration, &webauthn.Credential{ID: fmt.Append(nil, i)})
		}(i, registration)
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else {
			require.ErrorIs(t, err, errRegistrationUnavailable)
		}
	}
	assert.Equal(t, 1, success, "successful bootstrap enrollments")
	var admins int
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM users WHERE is_admin`).Scan(&admins))
	assert.Equal(t, 1, admins, "missing bootstrap admin")
	_, err = s.getAppState(context.Background(), "bootstrap_token_sha256")
	assert.Error(t, err, "bootstrap token not consumed")
}

func TestPostgresExistingUserUpgrade(t *testing.T) {
	s := postgresServer(t)
	require.NoError(t, goose.DownTo(s.db, "migrations", 1))
	first, second := uuid.New(), uuid.New()
	_, err := s.db.Exec(`INSERT INTO users(id,username,created_at) VALUES($1,'original',1),($2,'later',2)`, first[:], second[:])
	require.NoError(t, err)
	require.NoError(t, gatewaydb.RunMigrations(s.db))
	original, err := s.getUserByUsername(context.Background(), "original")
	require.NoError(t, err)
	assert.True(t, original.IsAdmin, "original user not promoted")
	later, err := s.getUserByUsername(context.Background(), "later")
	require.NoError(t, err)
	assert.False(t, later.IsAdmin, "later user became admin")
}
