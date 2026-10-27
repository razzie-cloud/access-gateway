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
		if _, err := linkLifetime(minutes); err == nil {
			t.Errorf("accepted %d", minutes)
		}
	}
	for _, minutes := range []int{1, 7, 60, 43200} {
		got, err := linkLifetime(minutes)
		if err != nil || got != time.Duration(minutes)*time.Minute {
			t.Errorf("lifetime(%d): %v %v", minutes, got, err)
		}
	}
}

func TestOriginAndAuthorization(t *testing.T) {
	s := &Server{cfg: Config{Origin: "https://auth.example"}, mem: NewMemorySessions(time.Minute), mux: http.NewServeMux()}
	s.routes()
	for _, path := range []string{"/ui/users", "/ui/links"} {
		if w := request(s, "POST", path, "username=other&minutes=60", ""); w.Code != 401 {
			t.Fatalf("unauthenticated %s: %d", path, w.Code)
		}
	}
	for _, origin := range []string{"", "https://evil.example", "null"} {
		r := httptest.NewRequest("POST", "/ui/links", nil)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		s.handler().ServeHTTP(w, r)
		if w.Code != 403 {
			t.Errorf("origin %q accepted: %d", origin, w.Code)
		}
	}
	r := httptest.NewRequest("POST", "/api/register/begin", strings.NewReader(`{}`))
	r.Header.Set("Origin", s.cfg.Origin)
	r.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	if w.Code != 415 {
		t.Errorf("media type accepted: %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.setCookie(w, "auth", "test", 0)
	cookie := w.Result().Cookies()[0]
	if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("missing session cookie protections")
	}
	if w := request(s, "GET", "/register", "", ""); w.Code != 200 || !strings.Contains(w.Body.String(), "/static/htmx.min.js") || !strings.Contains(w.Body.String(), "/static/pico.min.css") {
		t.Fatal("required frontend assets missing")
	}
	if w := request(s, "GET", "/forward_auth", "", ""); w.Code != 404 {
		t.Fatal("unknown paths must not serve account page")
	}
}

// Opt in with a disposable PostgreSQL URL. Each test creates and drops its own schema.
func postgresServer(t *testing.T) *Server {
	t.Helper()
	raw := os.Getenv("TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("TEST_DATABASE_URL unset; PostgreSQL integration test")
	}
	admin, err := sql.Open("pgx", raw)
	if err != nil {
		t.Fatal(err)
	}
	schema := "onboarding_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`); _ = admin.Close() })
	uri, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	query := uri.Query()
	query.Set("search_path", schema)
	uri.RawQuery = query.Encode()
	s, err := NewServer(Config{DatabaseURL: uri.String(), Origin: "https://auth.example", RPID: "auth.example", RPName: "Test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.db.Close() })
	return s
}

func addUser(t *testing.T, s *Server, username string, admin bool) User {
	t.Helper()
	id := uuid.New()
	u := User{ID: id[:], Username: username, IsAdmin: admin}
	if _, err := s.db.Exec(`INSERT INTO users(id,username,is_admin,created_at) VALUES($1,$2,$3,0)`, u.ID, u.Username, u.IsAdmin); err != nil {
		t.Fatal(err)
	}
	s.mem.PutAuth(username+"-session", username)
	return u
}

var linkPattern = regexp.MustCompile(`https://auth.example/register#([a-f0-9]{64})`)

func issueLink(t *testing.T, s *Server, actor, target string, minutes int) string {
	t.Helper()
	body := url.Values{"username": {target}, "minutes": {fmt.Sprint(minutes)}}.Encode()
	w := request(s, "POST", "/ui/links", body, actor+"-session")
	if w.Code != 200 {
		t.Fatalf("issue link: %d %s", w.Code, w.Body.String())
	}
	match := linkPattern.FindStringSubmatch(w.Body.String())
	if match == nil {
		t.Fatal("no registration link")
	}
	qr := regexp.MustCompile(`src="data:image/png;base64,([^"]+)"`).FindStringSubmatch(w.Body.String())
	if qr == nil {
		t.Fatal("no inline QR code")
	}
	data, err := base64.StdEncoding.DecodeString(html.UnescapeString(qr[1]))
	if err != nil {
		t.Fatal(err)
	}
	image, err := png.Decode(bytes.NewReader(data))
	if err != nil || image.Bounds().Dx() != 320 {
		t.Fatalf("invalid QR PNG: %v", err)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("link response can be cached")
	}
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
		if w := request(s, "POST", test.path, test.body, "member-session"); w.Code != test.status {
			t.Fatalf("%s %s: %d", test.path, test.body, w.Code)
		}
	}
	if w := request(s, "POST", "/ui/links", "username=missing&minutes=1", "admin-session"); w.Code != 404 {
		t.Fatal("unknown user accepted")
	}
	if w := request(s, "POST", "/ui/users", "username=new-user", "admin-session"); w.Code != 200 || w.Header().Get("HX-Retarget") != "#content" {
		t.Fatalf("admin create: %d %s", w.Code, w.Body.String())
	}
	created, err := s.getUserByUsername(context.Background(), "new-user")
	if err != nil || created.IsAdmin {
		t.Fatal("new user has wrong role")
	}
	if w := request(s, "POST", "/ui/users", "username=new-user", "admin-session"); w.Code != 409 {
		t.Fatal("duplicate user accepted")
	}
	if w := request(s, "GET", "/ui/state", "", "member-session"); w.Code != 200 || strings.Contains(w.Body.String(), "Create a user") {
		t.Fatal("member dashboard exposed admin form")
	}
	token := issueLink(t, s, "admin", "member", 17)
	registration, err := s.registrationFromLink(context.Background(), token)
	if err != nil || !equalID(registration.User.ID, member.ID) {
		t.Fatalf("link target: %+v %v", registration, err)
	}
	var stored string
	var expires, createdAt int64
	if err := s.db.QueryRow(`SELECT token_hash,expires_at,created_at FROM registration_links WHERE token_hash=$1`, hashToken(token)).Scan(&stored, &expires, &createdAt); err != nil {
		t.Fatal(err)
	}
	if stored == token || expires-createdAt != 17*60 {
		t.Fatal("raw token stored or incorrect expiry")
	}
	issueLink(t, s, "member", "", 1)
	issueLink(t, s, "admin", "new-user", 43200)
}

func TestPostgresSingleUseExpiryAndRollback(t *testing.T) {
	s := postgresServer(t)
	user := addUser(t, s, "member", false)
	token := issueLink(t, s, "member", "", 60)
	if w := request(s, "POST", "/api/register/begin", `{"linkToken":"`+token+`"}`, ""); w.Code != 200 {
		t.Fatalf("begin: %d %s", w.Code, w.Body.String())
	}
	if w := request(s, "POST", "/api/register/begin", `{"linkToken":"`+token+`","username":"another"}`, ""); w.Code != 400 {
		t.Fatal("allowed account override")
	}
	registration, err := s.registrationFromLink(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results <- s.completeRegistration(context.Background(), registration, &webauthn.Credential{ID: []byte(fmt.Sprintf("credential-%d", i))})
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
			t.Fatal(err)
		}
	}
	if success != 1 || unavailable != 1 {
		t.Fatalf("race: %d successful, %d unavailable", success, unavailable)
	}
	if w := request(s, "POST", "/api/register/begin", `{"linkToken":"`+token+`"}`, ""); w.Code != 403 {
		t.Fatal("reused consumed link")
	}
	secondCredential := &webauthn.Credential{ID: []byte("second-device")}
	token = issueLink(t, s, "member", "", 1)
	registration, err = s.registrationFromLink(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.completeRegistration(context.Background(), registration, secondCredential); err != nil {
		t.Fatal(err)
	}
	waUser, err := s.loadWebAuthnUser(context.Background(), user)
	if err != nil || len(waUser.Creds) != 2 {
		t.Fatal("multiple passkeys not retained")
	}
	token = issueLink(t, s, "member", "", 1)
	registration, err = s.registrationFromLink(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.completeRegistration(context.Background(), registration, secondCredential); err == nil {
		t.Fatal("duplicate credential overwritten")
	}
	if _, err := s.registrationFromLink(context.Background(), token); err != nil {
		t.Fatal("failed enrollment consumed link")
	}
	w := request(s, "POST", "/api/register/begin", `{"linkToken":"`+token+`"}`, "")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	pending, _, ok := s.mem.GetRegistration(w.Result().Cookies()[0].Value)
	if !ok {
		t.Fatal("missing ceremony")
	}
	if _, err := s.db.Exec(`UPDATE registration_links SET expires_at=$1 WHERE token_hash=$2`, time.Now().Unix()-1, hashToken(token)); err != nil {
		t.Fatal(err)
	}
	if err := s.completeRegistration(context.Background(), pending, &webauthn.Credential{ID: []byte("expired")}); !errors.Is(err, errRegistrationUnavailable) {
		t.Fatalf("expired finish: %v", err)
	}
	if w := request(s, "POST", "/api/register/begin", `{"linkToken":"`+token+`"}`, ""); w.Code != 403 {
		t.Fatal("expired begin accepted")
	}
	if w := request(s, "POST", "/api/register/begin", `{"linkToken":"invalid"}`, ""); w.Code != 403 {
		t.Fatal("invalid token accepted")
	}
}

func TestPostgresBootstrapRetryAndRace(t *testing.T) {
	s := postgresServer(t)
	if err := s.setAppState(context.Background(), "bootstrap_token_sha256", hashToken("bootstrap")); err != nil {
		t.Fatal(err)
	}
	var registrations []registrationContext
	for _, username := range []string{"first", "second"} {
		w := request(s, "POST", "/api/register/begin", `{"username":"`+username+`","token":"bootstrap"}`, "")
		if w.Code != 200 {
			t.Fatalf("bootstrap begin: %d %s", w.Code, w.Body.String())
		}
		registration, _, ok := s.mem.GetRegistration(w.Result().Cookies()[0].Value)
		if !ok {
			t.Fatal("missing session")
		}
		registrations = append(registrations, registration)
	}
	if n, err := s.countUsers(context.Background()); err != nil || n != 0 {
		t.Fatal("begin persisted incomplete user")
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i, registration := range registrations {
		wg.Add(1)
		go func(i int, registration registrationContext) {
			defer wg.Done()
			results <- s.completeRegistration(context.Background(), registration, &webauthn.Credential{ID: []byte(fmt.Sprint(i))})
		}(i, registration)
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, errRegistrationUnavailable) {
			t.Fatal(err)
		}
	}
	if success != 1 {
		t.Fatalf("bootstrap created %d users", success)
	}
	var admins int
	if err := s.db.QueryRow(`SELECT count(*) FROM users WHERE is_admin`).Scan(&admins); err != nil || admins != 1 {
		t.Fatal("missing bootstrap admin")
	}
	if _, err := s.getAppState(context.Background(), "bootstrap_token_sha256"); err == nil {
		t.Fatal("bootstrap token not consumed")
	}
}

func TestPostgresExistingUserUpgrade(t *testing.T) {
	s := postgresServer(t)
	if err := goose.DownTo(s.db, "migrations", 1); err != nil {
		t.Fatal(err)
	}
	first, second := uuid.New(), uuid.New()
	if _, err := s.db.Exec(`INSERT INTO users(id,username,created_at) VALUES($1,'original',1),($2,'later',2)`, first[:], second[:]); err != nil {
		t.Fatal(err)
	}
	if err := gatewaydb.RunMigrations(s.db); err != nil {
		t.Fatal(err)
	}
	original, err := s.getUserByUsername(context.Background(), "original")
	if err != nil || !original.IsAdmin {
		t.Fatal("original user not promoted")
	}
	later, err := s.getUserByUsername(context.Background(), "later")
	if err != nil || later.IsAdmin {
		t.Fatal("later user became admin")
	}
}
