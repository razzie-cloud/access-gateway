package app

import (
	"bytes"
	"encoding/base64"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/razzie-cloud/access-gateway/internal/logging"
	"github.com/razzie-cloud/access-gateway/internal/web"
	"github.com/skip2/go-qrcode"
)

var templates = template.Must(template.ParseFS(web.Assets, "templates.html"))

type viewData struct {
	LandingOrigin     string
	GatewayOrigin     string
	NeedsRegistration bool
	Invite            bool
	User              *User
	Users             []User
	Error             string
	Message           string
	Link              string
	QR                template.URL
	Expires           string
	AdminUsers        []adminUser
	Sessions          []sessionView
	Devices           []deviceView
}

type adminUser struct {
	User
	UUID string
}

func render(w http.ResponseWriter, r *http.Request, status int, name string, data viewData) {
	if data.LandingOrigin == "" {
		data.LandingOrigin = "https://razzie.cloud"
	}
	var buf bytes.Buffer
	if err := templates.ExecuteTemplate(&buf, name, data); err != nil {
		logging.Fields(r.Context(), "template", name)
		logging.Fail(r.Context(), slog.LevelError, "render_template", err)
		http.Error(w, "Unable to render page", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// The proxy displays this response on the protected app's origin. Both asset
// URLs and their CSP sources must therefore refer to the configured gateway,
// never to the request's Host or forwarded headers. This page needs no scripts.
func (s *Server) renderAdminDenied(w http.ResponseWriter, r *http.Request) {
	origin := strings.TrimRight(s.cfg.Origin, "/")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src "+origin+"; img-src "+origin+"; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
	render(w, r, http.StatusForbidden, "admin-denied", viewData{
		GatewayOrigin: origin,
		LandingOrigin: strings.TrimRight(s.cfg.LandingOrigin, "/"),
	})
}

func (s *Server) state(r *http.Request) (viewData, error) {
	var data viewData
	n, err := s.countUsers(r.Context())
	if err != nil {
		return data, err
	}
	data.NeedsRegistration = n == 0
	user, err := s.currentUser(r)
	if errors.Is(err, http.ErrNoCookie) {
		return data, nil
	}
	if err != nil {
		return data, err
	}
	data.User = &user
	if user.IsAdmin {
		data.Users, err = s.listUsers(r.Context())
		if err != nil {
			return data, err
		}
	}
	return data, nil
}

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	user, err := s.currentUser(r)
	if err != nil {
		if errors.Is(err, errSessionStore) {
			logging.Fail(r.Context(), slog.LevelError, "redis", err)
			render(w, r, 503, "message", viewData{Error: "Session storage unavailable"})
			return
		}
		render(w, r, 401, "message", viewData{Error: "Sign in first"})
		return
	}
	if !user.IsAdmin {
		render(w, r, 403, "message", viewData{Error: "Administrator access required"})
		return
	}
	s.renderActivity(w, r, user, "")
}

func (s *Server) handlePage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/register" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	data := viewData{Invite: r.URL.Path == "/register"}
	if !data.Invite {
		var err error
		data, err = s.state(r)
		if err != nil {
			http.Error(w, "Unable to load account", 500)
			return
		}
	}
	data.LandingOrigin = s.cfg.LandingOrigin
	render(w, r, 200, "page", data)
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	data, err := s.state(r)
	if err != nil {
		logging.Fail(r.Context(), slog.LevelError, "application", err)
		render(w, r, 500, "message", viewData{Error: "Unable to load account"})
		return
	}
	render(w, r, 200, "state", data)
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	user, err := s.currentUser(r)
	if err != nil {
		if errors.Is(err, errSessionStore) {
			logging.Fail(r.Context(), slog.LevelError, "redis", err)
			render(w, r, 503, "message", viewData{Error: "Session storage unavailable"})
			return
		}
		render(w, r, 401, "message", viewData{Error: "Sign in first"})
		return
	}
	if !user.IsAdmin {
		render(w, r, 403, "message", viewData{Error: "Administrator access required"})
		return
	}
	if err := r.ParseForm(); err != nil {
		render(w, r, 400, "message", viewData{Error: "Invalid form"})
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	if !validUsername(username) {
		render(w, r, 400, "message", viewData{Error: "Username must contain 1–64 bytes"})
		return
	}
	id := uuid.New()
	_, err = s.db.ExecContext(r.Context(), `INSERT INTO users(id,username,is_admin,created_at) VALUES($1,$2,FALSE,$3)`, id[:], username, time.Now().Unix())
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			render(w, r, 409, "message", viewData{Error: "That username already exists"})
		} else {
			logging.Fail(r.Context(), slog.LevelError, "application", err)
			render(w, r, 500, "message", viewData{Error: "Unable to create user"})
		}
		return
	}
	logging.For(r.Context()).Info("User created", "event", "user.created", "actor_user_id", userID(user.ID), "target_user_id", id.String())
	// Refresh the account selector so the administrator can immediately issue a link.
	data, err := s.state(r)
	if err != nil {
		logging.Fail(r.Context(), slog.LevelError, "application", err)
		render(w, r, 500, "message", viewData{Error: "User created, but unable to refresh accounts. Reload the page."})
		return
	}
	data.Message = "User created. Choose them under Device registration links to generate their first link."
	w.Header().Set("HX-Retarget", "#content")
	render(w, r, 200, "state", data)
}

func (s *Server) handleCreateLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	actor, err := s.currentUser(r)
	if err != nil {
		if errors.Is(err, errSessionStore) {
			logging.Fail(r.Context(), slog.LevelError, "redis", err)
			render(w, r, 503, "message", viewData{Error: "Session storage unavailable"})
			return
		}
		render(w, r, 401, "message", viewData{Error: "Sign in first"})
		return
	}
	if err := r.ParseForm(); err != nil {
		render(w, r, 400, "message", viewData{Error: "Invalid form"})
		return
	}
	minutes, err := strconv.Atoi(r.FormValue("minutes"))
	if err != nil {
		render(w, r, 400, "message", viewData{Error: "Enter expiration in whole minutes"})
		return
	}
	lifetime, err := linkLifetime(minutes)
	if err != nil {
		render(w, r, 400, "message", viewData{Error: err.Error()})
		return
	}
	target := strings.TrimSpace(r.FormValue("username"))
	if target == "" {
		target = actor.Username
	}
	if target != actor.Username && !actor.IsAdmin {
		render(w, r, 403, "message", viewData{Error: "You can only register your own devices"})
		return
	}
	user, err := s.getUserByUsername(r.Context(), target)
	if err != nil {
		render(w, r, 404, "message", viewData{Error: "User not found"})
		return
	}
	token, err := randomToken()
	if err != nil {
		logging.Fail(r.Context(), slog.LevelError, "application", err)
		render(w, r, 500, "message", viewData{Error: "Unable to generate link"})
		return
	}
	link := strings.TrimRight(s.cfg.Origin, "/") + "/register#" + token
	png, err := qrcode.Encode(link, qrcode.Medium, 320)
	if err != nil {
		logging.Fail(r.Context(), slog.LevelError, "application", err)
		render(w, r, 500, "message", viewData{Error: "Unable to generate QR code"})
		return
	}
	expires := time.Now().Add(lifetime)
	_, err = s.db.ExecContext(r.Context(), `INSERT INTO registration_links(token_hash,user_id,expires_at,created_at) VALUES($1,$2,$3,$4)`, hashToken(token), user.ID, expires.Unix(), time.Now().Unix())
	if err != nil {
		logging.Fail(r.Context(), slog.LevelError, "application", err)
		render(w, r, 500, "message", viewData{Error: "Unable to save registration link"})
		return
	}
	logging.For(r.Context()).Info("Registration link issued", "event", "registration_link.issued", "actor_user_id", userID(actor.ID), "target_user_id", userID(user.ID), "expires_at", expires.UTC())
	// QR bytes come from our encoder, never from user-supplied HTML or URLs.
	render(w, r, 200, "link", viewData{User: &user, Link: link, QR: template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png)), Expires: expires.UTC().Format(time.RFC1123)})
}

func (s *Server) handleUILogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	if cookie, err := r.Cookie("auth"); err == nil {
		if err := s.sessions.DeleteAuth(r.Context(), cookie.Value); err != nil {
			logging.Fail(r.Context(), slog.LevelError, "application", err)
			render(w, r, 503, "message", viewData{Error: "Unable to sign out; try again"})
			return
		}
		if cookie.Value != "" {
			logging.For(r.Context()).Info("Logout completed", "event", "logout.completed")
		}
	}
	s.setCookie(w, "auth", "", -1)
	s.handleStateAfterLogout(w, r)
}

func (s *Server) handleStateAfterLogout(w http.ResponseWriter, r *http.Request) {
	n, err := s.countUsers(r.Context())
	if err != nil {
		logging.Fail(r.Context(), slog.LevelError, "application", err)
		render(w, r, 500, "message", viewData{Error: "Unable to load account"})
		return
	}
	render(w, r, 200, "state", viewData{NeedsRegistration: n == 0})
}
