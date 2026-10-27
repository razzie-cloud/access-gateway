package app

import (
	"bytes"
	"encoding/base64"
	"errors"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/razzie-cloud/access-gateway/internal/web"
	"github.com/skip2/go-qrcode"
)

var templates = template.Must(template.ParseFS(web.Assets, "templates.html"))

type viewData struct {
	NeedsRegistration bool
	Invite            bool
	User              *User
	Users             []User
	Error             string
	Message           string
	Link              string
	QR                template.URL
	Expires           string
}

func render(w http.ResponseWriter, status int, name string, data viewData) {
	var buf bytes.Buffer
	if err := templates.ExecuteTemplate(&buf, name, data); err != nil {
		log.Printf("render %s: %v", name, err)
		http.Error(w, "Unable to render page", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
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
		rows, err := s.db.QueryContext(r.Context(), `SELECT id,username,is_admin,created_at FROM users ORDER BY username`)
		if err != nil {
			return data, err
		}
		defer rows.Close()
		for rows.Next() {
			var u User
			if err := rows.Scan(&u.ID, &u.Username, &u.IsAdmin, &u.CreatedAt); err != nil {
				return data, err
			}
			data.Users = append(data.Users, u)
		}
		if err := rows.Err(); err != nil {
			return data, err
		}
	}
	return data, nil
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
	render(w, 200, "page", data)
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	data, err := s.state(r)
	if err != nil {
		render(w, 500, "message", viewData{Error: "Unable to load account"})
		return
	}
	render(w, 200, "state", data)
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	user, err := s.currentUser(r)
	if err != nil {
		render(w, 401, "message", viewData{Error: "Sign in first"})
		return
	}
	if !user.IsAdmin {
		render(w, 403, "message", viewData{Error: "Administrator access required"})
		return
	}
	if err := r.ParseForm(); err != nil {
		render(w, 400, "message", viewData{Error: "Invalid form"})
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	if !validUsername(username) {
		render(w, 400, "message", viewData{Error: "Username must contain 1–64 bytes"})
		return
	}
	id := uuid.New()
	_, err = s.db.ExecContext(r.Context(), `INSERT INTO users(id,username,is_admin,created_at) VALUES($1,$2,FALSE,$3)`, id[:], username, time.Now().Unix())
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			render(w, 409, "message", viewData{Error: "That username already exists"})
		} else {
			render(w, 500, "message", viewData{Error: "Unable to create user"})
		}
		return
	}
	// Refresh the account selector so the administrator can immediately issue a link.
	data, err := s.state(r)
	if err != nil {
		render(w, 500, "message", viewData{Error: "User created, but unable to refresh accounts. Reload the page."})
		return
	}
	data.Message = "User created. Choose them under Device registration links to generate their first link."
	w.Header().Set("HX-Retarget", "#content")
	render(w, 200, "state", data)
}

func (s *Server) handleCreateLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	actor, err := s.currentUser(r)
	if err != nil {
		render(w, 401, "message", viewData{Error: "Sign in first"})
		return
	}
	if err := r.ParseForm(); err != nil {
		render(w, 400, "message", viewData{Error: "Invalid form"})
		return
	}
	minutes, err := strconv.Atoi(r.FormValue("minutes"))
	if err != nil {
		render(w, 400, "message", viewData{Error: "Enter expiration in whole minutes"})
		return
	}
	lifetime, err := linkLifetime(minutes)
	if err != nil {
		render(w, 400, "message", viewData{Error: err.Error()})
		return
	}
	target := strings.TrimSpace(r.FormValue("username"))
	if target == "" {
		target = actor.Username
	}
	if target != actor.Username && !actor.IsAdmin {
		render(w, 403, "message", viewData{Error: "You can only register your own devices"})
		return
	}
	user, err := s.getUserByUsername(r.Context(), target)
	if err != nil {
		render(w, 404, "message", viewData{Error: "User not found"})
		return
	}
	token, err := randomToken()
	if err != nil {
		render(w, 500, "message", viewData{Error: "Unable to generate link"})
		return
	}
	link := strings.TrimRight(s.cfg.Origin, "/") + "/register#" + token
	png, err := qrcode.Encode(link, qrcode.Medium, 320)
	if err != nil {
		render(w, 500, "message", viewData{Error: "Unable to generate QR code"})
		return
	}
	expires := time.Now().Add(lifetime)
	_, err = s.db.ExecContext(r.Context(), `INSERT INTO registration_links(token_hash,user_id,expires_at,created_at) VALUES($1,$2,$3,$4)`, hashToken(token), user.ID, expires.Unix(), time.Now().Unix())
	if err != nil {
		render(w, 500, "message", viewData{Error: "Unable to save registration link"})
		return
	}
	// QR bytes come from our encoder, never from user-supplied HTML or URLs.
	render(w, 200, "link", viewData{User: &user, Link: link, QR: template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png)), Expires: expires.UTC().Format(time.RFC1123)})
}

func (s *Server) handleUILogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	if cookie, err := r.Cookie("auth"); err == nil {
		s.mem.DeleteAuth(cookie.Value)
	}
	s.setCookie(w, "auth", "", -1)
	s.handleStateAfterLogout(w, r)
}

func (s *Server) handleStateAfterLogout(w http.ResponseWriter, r *http.Request) {
	n, err := s.countUsers(r.Context())
	if err != nil {
		render(w, 500, "message", viewData{Error: "Unable to load account"})
		return
	}
	render(w, 200, "state", viewData{NeedsRegistration: n == 0})
}
