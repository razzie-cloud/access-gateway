package app

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/razzie-cloud/access-gateway/internal/web"
)

func (s *Server) routes() {
	s.mux.HandleFunc("/", http.FileServer(http.FS(web.Assets)).ServeHTTP)
	s.mux.HandleFunc("/api/bootstrap", s.handleBootstrap)
	s.mux.HandleFunc("/api/register/begin", s.handleRegisterBegin)
	s.mux.HandleFunc("/api/register/finish", s.handleRegisterFinish)
	s.mux.HandleFunc("/api/login/begin", s.handleLoginBegin)
	s.mux.HandleFunc("/api/login/finish", s.handleLoginFinish)
	s.mux.HandleFunc("/api/me", s.handleMe)
	s.mux.HandleFunc("/api/logout", s.handleLogout)
}

/*func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, "web/index.html")
}*/

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 2<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	n, err := s.countUsers(ctx)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "db error"})
		return
	}
	writeJSON(w, 200, map[string]any{"needsRegistration": n == 0})
}

type registerBeginReq struct {
	Username string `json:"username"`
	Token    string `json:"token"`
}

func (s *Server) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req registerBeginReq
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad json"})
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || len(req.Username) > 64 {
		writeJSON(w, 400, map[string]string{"error": "invalid username"})
		return
	}
	if req.Token == "" {
		writeJSON(w, 400, map[string]string{"error": "missing token"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	n, err := s.countUsers(ctx)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "db error"})
		return
	}
	if n > 0 {
		writeJSON(w, 409, map[string]string{"error": "registration closed"})
		return
	}

	if err := s.validateBootstrapToken(ctx, req.Token); err != nil {
		writeJSON(w, 403, map[string]string{"error": "invalid token"})
		return
	}

	u, err := s.createFirstUser(ctx, req.Username)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "failed to create user"})
		return
	}

	waUser, err := s.loadWebAuthnUser(ctx, u)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "db error"})
		return
	}

	opts, sessionData, err := s.wa.BeginRegistration(
		waUser,
		//webauthn.WithUserVerification(webauthn.UserVerificationPreferred),
	)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "webauthn error"})
		return
	}

	sid := s.mem.NewSID()
	s.mem.PutRegistration(sid, req.Username, *sessionData)
	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	writeJSON(w, 200, opts)
}

func (s *Server) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	sid, err := r.Cookie("sid")
	if err != nil || sid.Value == "" {
		writeJSON(w, 400, map[string]string{"error": "missing sid"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	username, sd, ok := s.mem.GetRegistration(sid.Value)
	if !ok {
		writeJSON(w, 400, map[string]string{"error": "registration session expired"})
		return
	}

	u, err := s.getUserByUsername(ctx, username)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "unknown user"})
		return
	}
	waUser, err := s.loadWebAuthnUser(ctx, u)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "db error"})
		return
	}

	cred, err := s.wa.FinishRegistration(waUser, sd, r)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "webauthn finish failed"})
		return
	}

	if err := s.upsertCredential(ctx, u.ID, cred); err != nil {
		writeJSON(w, 500, map[string]string{"error": "failed to store credential"})
		return
	}

	_ = s.clearAppState(ctx, "bootstrap_token_sha256")
	s.mem.DeleteSID(sid.Value)
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", Path: "/", MaxAge: -1})

	writeJSON(w, 200, map[string]any{"ok": true})
}

type loginBeginReq struct {
	Username string `json:"username"`
}

func (s *Server) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req loginBeginReq
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad json"})
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" {
		writeJSON(w, 400, map[string]string{"error": "missing username"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	u, err := s.getUserByUsername(ctx, req.Username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, 404, map[string]string{"error": "user not found"})
			return
		}
		writeJSON(w, 500, map[string]string{"error": "db error"})
		return
	}

	waUser, err := s.loadWebAuthnUser(ctx, u)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "db error"})
		return
	}
	if len(waUser.Creds) == 0 {
		writeJSON(w, 400, map[string]string{"error": "no credentials"})
		return
	}

	opts, sessionData, err := s.wa.BeginLogin(waUser, webauthn.WithUserVerification(protocol.VerificationPreferred))
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "webauthn error"})
		return
	}

	sid := s.mem.NewSID()
	s.mem.PutLogin(sid, req.Username, *sessionData)
	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	writeJSON(w, 200, opts)
}

func (s *Server) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	sid, err := r.Cookie("sid")
	if err != nil || sid.Value == "" {
		writeJSON(w, 400, map[string]string{"error": "missing sid"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	username, sd, ok := s.mem.GetLogin(sid.Value)
	if !ok {
		writeJSON(w, 400, map[string]string{"error": "login session expired"})
		return
	}

	u, err := s.getUserByUsername(ctx, username)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "unknown user"})
		return
	}
	waUser, err := s.loadWebAuthnUser(ctx, u)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "db error"})
		return
	}

	cred, err := s.wa.FinishLogin(waUser, sd, r)
	if err != nil {
		writeJSON(w, 401, map[string]string{"error": "webauthn login failed"})
		return
	}

	if err := s.upsertCredential(ctx, u.ID, cred); err != nil {
		writeJSON(w, 500, map[string]string{"error": "failed to store credential"})
		return
	}

	auth := make([]byte, 32)
	_, _ = rand.Read(auth)
	authHex := hex.EncodeToString(auth)
	s.mem.PutAuth(authHex, username)

	http.SetCookie(w, &http.Cookie{
		Name:     "auth",
		Value:    authHex,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	s.mem.DeleteSID(sid.Value)
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", Path: "/", MaxAge: -1})

	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	c, err := r.Cookie("auth")
	if err != nil || c.Value == "" {
		writeJSON(w, 200, map[string]any{"authenticated": false})
		return
	}
	u, ok := s.mem.GetAuth(c.Value)
	writeJSON(w, 200, map[string]any{"authenticated": ok, "username": u})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	c, err := r.Cookie("auth")
	if err == nil && c.Value != "" {
		s.mem.DeleteAuth(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "auth", Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, 200, map[string]any{"ok": true})
}
