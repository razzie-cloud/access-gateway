package app

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/razzie-cloud/access-gateway/internal/web"
)

func (s *Server) routes() {
	s.mux.HandleFunc("/forward_auth", s.handleForwardAuth)
	s.mux.HandleFunc("/auth/authorize", s.handleAuthorize)
	s.mux.Handle("/static/", http.FileServer(http.FS(web.Assets)))
	s.mux.HandleFunc("/", s.handlePage)
	s.mux.HandleFunc("/register", s.handlePage)
	s.mux.HandleFunc("/ui/state", s.handleState)
	s.mux.HandleFunc("/ui/users", s.handleCreateUser)
	s.mux.HandleFunc("/ui/admin", s.handleAdmin)
	s.mux.HandleFunc("/ui/activity", s.handleActivity)
	s.mux.HandleFunc("/ui/devices/rename", s.handleRenameDevice)
	s.mux.HandleFunc("/ui/devices/remove", s.handleRemoveDevice)
	s.mux.HandleFunc("/ui/sessions/remove", s.handleRemoveSession)
	s.mux.HandleFunc("/ui/links", s.handleCreateLink)
	s.mux.HandleFunc("/ui/logout", s.handleUILogout)
	s.mux.HandleFunc("/api/bootstrap", s.handleBootstrap)
	s.mux.HandleFunc("/api/register/begin", s.handleRegisterBegin)
	s.mux.HandleFunc("/api/register/finish", s.handleRegisterFinish)
	s.mux.HandleFunc("/api/login/begin", s.handleLoginBegin)
	s.mux.HandleFunc("/api/login/finish", s.handleLoginFinish)
	s.mux.HandleFunc("/api/me", s.handleMe)
	s.mux.HandleFunc("/api/logout", s.handleLogout)
}

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
	Username   string `json:"username"`
	Token      string `json:"token"`
	LinkToken  string `json:"linkToken"`
	DeviceName string `json:"deviceName"`
}

func (s *Server) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	var req registerBeginReq
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad json"})
		return
	}
	req.DeviceName = strings.TrimSpace(req.DeviceName)
	if req.DeviceName == "" {
		req.DeviceName = "Unnamed device"
	}
	if !validDeviceName(req.DeviceName) {
		writeJSON(w, 400, map[string]string{"error": "device name must contain 1–80 characters without control characters"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	var registration registrationContext
	var err error
	if req.LinkToken != "" {
		// A link always determines the account; never accept a username override.
		if req.Username != "" || req.Token != "" {
			writeJSON(w, 400, map[string]string{"error": "ambiguous registration"})
			return
		}
		registration, err = s.registrationFromLink(ctx, req.LinkToken)
	} else {
		req.Username = strings.TrimSpace(req.Username)
		if !validUsername(req.Username) || req.Token == "" {
			writeJSON(w, 400, map[string]string{"error": "username and bootstrap token required"})
			return
		}
		n, countErr := s.countUsers(ctx)
		if countErr != nil {
			writeJSON(w, 500, map[string]string{"error": "db error"})
			return
		}
		if n > 0 {
			writeJSON(w, 409, map[string]string{"error": "registration closed"})
			return
		}
		err = s.validateBootstrapToken(ctx, req.Token)
		id := uuid.New()
		registration = registrationContext{User: User{ID: id[:], Username: req.Username, IsAdmin: true}, BootstrapHash: hashToken(req.Token)}
	}
	if err != nil {
		writeJSON(w, 403, map[string]string{"error": "invalid, expired or used registration token"})
		return
	}
	registration.DeviceName = req.DeviceName
	waUser := WebAuthnUser{User: registration.User}
	if registration.LinkHash != "" {
		waUser, err = s.loadWebAuthnUser(ctx, registration.User)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "db error"})
			return
		}
	}
	exclusions := make([]protocol.CredentialDescriptor, 0, len(waUser.Creds))
	for _, credential := range waUser.Creds {
		exclusions = append(exclusions, credential.Descriptor())
	}
	opts, sd, err := s.wa.BeginRegistration(waUser, webauthn.WithExclusions(exclusions))
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "webauthn error"})
		return
	}
	sid := newSID()
	if err := s.sessions.PutRegistration(r.Context(), sid, registration, *sd); err != nil {
		writeJSON(w, 503, map[string]string{"error": "session storage unavailable"})
		return
	}
	s.setCookie(w, "sid", sid, 0)
	writeJSON(w, 200, opts)
}

func (s *Server) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	sid, err := r.Cookie("sid")
	if err != nil || sid.Value == "" {
		writeJSON(w, 400, map[string]string{"error": "missing sid"})
		return
	}
	registration, sd, ok, err := s.sessions.GetRegistration(r.Context(), sid.Value)
	if err != nil {
		writeJSON(w, 503, map[string]string{"error": "session storage unavailable"})
		return
	}
	if !ok {
		writeJSON(w, 400, map[string]string{"error": "registration session expired"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	waUser := WebAuthnUser{User: registration.User}
	if registration.LinkHash != "" {
		waUser, err = s.loadWebAuthnUser(ctx, registration.User)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "db error"})
			return
		}
	}
	credential, err := s.wa.FinishRegistration(waUser, sd, r)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "webauthn finish failed"})
		return
	}
	if err := s.completeRegistration(ctx, registration, credential); err != nil {
		if errors.Is(err, errRegistrationUnavailable) {
			writeJSON(w, 409, map[string]string{"error": "registration link expired, used, or bootstrap already completed"})
		} else {
			writeJSON(w, 500, map[string]string{"error": "failed to store credential"})
		}
		return
	}
	if err := s.sessions.DeleteSID(r.Context(), sid.Value); err != nil {
		// Enrollment already committed in PostgreSQL. Its transaction prevents
		// reuse even if the expired ceremony cannot yet be removed from Redis.
		log.Print("unable to remove completed registration session")
	}
	s.setCookie(w, "sid", "", -1)
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

	sid := newSID()
	if err := s.sessions.PutLogin(r.Context(), sid, req.Username, *sessionData); err != nil {
		writeJSON(w, 503, map[string]string{"error": "session storage unavailable"})
		return
	}
	s.setCookie(w, "sid", sid, 0)

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

	username, sd, ok, err := s.sessions.GetLogin(ctx, sid.Value)
	if err != nil {
		writeJSON(w, 503, map[string]string{"error": "session storage unavailable"})
		return
	}
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

	auth := make([]byte, 32)
	_, _ = rand.Read(auth)
	authHex := hex.EncodeToString(auth)
	ok, err = s.completeDeviceLogin(ctx, sid.Value, authHex, u, cred)
	if err != nil {
		if errors.Is(err, errSessionStore) {
			writeJSON(w, 503, map[string]string{"error": "session storage unavailable"})
		} else if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, 401, map[string]string{"error": "device no longer registered"})
		} else {
			writeJSON(w, 500, map[string]string{"error": "failed to complete login"})
		}
		return
	}
	if !ok {
		writeJSON(w, 400, map[string]string{"error": "login session expired or already used"})
		return
	}

	s.setCookie(w, "auth", authHex, 0)

	s.setCookie(w, "sid", "", -1)

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
	u, ok, err := s.sessions.GetAuth(r.Context(), c.Value)
	if err != nil {
		writeJSON(w, 503, map[string]string{"error": "session storage unavailable"})
		return
	}
	writeJSON(w, 200, map[string]any{"authenticated": ok, "username": u})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	c, err := r.Cookie("auth")
	if err == nil && c.Value != "" {
		if err := s.sessions.DeleteAuth(r.Context(), c.Value); err != nil {
			writeJSON(w, 503, map[string]string{"error": "session storage unavailable"})
			return
		}
	}
	s.setCookie(w, "auth", "", -1)
	writeJSON(w, 200, map[string]any{"ok": true})
}
