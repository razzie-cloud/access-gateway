package app

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/razzie-cloud/access-gateway/internal/logging"
	"github.com/razzie-cloud/access-gateway/internal/web"
)

func (s *Server) routes() {
	s.limits = newRequestLimits()
	handle := func(pattern string, handler http.HandlerFunc) {
		s.mux.Handle(pattern, logging.Route(pattern, handler))
	}
	handle("/.well-known/paseto-keys", s.handleAssertionKeys)
	handle("/forward_auth", s.handleForwardAuth)
	handle("/forward_auth/admin", s.handleAdminForwardAuth)
	handle("/auth/authorize", s.handleAuthorize)
	s.mux.Handle("/static/", logging.Route("/static/", http.FileServer(http.FS(web.Assets))))
	handle("/", s.handlePage)
	handle("/register", s.handlePage)
	handle("/ui/state", s.handleState)
	handle("/ui/users", s.handleCreateUser)
	handle("/ui/admin", s.handleAdmin)
	handle("/ui/activity", s.handleActivity)
	handle("/ui/devices/rename", s.handleRenameDevice)
	handle("/ui/devices/remove", s.handleRemoveDevice)
	handle("/ui/sessions/remove", s.handleRemoveSession)
	handle("/ui/links", s.handleCreateLink)
	handle("/ui/logout", s.handleUILogout)
	handle("/api/bootstrap", s.handleBootstrap)
	handle("/api/register/begin", s.handleRegisterBegin)
	handle("/api/register/finish", s.handleRegisterFinish)
	handle("/api/login/begin", s.handleLoginBegin)
	handle("/api/login/finish", s.handleLoginFinish)
	handle("/api/me", s.handleMe)
	handle("/api/logout", s.handleLogout)
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
		logging.Fail(r.Context(), slog.LevelError, "postgres", err)
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
			logging.Fail(r.Context(), slog.LevelError, "postgres", countErr)
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
	registration.DiscoverableRequired = true
	waUser := WebAuthnUser{User: registration.User}
	if registration.LinkHash != "" {
		waUser, err = s.loadWebAuthnUser(ctx, registration.User)
		if err != nil {
			logging.Fail(r.Context(), slog.LevelError, "postgres", err)
			writeJSON(w, 500, map[string]string{"error": "db error"})
			return
		}
	}
	exclusions := make([]protocol.CredentialDescriptor, 0, len(waUser.Creds))
	for _, credential := range waUser.Creds {
		// Legacy credentials did not record discoverability. Do not block
		// upgrading one to a discoverable credential on the same authenticator.
		if credential.Extensions.RK != nil && *credential.Extensions.RK {
			exclusions = append(exclusions, credential.Descriptor())
		}
	}
	opts, sd, err := s.wa.BeginRegistration(waUser,
		webauthn.WithExclusions(exclusions),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithExtensions(webauthn.WithExtensionCredProps()),
	)
	if err != nil {
		logging.Fail(r.Context(), slog.LevelError, "webauthn", err)
		writeJSON(w, 500, map[string]string{"error": "webauthn error"})
		return
	}
	sid := newSID()
	if err := s.sessions.PutRegistration(r.Context(), sid, registration, *sd); err != nil {
		logging.Fail(r.Context(), slog.LevelError, "redis", err)
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
		logging.Fail(r.Context(), slog.LevelError, "redis", err)
		writeJSON(w, 503, map[string]string{"error": "session storage unavailable"})
		return
	}
	if !ok {
		writeJSON(w, 400, map[string]string{"error": "registration session expired"})
		return
	}
	if !registration.DiscoverableRequired {
		// A pre-upgrade prompt may have requested a non-discoverable key.
		// Restart before consuming its still-valid enrollment authorization.
		writeJSON(w, http.StatusConflict, map[string]string{"error": "registration requirements changed; start registration again"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	waUser := WebAuthnUser{User: registration.User}
	if registration.LinkHash != "" {
		waUser, err = s.loadWebAuthnUser(ctx, registration.User)
		if err != nil {
			logging.Fail(r.Context(), slog.LevelError, "postgres", err)
			writeJSON(w, 500, map[string]string{"error": "db error"})
			return
		}
	}
	credential, err := s.wa.FinishRegistration(waUser, sd, r)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "webauthn finish failed"})
		return
	}
	if credential.Extensions.RK != nil && !*credential.Extensions.RK {
		writeJSON(w, 400, map[string]string{"error": "a discoverable passkey is required"})
		return
	}
	// Older clients may omit credProps even though residentKey=required
	// succeeded. Remember the requirement for future exclusion lists.
	discoverable := true
	credential.Extensions.RK = &discoverable
	if err := s.completeRegistration(ctx, registration, credential); err != nil {
		if errors.Is(err, errRegistrationUnavailable) {
			writeJSON(w, 409, map[string]string{"error": "registration link expired, used, or bootstrap already completed"})
		} else {
			logging.Fail(r.Context(), slog.LevelError, "postgres", err)
			writeJSON(w, 500, map[string]string{"error": "failed to store credential"})
		}
		return
	}
	if err := s.sessions.DeleteSID(r.Context(), sid.Value); err != nil {
		// Enrollment already committed in PostgreSQL. Its transaction prevents
		// reuse even if the expired ceremony cannot yet be removed from Redis.
		logging.For(r.Context()).Warn("Unable to remove completed registration session", "event", "registration.cleanup_failed", "operation", "delete_ceremony", "dependency", "redis", "error_kind", logging.Kind(err))
	}
	s.setCookie(w, "sid", "", -1)
	writeJSON(w, 200, map[string]any{"ok": true})
}

type loginBeginReq struct {
	Username string `json:"username"`
}

const loginFailureMessage = "sign-in failed; check your passkey and try again"

func (s *Server) rejectLogin(w http.ResponseWriter, r *http.Request, username, reason string) {
	// Quote and bound attacker-controlled names. Never log bearer cookies,
	// challenges, signatures, bootstrap tokens or registration links.
	logging.For(r.Context()).Warn("Login rejected", "event", "login.rejected", "client_ip", s.clientIP(r).String(), "claimed_username", username[:min(len(username), 64)], "reason", reason)
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": loginFailureMessage})
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
	if !validUsername(req.Username) {
		writeJSON(w, 400, map[string]string{"error": "username must contain 1–64 bytes"})
		return
	}
	// Record the attempt before the browser prompt, including canceled prompts
	// and unknown accounts. A claimed name is never an authenticated identity.
	logging.For(r.Context()).Info("Login attempted", "event", "login.attempted", "client_ip", s.clientIP(r).String(), "claimed_username", req.Username)
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	allowed, user, err := s.loginCredentials(ctx, req.Username)
	if err != nil {
		logging.Fail(r.Context(), slog.LevelError, "application", err)
		writeJSON(w, 503, map[string]string{"error": "unable to sign in; try again later"})
		return
	}
	opts, sessionData, err := s.wa.BeginLogin(user,
		webauthn.WithUserVerification(protocol.VerificationPreferred), webauthn.WithAllowedCredentials(allowed))
	if err != nil {
		logging.Fail(r.Context(), slog.LevelError, "webauthn", err)
		writeJSON(w, 500, map[string]string{"error": "webauthn error"})
		return
	}

	// The library requires every stored allowed ID to be owned by the user.
	// Keep only real IDs in private session data; public options include padding.
	sessionData.AllowedCredentialIDs = nil
	for _, credential := range user.Creds {
		sessionData.AllowedCredentialIDs = append(sessionData.AllowedCredentialIDs, credential.ID)
	}
	sid := newSID()
	if err := s.sessions.PutLogin(ctx, sid, req.Username, *sessionData); err != nil {
		logging.Fail(r.Context(), slog.LevelError, "redis", err)
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
		s.rejectLogin(w, r, "", "missing ceremony cookie")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	claimedUsername, sd, ok, err := s.sessions.GetLogin(ctx, sid.Value)
	if err != nil {
		logging.Fail(r.Context(), slog.LevelError, "redis", err)
		writeJSON(w, 503, map[string]string{"error": "session storage unavailable"})
		return
	}
	if !ok {
		s.rejectLogin(w, r, "", "ceremony expired or missing")
		return
	}

	if claimedUsername == "" || len(sd.UserID) == 0 || len(sd.AllowedCredentialIDs) == 0 {
		s.rejectLogin(w, r, claimedUsername, "restart sign-in after upgrade")
		return
	}

	u, err := s.getUserByUsername(ctx, claimedUsername)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			logging.Fail(r.Context(), slog.LevelError, "application", err)
			writeJSON(w, 503, map[string]string{"error": "unable to sign in; try again later"})
		} else {
			s.rejectLogin(w, r, claimedUsername, "invalid assertion or unknown credential")
		}
		return
	}
	user, err := s.loadWebAuthnUser(ctx, u)
	if err != nil {
		logging.Fail(r.Context(), slog.LevelError, "application", err)
		writeJSON(w, 503, map[string]string{"error": "unable to sign in; try again later"})
		return
	}
	// Named login checks the session's account ID and allowlist, and verifies
	// the optional user handle along with the challenge, RP/origin and signature.
	cred, err := s.wa.FinishLogin(user, sd, r)
	if err != nil {
		s.rejectLogin(w, r, claimedUsername, "invalid assertion or unknown credential")
		return
	}

	auth := make([]byte, 32)
	_, _ = rand.Read(auth)
	authHex := hex.EncodeToString(auth)
	ok, err = s.completeDeviceLogin(ctx, sid.Value, authHex, u, cred)
	if err != nil {
		if errors.Is(err, errSessionStore) {
			logging.Fail(r.Context(), slog.LevelError, "redis", err)
			writeJSON(w, 503, map[string]string{"error": "session storage unavailable"})
		} else if errors.Is(err, sql.ErrNoRows) {
			s.rejectLogin(w, r, claimedUsername, "device removed")
		} else {
			logging.Fail(r.Context(), slog.LevelError, "application", err)
			writeJSON(w, 500, map[string]string{"error": "failed to complete login"})
		}
		return
	}
	if !ok {
		s.rejectLogin(w, r, claimedUsername, "ceremony expired or consumed")
		return
	}

	logging.For(r.Context()).Info("Login succeeded", "event", "login.succeeded", "user_id", userID(u.ID), "client_ip", s.clientIP(r).String())
	s.setCookie(w, "auth", authHex, int(authTTL.Seconds()))

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
		logging.Fail(r.Context(), slog.LevelError, "redis", err)
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
			logging.Fail(r.Context(), slog.LevelError, "redis", err)
			writeJSON(w, 503, map[string]string{"error": "session storage unavailable"})
			return
		}
		if c.Value != "" {
			logging.For(r.Context()).Info("Logout completed", "event", "logout.completed")
		}
	}
	s.setCookie(w, "auth", "", -1)
	writeJSON(w, 200, map[string]any{"ok": true})
}
