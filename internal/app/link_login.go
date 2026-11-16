package app

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/razzie-cloud/access-gateway/internal/logging"
)

const linkUnavailableMessage = "invalid, expired or used registration token; ask for a new link"

func (s *Server) handleLinkLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.methodNotAllowed(w, r, http.MethodPost)
		return
	}
	var req struct {
		LinkToken string `json:"linkToken"`
	}
	if err := readJSON(r, &req); err != nil {
		s.writeError(w, r, http.StatusBadRequest, "bad json")
		return
	}
	decoded, err := hex.DecodeString(req.LinkToken)
	if err != nil || len(decoded) != 32 || req.LinkToken != strings.ToLower(req.LinkToken) {
		s.writeError(w, r, http.StatusForbidden, linkUnavailableMessage)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	token, user, err := s.completeLinkLogin(ctx, req.LinkToken)
	if err != nil {
		switch {
		case errors.Is(err, errRegistrationUnavailable):
			s.writeError(w, r, http.StatusForbidden, linkUnavailableMessage)
		case errors.Is(err, errSessionStore):
			logging.Fail(r.Context(), slog.LevelError, "redis", err)
			s.writeError(w, r, http.StatusServiceUnavailable, "session storage unavailable; try again later")
		default:
			logging.Fail(r.Context(), slog.LevelError, "postgres", err)
			s.writeError(w, r, http.StatusServiceUnavailable, "unable to sign in; try again later")
		}
		return
	}
	// The bearer session is exposed only after PostgreSQL commits consumption.
	s.setCookie(w, "auth", token, int(authTTL.Seconds()))
	s.setCookie(w, "sid", "", -1)
	logging.For(r.Context()).Info("Login succeeded", "event", "login.succeeded", "user_id", userID(user.ID), "client_ip", s.clientIP(r).String(), "authentication_method", "registration_link")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// The link row is the authority for both enrollment and login, across replicas.
// Hold its lock until the Redis session exists and consumption commits. A failed
// Redis write rolls back consumption. A failed commit discards the undisclosed
// session with an independent cleanup context; never return a cookie on error.
func (s *Server) completeLinkLogin(ctx context.Context, linkToken string) (string, User, error) {
	var user User
	token, err := randomToken()
	if err != nil {
		return "", user, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", user, err
	}
	defer tx.Rollback()
	var expires int64
	var used sql.NullInt64
	linkHash := hashToken(linkToken)
	err = tx.QueryRowContext(ctx, `SELECT u.id,u.username,u.is_admin,u.created_at,l.expires_at,l.used_at
 FROM registration_links l JOIN users u ON u.id=l.user_id WHERE l.token_hash=$1 FOR UPDATE OF l`, linkHash).Scan(
		&user.ID, &user.Username, &user.IsAdmin, &user.CreatedAt, &expires, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return "", User{}, errRegistrationUnavailable
	}
	if err != nil {
		return "", User{}, err
	}
	if used.Valid || expires <= time.Now().Unix() {
		return "", User{}, errRegistrationUnavailable
	}
	if _, err = tx.ExecContext(ctx, `UPDATE registration_links SET used_at=$2 WHERE token_hash=$1`, linkHash, time.Now().Unix()); err != nil {
		return "", User{}, err
	}
	// Also clean up ambiguous Redis errors: the write may have reached Redis
	// even when its reply did not reach this process. Tokens are fresh per try.
	committed := false
	defer func() {
		if !committed {
			cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := s.sessions.DeleteAuth(cleanup, token); err != nil {
				logging.For(ctx).Warn("Unable to remove undisclosed link login session", "event", "login.cleanup_failed", "dependency", "redis", "error_kind", logging.Kind(err))
			}
		}
	}()
	if err := s.sessions.PutLinkAuth(ctx, token, user.Username); err != nil {
		return "", User{}, err
	}
	if err := tx.Commit(); err != nil {
		return "", User{}, err
	}
	committed = true
	return token, user, nil
}
