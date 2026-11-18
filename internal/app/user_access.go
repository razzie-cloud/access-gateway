package app

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/razzie-cloud/access-gateway/internal/logging"
)

var (
	errUserDisabled        = errors.New("user disabled")
	errUserAccessForbidden = errors.New("user access change forbidden")
	errUserAccessSelf      = errors.New("cannot disable own account")
)

// Authentication and enrollment hold a shared user-row lock until their writes
// finish. Access changes lock the same row exclusively, so a concurrent login
// either precedes the revocation sweep or sees the disabled state afterward.
func lockEnabledUser(ctx context.Context, tx *sql.Tx, id []byte) error {
	var disabled bool
	if err := tx.QueryRowContext(ctx, `SELECT disabled FROM users WHERE id=$1 FOR SHARE`, id).Scan(&disabled); err != nil {
		return err
	}
	if disabled {
		return errUserDisabled
	}
	return nil
}

// Both actor and target are locked in UUID order. This rechecks the actor's live
// authority and prevents two administrators from concurrently disabling each
// other or deadlocking. Redis failure still commits disabled=true; enabling is
// allowed only after a successful sweep, so old sessions can never be restored.
func (s *Server) changeUserAccess(ctx context.Context, actor User, targetID []byte, enabled bool) (User, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id,username,is_admin,disabled,created_at FROM users
 WHERE id=$1 OR id=$2 ORDER BY id FOR UPDATE`, actor.ID, targetID)
	if err != nil {
		return User{}, err
	}
	var target User
	allowed := false
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Username, &user.IsAdmin, &user.Disabled, &user.CreatedAt); err != nil {
			rows.Close()
			return User{}, err
		}
		if equalID(user.ID, actor.ID) {
			allowed = user.IsAdmin && !user.Disabled
		}
		if equalID(user.ID, targetID) {
			target = user
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return User{}, err
	}
	if !allowed {
		return User{}, errUserAccessForbidden
	}
	if len(target.ID) == 0 {
		return User{}, sql.ErrNoRows
	}
	if !enabled && equalID(actor.ID, targetID) {
		return User{}, errUserAccessSelf
	}
	if enabled && !target.Disabled {
		return target, nil // An idempotent enable must not revoke active sessions.
	}
	// Leave enough time to commit the disabled state even if Redis is down.
	cleanup, cancel := context.WithTimeout(ctx, 5*time.Second)
	revokeErr := s.sessions.RevokeUserSessions(cleanup, target.Username)
	cancel()
	target.Disabled = !enabled || revokeErr != nil
	if _, err := tx.ExecContext(ctx, `UPDATE users SET disabled=$2 WHERE id=$1`, target.ID, target.Disabled); err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	return target, revokeErr
}

func (s *Server) handleUserAccess(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.activityActor(w, r, http.MethodPost)
	if !ok {
		return
	}
	if !actor.IsAdmin {
		s.writeError(w, r, http.StatusForbidden, "Administrator access required")
		return
	}
	if err := r.ParseForm(); err != nil {
		s.writeError(w, r, http.StatusBadRequest, "Invalid form")
		return
	}
	id, err := uuid.Parse(r.PostForm.Get("user_id"))
	values := r.PostForm["enabled"]
	if err != nil || len(r.PostForm["user_id"]) != 1 || len(values) != 1 || (values[0] != "true" && values[0] != "false") {
		s.writeError(w, r, http.StatusBadRequest, "Choose a user and a valid access state")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	target, err := s.changeUserAccess(ctx, actor, id[:], values[0] == "true")
	status, message := http.StatusOK, "User enabled. They can sign in again; deleted sessions are not restored."
	if target.Disabled {
		message = "User disabled. All their gateway and app sessions have been revoked. Further login attempts are blocked until re-enabled."
	}
	if err != nil {
		switch {
		case errors.Is(err, errUserAccessForbidden):
			s.writeError(w, r, http.StatusForbidden, "Administrator access required")
			return
		case errors.Is(err, errUserAccessSelf):
			s.writeError(w, r, http.StatusConflict, "You cannot disable your own account")
			return
		case errors.Is(err, sql.ErrNoRows):
			s.writeError(w, r, http.StatusNotFound, "User not found")
			return
		case errors.Is(err, errSessionStore) && target.Disabled:
			logging.Fail(r.Context(), slog.LevelError, "redis", err)
			status = http.StatusServiceUnavailable
			message = "User remains disabled, but session cleanup could not finish. Retry disabling or enabling once session storage is available."
		default:
			logging.Fail(r.Context(), slog.LevelError, "postgres", err)
			s.writeError(w, r, http.StatusServiceUnavailable, "Unable to change user access. Refresh Users to check their current state before retrying.")
			return
		}
	}
	logging.For(r.Context()).Info("User access changed", "event", "user.access_changed", "actor_user_id", userID(actor.ID), "target_user_id", userID(target.ID), "disabled", target.Disabled, "sessions_revoked", err == nil)
	data, loadErr := s.activity(r, actor)
	if loadErr != nil {
		// Users can still be refreshed when Redis is unavailable. Return just
		// their authoritative database state rather than leaving a stale switch.
		users, userErr := s.listUsers(r.Context())
		if userErr != nil {
			s.writeError(w, r, http.StatusServiceUnavailable, "Access changed, but unable to refresh Users. Reload the page.")
			return
		}
		data = viewData{User: &actor, UsersError: "Access changed, but activity could not refresh. Refresh the other panels when session storage is available."}
		for _, user := range users {
			data.AdminUsers = append(data.AdminUsers, adminUser{User: user, UUID: userID(user.ID)})
		}
		if status != http.StatusOK {
			data.UsersError = message
		} else {
			data.UsersMessage = message
		}
		w.Header().Set("HX-Retarget", "#users")
		w.Header().Set("HX-Reswap", "outerHTML")
		s.render(w, r, http.StatusServiceUnavailable, "activity-users", data)
		return
	}
	if status == http.StatusOK {
		data.UsersMessage = message
	} else {
		data.UsersError = message
	}
	s.render(w, r, status, "activity", data)
}
