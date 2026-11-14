package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/razzie-cloud/access-gateway/internal/logging"
)

var errRegistrationUnavailable = errors.New("registration unavailable")
var errUsernameTaken = errors.New("username already exists")

// Only hashes are retained in server-side registration sessions and PostgreSQL.
type registrationContext struct {
	User                 User
	NewUser              bool
	LinkHash             string
	BootstrapHash        string
	DeviceName           string
	DiscoverableRequired bool
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func randomToken() (string, error) {
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(token[:]), nil
}

func validUsername(username string) bool {
	return strings.TrimSpace(username) != "" && len(username) <= 64
}

func linkLifetime(minutes int) (time.Duration, error) {
	if minutes < 1 || minutes > 30*24*60 {
		return 0, errors.New("expiration must be between 1 and 43200 minutes (30 days)")
	}
	return time.Duration(minutes) * time.Minute, nil
}

func (s *Server) registrationFromLink(ctx context.Context, token string) (registrationContext, error) {
	registration := registrationContext{LinkHash: hashToken(token)}
	err := s.db.QueryRowContext(ctx, `SELECT l.user_id,COALESCE(u.username,''),COALESCE(u.is_admin,FALSE),COALESCE(u.created_at,0)
 FROM registration_links l LEFT JOIN users u ON u.id=l.user_id
 WHERE l.token_hash=$1 AND l.used_at IS NULL AND l.expires_at>$2`, registration.LinkHash, time.Now().Unix()).Scan(
		&registration.User.ID, &registration.User.Username, &registration.User.IsAdmin, &registration.User.CreatedAt)
	registration.NewUser = registration.User.ID == nil
	return registration, err
}

// Both the authorization and credential are committed together. Row locks serialize
// competing ceremonies, including ceremonies started before another one finished.
func (s *Server) completeRegistration(ctx context.Context, registration registrationContext, credential *webauthn.Credential) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if registration.LinkHash != "" {
		var userID []byte
		var expires int64
		var used sql.NullInt64
		err = tx.QueryRowContext(ctx, `SELECT user_id,expires_at,used_at FROM registration_links WHERE token_hash=$1 FOR UPDATE`, registration.LinkHash).Scan(&userID, &expires, &used)
		if errors.Is(err, sql.ErrNoRows) {
			return errRegistrationUnavailable
		}
		if err != nil {
			return err
		}
		if used.Valid || expires <= time.Now().Unix() || (registration.NewUser && userID != nil) || (!registration.NewUser && !equalID(userID, registration.User.ID)) {
			return errRegistrationUnavailable
		}
		if registration.NewUser {
			if !validUsername(registration.User.Username) || len(registration.User.ID) != 16 {
				return errRegistrationUnavailable
			}
			// Never attach a new-user invitation to an existing username. The
			// unique constraint also protects names claimed by concurrent finishes.
			if _, err = tx.ExecContext(ctx, `INSERT INTO users(id,username,is_admin,created_at) VALUES($1,$2,FALSE,$3)`, registration.User.ID, registration.User.Username, time.Now().Unix()); err != nil {
				var pgErr *pgconn.PgError
				if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "users_username_key" {
					return errUsernameTaken
				}
				return err
			}
		}
		if _, err = tx.ExecContext(ctx, `UPDATE registration_links SET used_at=$2,user_id=$3 WHERE token_hash=$1`, registration.LinkHash, time.Now().Unix(), registration.User.ID); err != nil {
			return err
		}
	} else {
		if err := lockBootstrap(ctx, tx); err != nil {
			return err
		}
		var storedHash string
		err = tx.QueryRowContext(ctx, `SELECT value FROM app_states WHERE key='bootstrap_token_sha256' FOR UPDATE`).Scan(&storedHash)
		if errors.Is(err, sql.ErrNoRows) {
			return errRegistrationUnavailable
		}
		if err != nil {
			return err
		}
		if registration.BootstrapHash == "" || storedHash != registration.BootstrapHash {
			return errRegistrationUnavailable
		}
		var count int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return errRegistrationUnavailable
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO users(id,username,is_admin,created_at) VALUES($1,$2,TRUE,$3)`, registration.User.ID, registration.User.Username, time.Now().Unix()); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM app_states WHERE key='bootstrap_token_sha256'`); err != nil {
			return err
		}
	}
	data, err := marshalCredential(credential)
	if err != nil {
		return err
	}
	// Enrollment must never overwrite a credential belonging to another account.
	name := registration.DeviceName
	if name == "" { // Ceremonies started before device naming was introduced.
		name = "Unnamed device"
	}
	var deviceID int64
	if err = tx.QueryRowContext(ctx, `INSERT INTO webauthn_credentials(user_id,credential_id,credential_json,created_at,device_name) VALUES($1,$2,$3,$4,$5) RETURNING id`, registration.User.ID, credential.ID, data, time.Now().Unix(), name).Scan(&deviceID); err != nil {
		return fmt.Errorf("insert credential: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	kind := "link"
	if registration.NewUser {
		kind = "invitation"
	} else if registration.LinkHash == "" {
		kind = "bootstrap"
	}
	logging.For(ctx).Info("Device enrolled", "event", "registration.completed", "user_id", userID(registration.User.ID), "device_id", deviceID, "enrollment_type", kind)
	return nil
}

func equalID(a, b []byte) bool { return string(a) == string(b) }
