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
)

var errRegistrationUnavailable = errors.New("registration unavailable")

// Only hashes are retained in server-side registration sessions and PostgreSQL.
type registrationContext struct {
	User          User
	LinkHash      string
	BootstrapHash string
	DeviceName    string
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
	err := s.db.QueryRowContext(ctx, `SELECT u.id,u.username,u.is_admin,u.created_at
 FROM registration_links l JOIN users u ON u.id=l.user_id
 WHERE l.token_hash=$1 AND l.used_at IS NULL AND l.expires_at>$2`, registration.LinkHash, time.Now().Unix()).Scan(
		&registration.User.ID, &registration.User.Username, &registration.User.IsAdmin, &registration.User.CreatedAt)
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
		if used.Valid || expires <= time.Now().Unix() || !equalID(userID, registration.User.ID) {
			return errRegistrationUnavailable
		}
		if _, err = tx.ExecContext(ctx, `UPDATE registration_links SET used_at=$2 WHERE token_hash=$1`, registration.LinkHash, time.Now().Unix()); err != nil {
			return err
		}
	} else {
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
	if _, err = tx.ExecContext(ctx, `INSERT INTO webauthn_credentials(user_id,credential_id,credential_json,created_at,device_name) VALUES($1,$2,$3,$4,$5)`, registration.User.ID, credential.ID, data, time.Now().Unix(), name); err != nil {
		return fmt.Errorf("insert credential: %w", err)
	}
	return tx.Commit()
}

func equalID(a, b []byte) bool { return string(a) == string(b) }
