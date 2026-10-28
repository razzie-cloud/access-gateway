package app

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/go-rel/rel"
	"github.com/go-rel/rel/where"
	"github.com/go-webauthn/webauthn/webauthn"
)

func (s *Server) listUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,username,is_admin,created_at FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.IsAdmin, &u.CreatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *Server) countUsers(ctx context.Context) (int, error) {
	var users []User
	if err := s.repo.FindAll(ctx, &users); err != nil {
		return 0, err
	}
	return len(users), nil
}

func (s *Server) getAppState(ctx context.Context, key string) (string, error) {
	var st AppState
	err := s.repo.Find(ctx, &st, rel.Where(where.Eq("key", key)))
	if err != nil {
		return "", err
	}
	return st.Value, nil
}

func (s *Server) setAppState(ctx context.Context, key, value string) error {
	now := time.Now().Unix()
	st := AppState{Key: key, Value: value, UpdatedAt: now}
	// Insert-or-update via conflict fragment to stay minimal.
	return s.repo.Insert(ctx, &st, rel.OnConflictFragment(`("key") DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at`))
}

func (s *Server) clearAppState(ctx context.Context, key string) error {
	st := AppState{Key: key}
	return s.repo.Delete(ctx, &st)
}

func (s *Server) validateBootstrapToken(ctx context.Context, token string) error {
	hashHex, err := s.getAppState(ctx, "bootstrap_token_sha256")
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return err
		}
		return err
	}
	sum := sha256.Sum256([]byte(token))
	if hex.EncodeToString(sum[:]) != hashHex {
		return errors.New("invalid bootstrap token")
	}
	return nil
}

func (s *Server) getUserByUsername(ctx context.Context, username string) (User, error) {
	var u User
	err := s.repo.Find(ctx, &u, rel.Where(where.Eq("username", username)))
	return u, err
}

func (s *Server) loadWebAuthnUser(ctx context.Context, u User) (WebAuthnUser, error) {
	var rows []WebAuthnCredential
	if err := s.repo.FindAll(ctx, &rows, rel.Where(where.Eq("user_id", u.ID))); err != nil {
		return WebAuthnUser{}, err
	}
	creds := make([]webauthn.Credential, 0, len(rows))
	for _, r := range rows {
		c, err := unmarshalCredential(r.CredentialJSON)
		if err != nil {
			return WebAuthnUser{}, err
		}
		creds = append(creds, c)
	}
	return WebAuthnUser{User: u, Creds: creds}, nil
}

// Lock the registered device until its session is created. Device removal uses
// the same lock, so an in-flight login cannot resurrect a deleted credential or
// create a session after the removal's in-use check.
func (s *Server) completeDeviceLogin(ctx context.Context, sid, token string, user User, c *webauthn.Credential) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var deviceID int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM webauthn_credentials WHERE user_id=$1 AND credential_id=$2 FOR UPDATE`, user.ID, c.ID).Scan(&deviceID); err != nil {
		return false, err
	}
	b, err := marshalCredential(c)
	if err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE webauthn_credentials SET credential_json=$2 WHERE id=$1`, deviceID, b); err != nil {
		return false, err
	}
	ok, err := s.sessions.CompleteLogin(ctx, sid, token, user.Username, deviceID)
	if err != nil || !ok {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = s.sessions.DeleteAuth(cleanup, token)
		return false, err
	}
	return true, nil
}
