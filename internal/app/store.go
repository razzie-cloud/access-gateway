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
	"github.com/google/uuid"
)

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

func (s *Server) createFirstUser(ctx context.Context, username string) (User, error) {
	id := uuid.New()
	u := User{
		ID:        id[:],
		Username:  username,
		CreatedAt: time.Now().Unix(),
	}
	if err := s.repo.Insert(ctx, &u); err != nil {
		return User{}, err
	}
	return u, nil
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

func (s *Server) upsertCredential(ctx context.Context, userID []byte, c *webauthn.Credential) error {
	b, err := marshalCredential(c)
	if err != nil {
		return err
	}
	row := WebAuthnCredential{
		UserID:         userID,
		CredentialID:   c.ID,
		CredentialJSON: b,
		CreatedAt:      time.Now().Unix(),
	}
	return s.repo.Insert(ctx, &row, rel.OnConflictFragment(`("credential_id") DO UPDATE SET credential_json = EXCLUDED.credential_json`))
}
