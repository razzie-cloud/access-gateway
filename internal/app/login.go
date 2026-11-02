package app

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Keep dummy IDs stable across restarts and replicas. A per-process random key
// would let repeated requests distinguish unknown usernames from real ones.
func (s *Server) ensureLoginSecret(ctx context.Context) error {
	const key = "login_decoy_secret"
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO app_states(key,value,updated_at) VALUES($1,$2,$3)
 ON CONFLICT (key) DO NOTHING`, key, hex.EncodeToString(secret), time.Now().Unix()); err != nil {
		return err
	}
	var value string
	if err := s.db.QueryRowContext(ctx, `SELECT value FROM app_states WHERE key=$1`, key).Scan(&value); err != nil {
		return err
	}
	var err error
	s.loginSecret, err = hex.DecodeString(value)
	if err != nil || len(s.loginSecret) != 32 {
		return errors.New("invalid login decoy secret")
	}
	return nil
}

type loginCredentialGroup struct {
	length int
	slots  int
	ids    [][]byte
}

// Use one database snapshot for both the account's IDs and a common response
// shape: the largest per-account credential count for each ID length. Padding
// every account (including unknown and unenrolled users) to that same shape
// avoids exposing per-account credential counts, lengths or transports. Only
// the requested account's real IDs leave the server; other IDs are decoys.
func (s *Server) loginCredentials(ctx context.Context, username string) ([]protocol.CredentialDescriptor, WebAuthnUser, error) {
	rows, err := s.db.QueryContext(ctx, `WITH counts AS (
 SELECT octet_length(credential_id) AS length, count(*) AS slots
 FROM webauthn_credentials GROUP BY user_id,octet_length(credential_id)
), profile AS (
 SELECT length,max(slots) AS slots FROM counts GROUP BY length
), selected AS (
 SELECT c.user_id,c.credential_id FROM webauthn_credentials c JOIN users u ON u.id=c.user_id
 WHERE u.username=$1
)
SELECT p.length,p.slots,s.user_id,s.credential_id FROM profile p
LEFT JOIN selected s ON octet_length(s.credential_id)=p.length
ORDER BY p.length,s.credential_id`, username)
	if err != nil {
		return nil, WebAuthnUser{}, err
	}
	defer rows.Close()
	var groups []loginCredentialGroup
	user := WebAuthnUser{User: User{Username: username}}
	for rows.Next() {
		var length, slots int
		var userID, id []byte
		if err := rows.Scan(&length, &slots, &userID, &id); err != nil {
			return nil, WebAuthnUser{}, err
		}
		if len(groups) == 0 || groups[len(groups)-1].length != length {
			groups = append(groups, loginCredentialGroup{length: length, slots: slots})
		}
		if id != nil {
			user.User.ID = userID
			group := &groups[len(groups)-1]
			group.ids = append(group.ids, id)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, WebAuthnUser{}, err
	}
	if len(groups) == 0 {
		// Never send an empty allowCredentials: that would show every passkey.
		groups = []loginCredentialGroup{{length: 32, slots: 1}}
	}
	allowed, realIDs, err := s.padLoginCredentials(username, groups)
	if err != nil {
		return nil, WebAuthnUser{}, err
	}
	for _, id := range realIDs {
		user.Creds = append(user.Creds, webauthn.Credential{ID: id})
	}
	if len(user.Creds) == 0 {
		// A dummy account takes the same BeginLogin path and never has an
		// empty private allowlist, even if credentials are enrolled later.
		user.User.ID, err = hkdf.Key(sha256.New, s.loginSecret, []byte(s.cfg.Origin), "login dummy user:"+username, 16)
		if err != nil {
			return nil, WebAuthnUser{}, err
		}
		user.Creds = []webauthn.Credential{{ID: allowed[0].CredentialID}}
	}
	return allowed, user, nil
}

func (s *Server) padLoginCredentials(username string, groups []loginCredentialGroup) ([]protocol.CredentialDescriptor, [][]byte, error) {
	var allowed []protocol.CredentialDescriptor
	var realIDs [][]byte
	for _, group := range groups {
		for slot := range group.slots {
			// Generate all padding slots for every request, even when replaced by
			// real IDs, to keep the cryptographic work independent of existence.
			id, err := hkdf.Key(sha256.New, s.loginSecret, []byte(s.cfg.Origin),
				fmt.Sprintf("login decoy:%s:%d:%d", username, group.length, slot), group.length)
			if err != nil {
				return nil, nil, err
			}
			if slot < len(group.ids) {
				id = group.ids[slot]
				realIDs = append(realIDs, id)
			}
			allowed = append(allowed, protocol.CredentialDescriptor{Type: protocol.PublicKeyCredentialType, CredentialID: id})
		}
	}
	// No separate real/padding section, and stable ordering for repeated queries.
	slices.SortFunc(allowed, func(a, b protocol.CredentialDescriptor) int {
		if n := len(a.CredentialID) - len(b.CredentialID); n != 0 {
			return n
		}
		return bytes.Compare(a.CredentialID, b.CredentialID)
	})
	return allowed, realIDs, nil
}
