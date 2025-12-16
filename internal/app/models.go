package app

import (
	"encoding/json"

	"github.com/go-webauthn/webauthn/webauthn"
)

type User struct {
	ID        []byte `db:",primary"`
	Username  string
	CreatedAt int64
}

type WebAuthnCredential struct {
	ID             int64 `db:",primary"`
	UserID         []byte
	CredentialID   []byte
	CredentialJSON []byte
	CreatedAt      int64
}

func (WebAuthnCredential) Table() string {
	return "webauthn_credentials"
}

type AppState struct {
	Key       string `db:",primary"`
	Value     string
	UpdatedAt int64
}

type WebAuthnUser struct {
	User  User
	Creds []webauthn.Credential
}

func (u WebAuthnUser) WebAuthnID() []byte {
	return u.User.ID
}

func (u WebAuthnUser) WebAuthnName() string {
	return u.User.Username
}

func (u WebAuthnUser) WebAuthnDisplayName() string {
	return u.User.Username
}

func (u WebAuthnUser) WebAuthnIcon() string {
	return ""
}

func (u WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.Creds
}

func marshalCredential(c *webauthn.Credential) ([]byte, error) {
	return json.Marshal(c)
}

func unmarshalCredential(b []byte) (webauthn.Credential, error) {
	var c webauthn.Credential
	err := json.Unmarshal(b, &c)
	return c, err
}
