package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	ceremonyTTL      = 30 * time.Minute
	authTTL          = 7 * 24 * time.Hour
	appLoginTTL      = 10 * time.Minute
	appCodeTTL       = time.Minute
	maxAppLoginFlows = 4096
)

var errSessionStore = errors.New("session storage unavailable")

type sessionStore interface {
	PutRegistration(context.Context, string, registrationContext, webauthn.SessionData) error
	GetRegistration(context.Context, string) (registrationContext, webauthn.SessionData, bool, error)
	PutLogin(context.Context, string, string, webauthn.SessionData) error
	GetLogin(context.Context, string) (string, webauthn.SessionData, bool, error)
	PutAuth(context.Context, string, string) error
	GetAuth(context.Context, string) (string, bool, error)
	CompleteLogin(context.Context, string, string, string, int64) (bool, error)
	DeleteAuth(context.Context, string) error
	DeleteSID(context.Context, string) error
	beginAppLogin(context.Context, string, string) (string, string, error)
	appLogin(context.Context, string) (appLoginFlow, bool, error)
	authorizeAppLogin(context.Context, string, string) (string, bool, error)
	completeAppLogin(context.Context, string, string, string, string) (string, string, bool, error)
	getAppAuth(context.Context, string, string) (string, bool, error)
	ListSessions(context.Context) ([]sessionSummary, error)
	DeleteSession(context.Context, string, string) error
	Close() error
}

// Administrative metadata only; never include bearer tokens or ceremony data.
type sessionSummary struct {
	ID        string
	Kind      string
	Username  string
	Origin    string
	ExpiresAt time.Time
	DeviceID  int64
	ParentID  string
}

type appLoginFlow struct {
	origin, returnTo string
}

func newSID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
