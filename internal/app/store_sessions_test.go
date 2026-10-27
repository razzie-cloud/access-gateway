package app

import (
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemorySessionsCeremonies(t *testing.T) {
	m := NewMemorySessions(time.Minute)
	registration := registrationContext{
		User:     User{ID: []byte{1, 2, 3}, Username: "alice"},
		LinkHash: hashToken("registration-token"),
	}
	regData := webauthn.SessionData{Challenge: "registration-challenge", UserID: registration.User.ID}
	loginData := webauthn.SessionData{Challenge: "login-challenge", UserID: []byte{4, 5, 6}}
	m.PutRegistration("shared-sid", registration, regData)
	m.PutLogin("shared-sid", "bob", loginData)

	// Reading a ceremony must leave it available for a retry after a failed finish.
	for range 2 {
		got, sd, ok := m.GetRegistration("shared-sid")
		require.True(t, ok)
		assert.Equal(t, registration, got)
		assert.Equal(t, regData, sd)
		username, sd, ok := m.GetLogin("shared-sid")
		require.True(t, ok)
		assert.Equal(t, "bob", username)
		assert.Equal(t, loginData, sd)
	}

	m.PutRegistration("other-sid", registration, regData)
	m.PutLogin("other-sid", "alice", loginData)
	m.PutAuth("shared-sid", "alice")
	m.DeleteSID("shared-sid")
	m.DeleteSID("shared-sid") // Deletion is idempotent.
	_, _, ok := m.GetRegistration("shared-sid")
	assert.False(t, ok, "deleted registration is still available")
	_, _, ok = m.GetLogin("shared-sid")
	assert.False(t, ok, "deleted login is still available")
	_, _, ok = m.GetRegistration("other-sid")
	assert.True(t, ok, "deleting one SID removed another registration")
	_, _, ok = m.GetLogin("other-sid")
	assert.True(t, ok, "deleting one SID removed another login")
	username, ok := m.GetAuth("shared-sid")
	assert.True(t, ok, "deleting a ceremony removed an auth session")
	assert.Equal(t, "alice", username)
}

func TestMemorySessionsMissingAndExpired(t *testing.T) {
	m := NewMemorySessions(time.Minute)
	// Seed past deadlines directly so expiry tests never depend on sleeps.
	past := time.Now().Add(-time.Minute)
	m.reg["expired"] = regEntry{registration: registrationContext{User: User{Username: "alice"}}, sd: webauthn.SessionData{Challenge: "secret"}, exp: past}
	m.log["expired"] = loginEntry{username: "alice", sd: webauthn.SessionData{Challenge: "secret"}, exp: past}
	m.auth["expired"] = authEntry{username: "alice", exp: past}

	for _, key := range []string{"missing", "expired"} {
		t.Run(key, func(t *testing.T) {
			registration, sd, ok := m.GetRegistration(key)
			assert.False(t, ok)
			assert.Equal(t, registrationContext{}, registration)
			assert.Equal(t, webauthn.SessionData{}, sd)
			username, sd, ok := m.GetLogin(key)
			assert.False(t, ok)
			assert.Empty(t, username)
			assert.Equal(t, webauthn.SessionData{}, sd)
			username, ok = m.GetAuth(key)
			assert.False(t, ok)
			assert.Empty(t, username)
		})
	}
	assert.Empty(t, m.reg, "expired registrations were not removed")
	assert.Empty(t, m.log, "expired logins were not removed")
	assert.Empty(t, m.auth, "expired auth sessions were not removed")
}

func TestMemorySessionsLifetimes(t *testing.T) {
	const ttl = 17 * time.Minute
	m := NewMemorySessions(ttl)
	before := time.Now()
	m.PutRegistration("sid", registrationContext{}, webauthn.SessionData{})
	m.PutLogin("sid", "alice", webauthn.SessionData{})
	m.PutAuth("auth", "alice")
	after := time.Now()
	for _, tc := range []struct {
		name string
		exp  time.Time
		ttl  time.Duration
	}{
		{"registration", m.reg["sid"].exp, ttl},
		{"login", m.log["sid"].exp, ttl},
		{"auth", m.auth["auth"].exp, 7 * 24 * time.Hour},
	} {
		assert.False(t, tc.exp.Before(before.Add(tc.ttl)), "%s expiry is too early", tc.name)
		assert.False(t, tc.exp.After(after.Add(tc.ttl)), "%s expiry is too late", tc.name)
	}
}

func TestMemorySessionsAuthReplacementAndDeletion(t *testing.T) {
	m := NewMemorySessions(time.Minute)
	m.PutAuth("token", "alice")
	m.PutAuth("token", "bob")
	m.PutAuth("other", "alice")
	username, ok := m.GetAuth("token")
	require.True(t, ok)
	assert.Equal(t, "bob", username)
	m.DeleteAuth("token")
	m.DeleteAuth("token")
	username, ok = m.GetAuth("token")
	assert.False(t, ok)
	assert.Empty(t, username)
	username, ok = m.GetAuth("other")
	assert.True(t, ok, "deleting one auth token removed another")
	assert.Equal(t, "alice", username)
}

func TestMemorySessionsConcurrentAccess(t *testing.T) {
	m := NewMemorySessions(time.Minute)
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			key := fmt.Sprintf("session-%d", i)
			for range 20 {
				m.PutRegistration(key, registrationContext{User: User{Username: key}}, webauthn.SessionData{Challenge: key})
				m.PutLogin(key, key, webauthn.SessionData{Challenge: key})
				m.PutAuth(key, key)
				registration, sd, ok := m.GetRegistration(key)
				assert.True(t, ok, "registration %s missing", key)
				assert.Equal(t, key, registration.User.Username)
				assert.Equal(t, key, sd.Challenge)
				username, sd, ok := m.GetLogin(key)
				assert.True(t, ok, "login %s missing", key)
				assert.Equal(t, key, username)
				assert.Equal(t, key, sd.Challenge)
				username, ok = m.GetAuth(key)
				assert.True(t, ok, "auth %s missing", key)
				assert.Equal(t, key, username)
				m.DeleteSID(key)
				m.DeleteAuth(key)
			}
		})
	}
	wg.Wait()
	assert.Empty(t, m.reg)
	assert.Empty(t, m.log)
	assert.Empty(t, m.auth)
}

func TestNewSID(t *testing.T) {
	m := NewMemorySessions(time.Minute)
	seen := make(map[string]bool)
	for range 100 {
		sid := m.NewSID()
		decoded, err := hex.DecodeString(sid)
		require.NoError(t, err)
		assert.Len(t, decoded, 16, "SID must encode 16 random bytes")
		require.NotContains(t, seen, sid, "duplicate SID")
		seen[sid] = true
	}
}
