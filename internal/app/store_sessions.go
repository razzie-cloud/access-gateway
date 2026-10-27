package app

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

type MemorySessions struct {
	mu sync.Mutex

	ttl time.Duration

	reg  map[string]regEntry
	log  map[string]loginEntry
	auth map[string]authEntry
}

type regEntry struct {
	registration registrationContext
	sd           webauthn.SessionData
	exp          time.Time
}

type loginEntry struct {
	username string
	sd       webauthn.SessionData
	exp      time.Time
}

type authEntry struct {
	username string
	exp      time.Time
}

func NewMemorySessions(ttl time.Duration) *MemorySessions {
	return &MemorySessions{
		ttl:  ttl,
		reg:  map[string]regEntry{},
		log:  map[string]loginEntry{},
		auth: map[string]authEntry{},
	}
}

func (m *MemorySessions) NewSID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (m *MemorySessions) PutRegistration(sid string, registration registrationContext, sd webauthn.SessionData) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reg[sid] = regEntry{registration: registration, sd: sd, exp: time.Now().Add(m.ttl)}
}

func (m *MemorySessions) GetRegistration(sid string) (registrationContext, webauthn.SessionData, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.reg[sid]
	if !ok || time.Now().After(e.exp) {
		delete(m.reg, sid)
		return registrationContext{}, webauthn.SessionData{}, false
	}
	return e.registration, e.sd, true
}

func (m *MemorySessions) PutLogin(sid, username string, sd webauthn.SessionData) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.log[sid] = loginEntry{username: username, sd: sd, exp: time.Now().Add(m.ttl)}
}

func (m *MemorySessions) GetLogin(sid string) (string, webauthn.SessionData, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.log[sid]
	if !ok || time.Now().After(e.exp) {
		delete(m.log, sid)
		return "", webauthn.SessionData{}, false
	}
	return e.username, e.sd, true
}

func (m *MemorySessions) PutAuth(token, username string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.auth[token] = authEntry{username: username, exp: time.Now().Add(7 * 24 * time.Hour)}
}

func (m *MemorySessions) GetAuth(token string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.auth[token]
	if !ok || time.Now().After(e.exp) {
		delete(m.auth, token)
		return "", false
	}
	return e.username, true
}

func (m *MemorySessions) DeleteAuth(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.auth, token)
}

func (m *MemorySessions) DeleteSID(sid string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.reg, sid)
	delete(m.log, sid)
}
