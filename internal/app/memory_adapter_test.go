package app

import (
	"context"
	"errors"
	"github.com/go-webauthn/webauthn/webauthn"
)

// The memory implementation is a test double only; NewServer always uses Redis.
type memorySessionStore struct{ mem *MemorySessions }

func testMemory(s *Server) *MemorySessions { return s.sessions.(memorySessionStore).mem }
func (m memorySessionStore) Close() error  { return nil }
func (m memorySessionStore) PutRegistration(_ context.Context, sid string, r registrationContext, sd webauthn.SessionData) error {
	m.mem.PutRegistration(sid, r, sd)
	return nil
}
func (m memorySessionStore) GetRegistration(_ context.Context, sid string) (registrationContext, webauthn.SessionData, bool, error) {
	r, sd, ok := m.mem.GetRegistration(sid)
	return r, sd, ok, nil
}
func (m memorySessionStore) PutLogin(_ context.Context, sid, name string, sd webauthn.SessionData) error {
	m.mem.PutLogin(sid, name, sd)
	return nil
}
func (m memorySessionStore) GetLogin(_ context.Context, sid string) (string, webauthn.SessionData, bool, error) {
	n, sd, ok := m.mem.GetLogin(sid)
	return n, sd, ok, nil
}
func (m memorySessionStore) PutAuth(_ context.Context, t, n string) error {
	m.mem.PutAuth(t, n)
	return nil
}
func (m memorySessionStore) GetAuth(_ context.Context, t string) (string, bool, error) {
	n, ok := m.mem.GetAuth(t)
	return n, ok, nil
}
func (m memorySessionStore) DeleteAuth(_ context.Context, t string) error {
	m.mem.DeleteAuth(t)
	return nil
}
func (m memorySessionStore) DeleteSID(_ context.Context, t string) error {
	m.mem.DeleteSID(t)
	return nil
}
func (m memorySessionStore) CompleteLogin(_ context.Context, sid, token, name string) (bool, error) {
	if n, _, ok := m.mem.GetLogin(sid); !ok || n != name {
		return false, nil
	}
	m.mem.PutAuth(token, name)
	m.mem.DeleteSID(sid)
	return true, nil
}
func (m memorySessionStore) beginAppLogin(_ context.Context, o, t string) (string, string, error) {
	f, s, ok := m.mem.beginAppLogin(o, t)
	if !ok {
		return "", "", errors.New("capacity")
	}
	return f, s, nil
}
func (m memorySessionStore) appLogin(_ context.Context, f string) (appLoginFlow, bool, error) {
	v, ok := m.mem.appLogin(f)
	return appLoginFlow{origin: v.origin, returnTo: v.returnTo}, ok, nil
}
func (m memorySessionStore) authorizeAppLogin(_ context.Context, f, p string) (string, bool, error) {
	c, ok := m.mem.authorizeAppLogin(f, p)
	return c, ok, nil
}
func (m memorySessionStore) completeAppLogin(_ context.Context, f, c, s, o string) (string, string, bool, error) {
	v, t, ok := m.mem.completeAppLogin(f, c, s, o)
	return v, t, ok, nil
}
func (m memorySessionStore) getAppAuth(_ context.Context, t, o string) (string, bool, error) {
	n, ok := m.mem.getAppAuth(t, o)
	return n, ok, nil
}
