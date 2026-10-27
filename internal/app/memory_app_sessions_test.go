package app

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"time"
)

type memoryAppLoginFlow struct {
	origin, returnTo, state string
	parent                  string
	codeHash                [32]byte
	exp, codeExp            time.Time
}

type appSession struct {
	origin, parent string
}

func (m *MemorySessions) beginAppLogin(origin, returnTo string) (string, string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneAppSessions()
	if len(m.flows) >= maxAppLoginFlows {
		return "", "", false
	}
	flowID, state := rand.Text(), rand.Text()
	m.flows[flowID] = memoryAppLoginFlow{origin: origin, returnTo: returnTo, state: state, exp: time.Now().Add(appLoginTTL)}
	return flowID, state, true
}

func (m *MemorySessions) appLogin(flowID string) (memoryAppLoginFlow, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	flow, ok := m.flows[flowID]
	if !ok || !time.Now().Before(flow.exp) {
		delete(m.flows, flowID)
		return memoryAppLoginFlow{}, false
	}
	return flow, true
}

func (m *MemorySessions) authorizeAppLogin(flowID, parent string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	flow, ok := m.flows[flowID]
	auth, authenticated := m.auth[parent]
	now := time.Now()
	if !ok || !now.Before(flow.exp) || !authenticated || !now.Before(auth.exp) {
		return "", false
	}
	code := rand.Text()
	flow.parent, flow.codeHash, flow.codeExp = parent, sha256.Sum256([]byte(code)), now.Add(appCodeTTL)
	m.flows[flowID] = flow
	return code, true
}

func (m *MemorySessions) completeAppLogin(flowID, code, state, origin string) (string, string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	flow, ok := m.flows[flowID]
	auth, authenticated := m.auth[flow.parent]
	now := time.Now()
	codeHash := sha256.Sum256([]byte(code))
	if !ok || origin != flow.origin || !now.Before(flow.exp) || !now.Before(flow.codeExp) ||
		!authenticated || !now.Before(auth.exp) ||
		subtle.ConstantTimeCompare([]byte(state), []byte(flow.state)) != 1 ||
		subtle.ConstantTimeCompare(codeHash[:], flow.codeHash[:]) != 1 {
		return "", "", false
	}
	delete(m.flows, flowID)
	token := rand.Text()
	m.apps[token] = appSession{origin: origin, parent: flow.parent}
	return token, flow.returnTo, true
}

func (m *MemorySessions) getAppAuth(token, origin string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	app, ok := m.apps[token]
	if !ok || app.origin != origin {
		return "", false
	}
	auth, ok := m.auth[app.parent]
	if !ok || !time.Now().Before(auth.exp) {
		delete(m.apps, token)
		return "", false
	}
	return auth.username, true
}

// Called with mu held when starting a flow; no background goroutine is needed.
func (m *MemorySessions) pruneAppSessions() {
	now := time.Now()
	for id, flow := range m.flows {
		if !now.Before(flow.exp) {
			delete(m.flows, id)
		}
	}
	for token, app := range m.apps {
		auth, ok := m.auth[app.parent]
		if !ok || !now.Before(auth.exp) {
			delete(m.apps, token)
		}
	}
}
