package app

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAppLoginBindingsAndExpiry(t *testing.T) {
	for _, mismatch := range []string{"code", "state", "origin", "flow", "code expiry", "flow expiry", "auth expiry", "logout"} {
		t.Run(mismatch, func(t *testing.T) {
			m := NewMemorySessions(time.Minute)
			m.PutAuth("parent", "alice")
			flowID, state, ok := m.beginAppLogin(testAppOrigin, testAppOrigin+"/private")
			require.True(t, ok)
			code, ok := m.authorizeAppLogin(flowID, "parent")
			require.True(t, ok)
			origin := testAppOrigin
			flow := m.flows[flowID]
			originalFlowID := flowID
			switch mismatch {
			case "code":
				code = "wrong"
			case "state":
				state = "wrong"
			case "origin":
				origin = "https://another.example"
			case "flow":
				flowID = "wrong"
			case "code expiry":
				flow.codeExp = time.Now().Add(-time.Minute)
			case "flow expiry":
				flow.exp = time.Now().Add(-time.Minute)
			case "auth expiry":
				m.auth["parent"] = authEntry{username: "alice", exp: time.Now().Add(-time.Minute)}
			case "logout":
				m.DeleteAuth("parent")
			}
			m.flows[originalFlowID] = flow
			token, target, ok := m.completeAppLogin(flowID, code, state, origin)
			assert.False(t, ok)
			assert.Empty(t, token)
			assert.Empty(t, target)
			assert.Empty(t, m.apps)
		})
	}
}

func TestAppLoginConcurrentConsumption(t *testing.T) {
	m := NewMemorySessions(time.Minute)
	m.PutAuth("parent", "alice")
	flow, state, ok := m.beginAppLogin(testAppOrigin, testAppOrigin+"/private")
	require.True(t, ok)
	code, ok := m.authorizeAppLogin(flow, "parent")
	require.True(t, ok)
	var wins atomic.Int32
	var group sync.WaitGroup
	for i := 0; i < 24; i++ {
		group.Go(func() {
			token, target, ok := m.completeAppLogin(flow, code, state, testAppOrigin)
			if ok {
				wins.Add(1)
				assert.NotEmpty(t, token)
				assert.Equal(t, testAppOrigin+"/private", target)
			}
		})
	}
	group.Wait()
	assert.EqualValues(t, 1, wins.Load())
	assert.Len(t, m.apps, 1)
}

func TestAppSessionsRequireLiveParentAndCorrectOrigin(t *testing.T) {
	m := NewMemorySessions(time.Minute)
	m.PutAuth("parent", "alice")
	flow, state, ok := m.beginAppLogin(testAppOrigin, testAppOrigin+"/")
	require.True(t, ok)
	_, ok = m.authorizeAppLogin(flow, "unknown")
	assert.False(t, ok)
	code, ok := m.authorizeAppLogin(flow, "parent")
	require.True(t, ok)
	token, _, ok := m.completeAppLogin(flow, code, state, testAppOrigin)
	require.True(t, ok)
	_, ok = m.getAppAuth(token, "https://other.example")
	assert.False(t, ok)
	_, ok = m.getAppAuth("parent", testAppOrigin)
	assert.False(t, ok, "gateway token was accepted as an app token")
	name, ok := m.getAppAuth(token, testAppOrigin)
	assert.True(t, ok)
	assert.Equal(t, "alice", name)
	m.DeleteAuth("parent")
	_, ok = m.getAppAuth(token, testAppOrigin)
	assert.False(t, ok)
	assert.Empty(t, m.apps)
}

func TestAppLoginCapacityAndPruning(t *testing.T) {
	m := NewMemorySessions(time.Minute)
	for i := 0; i < maxAppLoginFlows; i++ {
		m.flows[fmt.Sprint(i)] = memoryAppLoginFlow{exp: time.Now().Add(time.Minute)}
	}
	_, _, ok := m.beginAppLogin(testAppOrigin, testAppOrigin+"/")
	assert.False(t, ok)
	m.flows["0"] = memoryAppLoginFlow{exp: time.Now().Add(-time.Minute)}
	m.apps["dead"] = appSession{origin: testAppOrigin, parent: "deleted"}
	_, _, ok = m.beginAppLogin(testAppOrigin, testAppOrigin+"/")
	assert.True(t, ok)
	assert.NotContains(t, m.flows, "0")
	assert.NotContains(t, m.apps, "dead")
}
