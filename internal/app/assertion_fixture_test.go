package app

import (
	"aidanwoods.dev/go-paseto"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
	"time"
)

func TestIdentityWireFixture(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	start := now.Truncate(signingPeriod)
	secret, err := paseto.NewV4AsymmetricSecretKeyFromSeed("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	require.NoError(t, err)
	next, err := paseto.NewV4AsymmetricSecretKeyFromSeed("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
	require.NoError(t, err)
	s := unitServer()
	s.assertions = &memoryAssertionKeys{keys: map[time.Time]paseto.V4AsymmetricSecretKey{start: secret, start.Add(signingPeriod): next}}
	set, err := s.assertionKeys(t.Context(), now)
	require.NoError(t, err)
	signed, err := s.signIdentity(t.Context(), now, "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa", "alice", "https://app.example", "GET", "/static/app.css?check=hello%20world", false)
	require.NoError(t, err)
	actual, err := json.MarshalIndent(struct {
		Now    time.Time       `json:"now"`
		KeySet assertionKeySet `json:"key_set"`
		Token  string          `json:"token"`
	}{now, set, signed}, "", "  ")
	require.NoError(t, err)
	expected, err := os.ReadFile("testdata/identity-v1.json")
	require.NoError(t, err)
	require.JSONEq(t, string(expected), string(actual))
}
