package app

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidUsername(t *testing.T) {
	for _, tc := range []struct {
		name, username string
		want           bool
	}{
		{"empty", "", false},
		{"whitespace", " \t\r\n", false},
		{"unicode whitespace", "\u2003\u00a0", false},
		{"one byte", "a", true},
		{"maximum bytes", strings.Repeat("a", 64), true},
		{"too many bytes", strings.Repeat("a", 65), false},
		{"unicode at maximum", strings.Repeat("é", 32), true},
		{"unicode over maximum", strings.Repeat("é", 33), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, validUsername(tc.username))
		})
	}
}

func TestHashToken(t *testing.T) {
	for _, tc := range []struct{ token, want string }{
		{"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
	} {
		assert.Equal(t, tc.want, hashToken(tc.token), "hashToken(%q)", tc.token)
	}
	assert.NotEqual(t, hashToken("token"), hashToken(" token "), "bearer tokens must be hashed verbatim")
}

func TestRandomToken(t *testing.T) {
	seen := make(map[string]bool)
	for range 100 {
		token, err := randomToken()
		require.NoError(t, err)
		decoded, err := hex.DecodeString(token)
		require.NoError(t, err)
		assert.Len(t, decoded, 32, "token must encode 32 random bytes")
		assert.Equal(t, strings.ToLower(token), token, "token must use lowercase hex")
		require.NotContains(t, seen, token, "duplicate registration token")
		seen[token] = true
	}
}
