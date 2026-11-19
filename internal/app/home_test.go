package app

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHomeOriginRequiresAllowedApp(t *testing.T) {
	for _, home := range []string{"https://home.example.com", "https://home.example.com/", "http://home.localhost:9191"} {
		cfg := Config{Origin: "https://auth.example.com", HomeOrigin: home, ForwardAuthOrigins: []string{"https://*.example.com", "http://home.localhost:9191"}}
		require.NoError(t, validateForwardAuthConfig(cfg))
	}
	for _, home := range []string{"javascript:alert(1)", "//evil.example", "https://auth.example.com", "https://evil.example", "https://home.example.com/path", "https://home.example.com/?next=evil", "https://u:p@home.example.com", "http://home.example.com"} {
		require.Error(t, validateForwardAuthConfig(Config{Origin: "https://auth.example.com", HomeOrigin: home, ForwardAuthOrigins: []string{"https://*.example.com"}}), home)
	}
	require.Error(t, validateForwardAuthConfig(Config{Origin: "https://auth.example.com", HomeOrigin: "https://home.example.com"}))
}

func TestHomeDestinationOnlyAffectsSignIn(t *testing.T) {
	s := unitServer()
	s.cfg.HomeOrigin = "https://home.example.com/"
	for _, data := range []viewData{{}, {Invite: true}, {NeedsRegistration: true}, {User: &User{Username: "Alice"}}} {
		w := httptest.NewRecorder()
		s.render(w, httptest.NewRequest(http.MethodGet, "/", nil), http.StatusOK, "page", data)
		require.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), `<meta name="login-destination" content="https://home.example.com/">`)
		assert.Empty(t, w.Header().Get("Location"), "Account management remains directly accessible")
	}
}
