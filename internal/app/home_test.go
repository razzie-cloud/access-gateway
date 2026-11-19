package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestHomeDestinationKeepsAccountManagementAccessible(t *testing.T) {
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

func TestCloudLogoFollowsAccountState(t *testing.T) {
	for _, cfg := range []struct{ landing, home, public string }{
		{"https://cloud.example.com/", "https://home.example.com/", "https://cloud.example.com/"},
		{"http://localhost:9191", "http://home.localhost:9191", "http://localhost:9191/"},
		{"https://cloud.example.com", "", "https://cloud.example.com/"},
		{"", "https://home.example.com", "https://razzie.cloud/"},
	} {
		for _, tc := range []struct {
			name string
			data viewData
		}{
			{"signed-out", viewData{}},
			{"bootstrap", viewData{NeedsRegistration: true}},
			{"enrollment", viewData{Invite: true}},
			{"member", viewData{User: &User{Username: "Alice"}}},
			{"admin", viewData{User: &User{Username: "Alice", IsAdmin: true}}},
		} {
			for _, template := range []string{"page", "state"} {
				t.Run(cfg.public+"/"+tc.name+"/"+template, func(t *testing.T) {
					s := unitServer()
					s.cfg.LandingOrigin, s.cfg.HomeOrigin = cfg.landing, cfg.home
					w := httptest.NewRecorder()
					s.render(w, httptest.NewRequest(http.MethodGet, "/", nil), http.StatusOK, template, tc.data)
					require.Equal(t, http.StatusOK, w.Code)
					want := cfg.public
					if tc.data.User != nil && cfg.home != "" {
						want = strings.TrimRight(cfg.home, "/") + "/"
					}
					assert.Contains(t, w.Body.String(), `class="brand" href="`+want+`"`)
					assert.Contains(t, w.Body.String(), `class="service-name" href="/">Access Gateway</a>`)
					assert.Equal(t, 1, strings.Count(w.Body.String(), `id="cloud-brand"`))
					if template == "state" {
						assert.Contains(t, w.Body.String(), `id="cloud-brand" hx-swap-oob="innerHTML"`)
					}
				})
			}
		}
	}
}
