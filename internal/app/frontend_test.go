package app

import (
	"bytes"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdminDeniedPageUsesConfiguredOrigins(t *testing.T) {
	for _, tc := range []struct{ gateway, landing, home string }{
		{"https://auth.example/", "https://cloud.example/", "https://cloud.example/"},
		{"http://auth.localhost:8082", "http://localhost:8082", "http://localhost:8082/"},
		{"https://auth.example:8443", "", "https://razzie.cloud/"},
	} {
		t.Run(tc.gateway, func(t *testing.T) {
			s := unitServer()
			s.cfg.Origin, s.cfg.LandingOrigin = tc.gateway, tc.landing
			s.mux.HandleFunc("/denied", func(w http.ResponseWriter, r *http.Request) {
				s.writeError(w, r, http.StatusForbidden, "Administrator access required")
			})
			r := httptest.NewRequest(http.MethodGet, "https://untrusted.example/denied", nil)
			r.Header.Set("X-Forwarded-Host", "spoofed.example")
			r.Header.Set("X-Forwarded-Uri", "/secret?token=private")
			w := httptest.NewRecorder()
			s.handler().ServeHTTP(w, r)
			require.Equal(t, http.StatusForbidden, w.Code)
			assert.Equal(t, "text/html; charset=utf-8", w.Header().Get("Content-Type"))
			assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			assert.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"))
			assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
			gateway := strings.TrimRight(tc.gateway, "/")
			assert.Equal(t, "default-src 'none'; style-src "+gateway+"; img-src "+gateway+"; base-uri 'none'; frame-ancestors 'none'; form-action 'none'", w.Header().Get("Content-Security-Policy"))
			body := w.Body.String()
			assert.Contains(t, body, "<!doctype html>")
			assert.Contains(t, body, `href="`+tc.home+`"`)
			assert.Contains(t, body, `href="`+gateway+`/">Manage your account`)
			assert.Contains(t, body, `href="`+gateway+`/static/pico.min.css"`)
			assert.Contains(t, body, `href="`+gateway+`/static/app.css"`)
			assert.Contains(t, body, `src="`+gateway+`/static/razzie-cloud-logo.png"`)
			for _, unwanted := range []string{"untrusted.example", "spoofed.example", "private", "<script", "<form", `style=`, `data-theme=`} {
				assert.NotContains(t, body, unwanted)
			}
			for _, ref := range regexp.MustCompile(`(?:href|src)="([^"]+)"`).FindAllStringSubmatch(body, -1) {
				u, err := url.Parse(html.UnescapeString(ref[1]))
				require.NoError(t, err)
				assert.True(t, u.IsAbs() && u.Host != "", "reference must be absolute: %s", ref[1])
			}
			for _, header := range []string{"Location", "Set-Cookie", "X-Auth-Request-User", "X-Auth-Request-Name", "X-Auth-Request-Token"} {
				assert.Empty(t, w.Header().Get(header))
			}
		})
	}
}

// Account state is replaced after sign-in, sign-out and user creation. Navigation
// and privileged forms must follow the rendered state rather than the old shell.
func TestFrontendStateTransitions(t *testing.T) {
	for _, tc := range []struct {
		name                                     string
		data                                     viewData
		login, bootstrap, invite, account, admin bool
	}{
		{name: "login", login: true},
		{name: "bootstrap", data: viewData{NeedsRegistration: true}, bootstrap: true},
		{name: "enrollment", data: viewData{Invite: true}, invite: true},
		{name: "member", data: viewData{User: &User{Username: "<member>"}}, account: true},
		{name: "admin", data: viewData{User: &User{Username: "<admin>", IsAdmin: true}}, account: true, admin: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.data.LandingOrigin = "http://localhost:9191"
			var page bytes.Buffer
			require.NoError(t, templates.ExecuteTemplate(&page, "page", tc.data))
			html := page.String()
			assert.Contains(t, html, `class="brand" href="http://localhost:9191/"`)
			assert.Contains(t, html, `class="service-name" href="/">Access Gateway</a>`)
			assert.Equal(t, tc.login, strings.Contains(html, `data-webauthn="login"`))
			assert.Equal(t, tc.bootstrap, strings.Contains(html, `name="token"`))
			assert.Equal(t, tc.invite, strings.Contains(html, `id="link-token"`))
			assert.Equal(t, tc.account, strings.Contains(html, `id="activity-data"`))
			assert.Equal(t, tc.account, strings.Contains(html, `hx-post="/ui/logout"`))
			assert.Equal(t, tc.admin, strings.Contains(html, `hx-post="/ui/users"`))
			assert.Equal(t, tc.admin, strings.Contains(html, `href="#users"`))
			assert.NotContains(t, html, "<member>")
			assert.NotContains(t, html, "<admin>")
			assert.NotContains(t, html, `style=`)
			assert.Contains(t, html, `"historyCacheSize":0`)
			if tc.invite {
				assert.Contains(t, html, `id="device-registration"`)
				assert.Contains(t, html, `name="linkToken"`)
			}
			if !tc.invite {
				page.Reset()
				require.NoError(t, templates.ExecuteTemplate(&page, "state", tc.data))
				assert.Equal(t, tc.account, strings.Contains(page.String(), `class="sidebar"`))
			}
		})
	}
}

func TestFrontendProtectedActivityActions(t *testing.T) {
	data := viewData{
		User: &User{Username: "alice"},
		Devices: []deviceView{
			{ID: 1, Username: "alice", Name: "Current device", InUse: true, Current: true},
			{ID: 2, Username: "alice", Name: "Offline device"},
		},
		Sessions: []sessionView{
			{sessionSummary: sessionSummary{ID: "current", Kind: "Gateway"}, Current: true},
			{sessionSummary: sessionSummary{ID: "other", Kind: "Application"}},
		},
	}
	var page bytes.Buffer
	require.NoError(t, templates.ExecuteTemplate(&page, "activity", data))
	html := page.String()
	for route, field := range map[string]string{"devices/remove": "device_id", "sessions/remove": "session_id"} {
		forms := regexp.MustCompile(`(?s)<form[^>]+hx-post="/ui/`+route+`"[^>]*>.*?</form>`).FindAllString(html, -1)
		require.Len(t, forms, 2)
		assert.Contains(t, forms[0], `name="`+field+`"`)
		assert.Contains(t, forms[0], ` disabled`)
		assert.NotContains(t, forms[1], ` disabled`)
		for _, form := range forms {
			assert.Contains(t, form, `hx-target="#activity-data"`)
		}
	}
	assert.Contains(t, html, `hx-post="/ui/devices/rename"`)
	assert.NotContains(t, html, `id="users"`)
}
