package app

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
			var page bytes.Buffer
			require.NoError(t, templates.ExecuteTemplate(&page, "page", tc.data))
			html := page.String()
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
